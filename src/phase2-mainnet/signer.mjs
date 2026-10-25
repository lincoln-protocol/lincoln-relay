// SPDX-License-Identifier: Apache-2.0
// One durable nonce/fee ledger per Robinhood mainnet signing address. No key export.
import path from 'node:path';
import fs from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {getAddress,isAddress,keccak256,parseTransaction,recoverTransactionAddress,verifyTypedData} from 'viem';
import {openServiceStore} from '../phase1-service/store.mjs';
import {classifyMainnetBroadcastError} from './broadcast-errors.mjs';
import {TREASURY_KIND,TREASURY_MAX_GAS,assertTreasuryEntry,treasuryId,treasuryTransfer} from './treasury-intent.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
export const MAINNET_RPC='https://rpc.mainnet.chain.robinhood.com/';
const run=promisify(execFile),HASH=/^0x[0-9a-fA-F]{64}$/,HEX=/^0x(?:[0-9a-fA-F]{2})*$/;
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const integer=(value,code,{zero=false}={})=>{need(typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value),code);const n=BigInt(value);need((zero?n>=0n:n>0n)&&n<2n**256n,code);return n;};
const clone=value=>JSON.parse(JSON.stringify(value));
const live=entry=>!['confirmed','reverted','cancelled'].includes(entry.status);
const cost=entry=>['confirmed','reverted'].includes(entry.status)?BigInt(entry.feeWei):live(entry)
  ?(entry.attempts??[]).reduce((highest,attempt)=>BigInt(attempt.feeCeilingWei)>highest?BigInt(attempt.feeCeilingWei):highest,BigInt(entry.feeCeilingWei)):0n;
const publicEntry=entry=>{const {rawTransaction,...result}=entry;return clone({...result,...(entry.attempts?{attempts:entry.attempts.map(({rawTransaction,...attempt})=>attempt)}:{})});};
const MAX_ATTEMPTS=32;
// Every ordinary intent is value-free. The single exception is a treasury
// entry whose exact shape (relay -> fixed Safe) treasury-intent.mjs pins.
const valueAllowed=(e,address)=>e.kind===undefined?e.value==='0'&&!String(e.id).startsWith('treasury:'):(assertTreasuryEntry(e,{address}),true);
const statuses=new Set(['prepared','signed','broadcasting','submitted','unknown','rejected','conflicted','confirmed','reverted','cancelled']);
const retryableReason=reason=>['FEE_BELOW_BASE','INSUFFICIENT_FUNDS'].includes(reason);
// What the transport said, reduced to fixed-shape facts for the ledger and the
// log: error names, string codes, numeric codes and HTTP statuses, down the
// cause chain. Never messages, bodies or URLs.
const errorClass=error=>{
  const out=[];const seen=new Set();
  for(let current=error,depth=0;current&&typeof current==='object'&&!seen.has(current)&&depth<6;current=current.cause,depth++){
    seen.add(current);const item={};
    if(typeof current.name==='string'&&/^[A-Za-z]{1,64}$/.test(current.name))item.name=current.name;
    if(typeof current.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(current.code)||Number.isSafeInteger(current.code))item.code=current.code;
    if(Number.isSafeInteger(current.status)&&current.status>=100&&current.status<=599)item.status=current.status;
    if(Object.keys(item).length)out.push(item);
  }
  return out;
};
const missingReceipt=error=>['TransactionReceiptNotFoundError','TransactionNotFoundError'].includes(error?.name)||['RECEIPT_NOT_FOUND','TRANSACTION_NOT_FOUND'].includes(error?.code);
const attemptsOf=entry=>entry.attempts??(entry.hash?[{hash:entry.hash,...(entry.rawTransaction?{rawTransaction:entry.rawTransaction}:{}),gasPrice:entry.gasPrice,feeCeilingWei:entry.feeCeilingWei,status:entry.status,
  ...(entry.rejectionReason?{rejectionReason:entry.rejectionReason}:{})}]:[]);

/** Robinhood legacy transactions pay the actual base fee. Keep the approved
 * ceiling unchanged; an explicit operator price remains exact.
 */
export async function quoteMainnetGasPrice({client,maxFeePerGasWei,explicitGasPrice}={}){
  const cap=integer(maxFeePerGasWei,'MAINNET_EXPLICIT_GAS_PRICE_REQUIRED');
  if(explicitGasPrice!==undefined){const price=integer(explicitGasPrice,'MAINNET_GAS_PRICE_INVALID');need(price<=cap,'MAINNET_GAS_PRICE_EXCEEDED');return price;}
  return(await quoteMainnetGasPriceDetails({client,maxFeePerGasWei})).gasPriceWei;
}
/** One block read supplies both observed billing base and signing ceiling. */
export async function quoteMainnetGasPriceDetails({client,maxFeePerGasWei}={}){
  const cap=integer(maxFeePerGasWei,'MAINNET_EXPLICIT_GAS_PRICE_REQUIRED');
  const block=await client.getBlock({blockTag:'latest'}),base=block.baseFeePerGas??await client.getGasPrice();
  need(typeof base==='bigint'&&base>=0n&&base<=cap,'MAINNET_GAS_PRICE_EXCEEDED');
  const candidate=base*2n>base+20000000n?base*2n:base+20000000n;
  return{baseFeePerGas:base,gasPriceWei:candidate>cap?cap:candidate};
}
function cleanEnv(){return Object.fromEntries(Object.entries(process.env).filter(([key])=>! /^(ETH_|CAST_|FOUNDRY_|PRIVATE_KEY|MNEMONIC|CHAIN$|TEMPO_|TURNKEY_|AWS_|GCP_)/.test(key)));}

/** Only cast decrypts the local keystore. Never call wallet private-key or export. */
export function createCastKeystoreSigner({address,account,keystoreFile,passwordFile}={}){
  need(isAddress(address)&&((typeof account==='string'&&/^[a-zA-Z0-9_-]{1,80}$/.test(account)&&keystoreFile===undefined)
    ||account===undefined&&typeof keystoreFile==='string'&&path.isAbsolute(keystoreFile)),'MAINNET_KEYSTORE_OPTIONS_INVALID');
  need(typeof passwordFile==='string'&&path.isAbsolute(passwordFile),'MAINNET_PASSWORD_FILE_REQUIRED');
  return async intent=>{
    need(intent.chainId===4663&&(intent.value==='0'&&intent.kind===undefined||intent.kind===TREASURY_KIND&&valueAllowed(intent,address)),'MAINNET_SIGNING_INTENT_INVALID');
    const passwordStat=await fs.lstat(passwordFile);
    need(passwordStat.isFile()&&!passwordStat.isSymbolicLink()&&await fs.realpath(passwordFile)===passwordFile
      &&passwordStat.size<=1024&&(passwordStat.mode&0o077)===0
      &&(typeof process.getuid!=='function'||passwordStat.uid===process.getuid()),'MAINNET_PASSWORD_FILE_INVALID');
    if(keystoreFile){const stat=await fs.lstat(keystoreFile);
      need(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(keystoreFile)===keystoreFile&&stat.size>0&&stat.size<=64*1024
        &&(stat.mode&0o077)===0&&(typeof process.getuid!=='function'||stat.uid===process.getuid()),'MAINNET_KEYSTORE_FILE_INVALID');}
    const args=['mktx','--rpc-url',MAINNET_RPC,'--chain','4663',...(keystoreFile?['--keystore',keystoreFile]:['--account',account]),'--password-file',passwordFile,
      '--legacy','--nonce',intent.nonce,'--gas-limit',intent.gas,'--gas-price',intent.gasPrice,'--value',intent.value];
    // Foundry 1.8.4 accepts raw calldata as its positional SIG argument;
    // mktx has no --data flag. The creation branch remains unchanged.
    if(intent.to&&intent.data==='0x')args.push(intent.to);else if(intent.to)args.push(intent.to,intent.data);else args.push('--create',intent.data);
    let stdout;try{({stdout}=await run('cast',args,{env:cleanEnv(),timeout:60000,maxBuffer:2*1024*1024}));}
    catch{throw Object.assign(new Error('MAINNET_KEYSTORE_SIGN_FAILED'),{code:'MAINNET_KEYSTORE_SIGN_FAILED'});}
    const raw=stdout.trim();need(HEX.test(raw)&&raw.length>2,'MAINNET_SIGNED_TRANSACTION_INVALID');
    need((await recoverTransactionAddress({serializedTransaction:raw})).toLowerCase()===address.toLowerCase(),'MAINNET_KEYSTORE_ADDRESS_MISMATCH');
    return raw;
  };
}

/** EIP-712 signer for points fee receipts: same keystore, same `cast` boundary and
 * file checks as the transaction signer, which stays untouched. */
export function createCastTypedDataSigner({address,account,keystoreFile,passwordFile}={}){
  need(isAddress(address)&&((typeof account==='string'&&/^[a-zA-Z0-9_-]{1,80}$/.test(account)&&keystoreFile===undefined)
    ||account===undefined&&typeof keystoreFile==='string'&&path.isAbsolute(keystoreFile)),'MAINNET_KEYSTORE_OPTIONS_INVALID');
  need(typeof passwordFile==='string'&&path.isAbsolute(passwordFile),'MAINNET_PASSWORD_FILE_REQUIRED');
  const signer=getAddress(address);
  return {address:signer,async signTypedData({domain,types,primaryType,message}){
    const passwordStat=await fs.lstat(passwordFile);
    need(passwordStat.isFile()&&!passwordStat.isSymbolicLink()&&await fs.realpath(passwordFile)===passwordFile
      &&passwordStat.size<=1024&&(passwordStat.mode&0o077)===0
      &&(typeof process.getuid!=='function'||passwordStat.uid===process.getuid()),'MAINNET_PASSWORD_FILE_INVALID');
    if(keystoreFile){const stat=await fs.lstat(keystoreFile);
      need(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(keystoreFile)===keystoreFile&&stat.size>0&&stat.size<=64*1024
        &&(stat.mode&0o077)===0&&(typeof process.getuid!=='function'||stat.uid===process.getuid()),'MAINNET_KEYSTORE_FILE_INVALID');}
    const typed={types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'}],...types},primaryType,domain,
      message:JSON.parse(JSON.stringify(message,(_,v)=>typeof v==='bigint'?String(v):v))};
    let stdout;try{({stdout}=await run('cast',['wallet','sign','--data',...(keystoreFile?['--keystore',keystoreFile]:['--account',account]),'--password-file',passwordFile,JSON.stringify(typed)],{env:cleanEnv(),timeout:60000,maxBuffer:1024*1024}));}
    catch{throw Object.assign(new Error('MAINNET_KEYSTORE_SIGN_FAILED'),{code:'MAINNET_KEYSTORE_SIGN_FAILED'});}
    const signature=stdout.trim();need(/^0x[0-9a-fA-F]{130}$/.test(signature),'MAINNET_SIGNED_TYPED_DATA_INVALID');
    need(await verifyTypedData({address:signer,domain,types,primaryType,message,signature}),'MAINNET_KEYSTORE_ADDRESS_MISMATCH');
    return signature;
  }};
}

export function mainnetSignerDirectory({root=ROOT,address}={}){
  need(isAddress(address),'MAINNET_SIGNER_ADDRESS_INVALID');
  return path.join(root,'.phase1-private/phase2-mainnet/signers',`4663-${address.toLowerCase()}`);
}

/** prepare persists intent+nonce+ceiling; broadcast persists the signed hash before RPC.
 * Each operation obtains the same address lock. A crash leaves a lock that requires
 * explicit operator recovery, never automatic stale-lock deletion.
 */
export function createMainnetSigner({client,address,account,keystoreFile,passwordFile,budgetWei,maxFeePerGasWei,reserveWei,
  root=ROOT,directory,signRawTransaction,beforeBroadcast,expectedGenesisHash,treasuryAuthorizer,
  unknownBroadcastProbeMs=0,unknownBroadcastProbeIntervalMs=3000,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),now=Date.now}={}){
  need(client&&isAddress(address)&&(treasuryAuthorizer===undefined||typeof treasuryAuthorizer==='function'),'MAINNET_SIGNER_OPTIONS_INVALID');address=getAddress(address);
  need(Number.isSafeInteger(unknownBroadcastProbeMs)&&unknownBroadcastProbeMs>=0&&unknownBroadcastProbeMs<=300000
    &&Number.isSafeInteger(unknownBroadcastProbeIntervalMs)&&unknownBroadcastProbeIntervalMs>=1&&unknownBroadcastProbeIntervalMs<=60000,'MAINNET_SIGNER_PROBE_INVALID');
  const budget=integer(budgetWei,'MAINNET_EXPLICIT_BUDGET_REQUIRED'),maxPrice=integer(maxFeePerGasWei,'MAINNET_EXPLICIT_GAS_PRICE_REQUIRED');
  const reserve=integer(reserveWei,'MAINNET_EXPLICIT_RESERVE_REQUIRED',{zero:true});
  directory??=mainnetSignerDirectory({root,address});let sign=signRawTransaction;
  const identity=`lincoln-mainnet-signer:4663:${address.toLowerCase()}`;
  const connect=async()=>{
    need(await client.getChainId()===4663,'MAINNET_SIGNER_WRONG_CHAIN');
    const genesisHash=(await client.getBlock({blockNumber:0n})).hash;need(HASH.test(genesisHash),'MAINNET_SIGNER_GENESIS_INVALID');
    if(expectedGenesisHash!==undefined)need(HASH.test(expectedGenesisHash)&&genesisHash===expectedGenesisHash,'MAINNET_SIGNER_GENESIS_MISMATCH');
    const store=await openServiceStore({directory,identity,filename:'signer.json'});
    try{
      const state=await store.read()??{schema:'phase2-mainnet-signer/v1',chainId:4663,address,genesisHash,budgetWei,maxFeePerGasWei,reserveWei,entries:[]};
      need(state.schema==='phase2-mainnet-signer/v1'&&state.chainId===4663&&state.address.toLowerCase()===address.toLowerCase()&&state.genesisHash===genesisHash,'MAINNET_SIGNER_IDENTITY_MISMATCH');
      need(state.budgetWei===budgetWei&&state.maxFeePerGasWei===maxFeePerGasWei&&state.reserveWei===reserveWei,'MAINNET_SIGNER_BUDGET_CHANGED');
      need(Array.isArray(state.entries)&&new Set(state.entries.map(e=>e.id)).size===state.entries.length,'MAINNET_SIGNER_LEDGER_CORRUPT');
      for(const e of state.entries){
        need(typeof e.id==='string'&&e.intentDigest===digest({to:e.to,data:e.data,value:e.value})&&HEX.test(e.data)&&(!e.to||isAddress(e.to))&&e.chainId===4663,'MAINNET_SIGNER_LEDGER_CORRUPT');
        try{need(valueAllowed(e,address),'MAINNET_SIGNER_LEDGER_CORRUPT');}catch{throw Object.assign(new Error('MAINNET_SIGNER_LEDGER_CORRUPT'),{code:'MAINNET_SIGNER_LEDGER_CORRUPT'});}
        integer(e.nonce,'MAINNET_SIGNER_LEDGER_CORRUPT',{zero:true});integer(e.gas,'MAINNET_SIGNER_LEDGER_CORRUPT');integer(e.gasPrice,'MAINNET_SIGNER_LEDGER_CORRUPT');
        need(BigInt(e.gas)*BigInt(e.gasPrice)===BigInt(e.feeCeilingWei)&&BigInt(e.gasPrice)<=maxPrice&&statuses.has(e.status),'MAINNET_SIGNER_LEDGER_CORRUPT');
        if(e.rawTransaction)need(keccak256(e.rawTransaction)===e.hash,'MAINNET_SIGNER_LEDGER_CORRUPT');
        if(e.attempts!==undefined){
          need(Array.isArray(e.attempts)&&e.attempts.length>0&&e.attempts.length<=MAX_ATTEMPTS&&new Set(e.attempts.map(a=>a.hash)).size===e.attempts.length,'MAINNET_SIGNER_LEDGER_CORRUPT');
          for(const a of e.attempts){
            need(HASH.test(a.hash)&&statuses.has(a.status)&&BigInt(a.gasPrice)>0n&&BigInt(a.gasPrice)<=maxPrice&&BigInt(a.feeCeilingWei)===BigInt(e.gas)*BigInt(a.gasPrice),'MAINNET_SIGNER_LEDGER_CORRUPT');
            if(a.rawTransaction)need(keccak256(a.rawTransaction)===a.hash,'MAINNET_SIGNER_LEDGER_CORRUPT');
            if(a.broadcasts!==undefined)need(Array.isArray(a.broadcasts)&&a.broadcasts.length<=MAX_ATTEMPTS&&a.broadcasts.every(b=>['broadcasting','submitted','unknown','rejected'].includes(b.status)),'MAINNET_SIGNER_LEDGER_CORRUPT');
          }
          if(e.hash)need(e.attempts.some(a=>a.hash===e.hash&&a.gasPrice===e.gasPrice&&a.feeCeilingWei===e.feeCeilingWei),'MAINNET_SIGNER_LEDGER_CORRUPT');
        }
        if(e.status==='rejected')need(retryableReason(e.rejectionReason)&&HASH.test(e.hash),'MAINNET_SIGNER_LEDGER_CORRUPT');
        if(['confirmed','reverted'].includes(e.status))need(HASH.test(e.hash)&&HASH.test(e.blockHash)&&BigInt(e.feeWei)<=BigInt(e.feeCeilingWei),'MAINNET_SIGNER_LEDGER_CORRUPT');
      }
      need(state.entries.filter(live).length<=1,'MAINNET_SIGNER_LEDGER_CORRUPT');
      need(state.entries.reduce((sum,e)=>sum+cost(e),0n)<=budget,'MAINNET_SIGNER_BUDGET_EXCEEDED');return {store,state};
    }catch(error){await store.close();throw error;}
  };
  const withStore=async fn=>{const {store,state}=await connect();try{return await fn(state,store);}finally{await store.close();}};
  const summary=state=>({schema:state.schema,address,chainId:4663,genesisHash:state.genesisHash,budgetWei,maxFeePerGasWei,reserveWei,
    committedWei:state.entries.reduce((sum,e)=>sum+cost(e),0n).toString(),entries:state.entries.map(publicEntry)});
  const transactionMatches=(tx,e,a)=>need(tx.from?.toLowerCase()===address.toLowerCase()&&(tx.to??null)?.toLowerCase()===(e.to??null)?.toLowerCase()
    &&Number(tx.chainId)===4663&&BigInt(tx.nonce)===BigInt(e.nonce)&&BigInt(tx.value)===BigInt(e.value)&&tx.input?.toLowerCase()===e.data.toLowerCase()
    &&BigInt(tx.gas)===BigInt(e.gas)&&BigInt(tx.gasPrice)===BigInt(a.gasPrice),'MAINNET_RECEIPT_INTENT_MISMATCH');
  // Pure chain reads for one attempt: null while its receipt is still absent.
  const inspect=async a=>{
    let receipt;try{receipt=await client.getTransactionReceipt({hash:a.hash});}catch(error){if(missingReceipt(error))return null;throw Object.assign(new Error('MAINNET_RECEIPT_LOOKUP_FAILED'),{code:'MAINNET_RECEIPT_LOOKUP_FAILED'});}
    const [transaction,block]=await Promise.all([client.getTransaction({hash:a.hash}),client.getBlock({blockNumber:receipt.blockNumber})]);
    return {receipt,transaction,block};
  };
  const settle=async(state,store,e,reads=null)=>{
    if(e.status==='cancelled')return false;const winners=[];
    for(const a of attemptsOf(e)){
      const read=reads?.has(a.hash)?reads.get(a.hash):await inspect(a);if(read===null)continue;
      const {receipt,transaction,block}=read;
      need(receipt.transactionHash?.toLowerCase()===a.hash.toLowerCase()&&receipt.from?.toLowerCase()===address.toLowerCase(),'MAINNET_RECEIPT_IDENTITY_MISMATCH');
      transactionMatches(transaction,e,a);
      need(block.hash===receipt.blockHash,'MAINNET_RECEIPT_REORG');
      const fee=BigInt(receipt.gasUsed)*BigInt(receipt.effectiveGasPrice);
      need(fee<=BigInt(a.feeCeilingWei)&&BigInt(receipt.gasUsed)<=BigInt(e.gas)&&BigInt(receipt.effectiveGasPrice)<=BigInt(a.gasPrice),'MAINNET_RECEIPT_FEE_EXCEEDED');
      need(['success','reverted'].includes(receipt.status),'MAINNET_RECEIPT_STATUS_INVALID');winners.push({a,receipt,fee});
    }
    need(winners.length<=1,'MAINNET_MULTIPLE_CANONICAL_ATTEMPTS');if(!winners.length)return false;
    const {a,receipt,fee}=winners[0];
    Object.assign(e,{hash:a.hash,gasPrice:a.gasPrice,feeCeilingWei:a.feeCeilingWei,status:receipt.status==='success'?'confirmed':'reverted',feeWei:fee.toString(),gasUsed:receipt.gasUsed.toString(),
      effectiveGasPrice:receipt.effectiveGasPrice.toString(),blockNumber:receipt.blockNumber.toString(),blockHash:receipt.blockHash,contractAddress:receipt.contractAddress??null});
    if(a.rawTransaction)e.rawTransaction=a.rawTransaction;else delete e.rawTransaction;
    if(e.attempts)e.attempts.find(attempt=>attempt.hash===a.hash).status=e.status;
    delete e.rejectionReason;await store.write(state);return true;
  };
  const conflict=async(state,store,e,reason)=>{e.status='conflicted';e.rejectionReason=reason;await store.write(state);throw Object.assign(new Error('MAINNET_SIGNER_NONCE_CONFLICT'),{code:'MAINNET_SIGNER_NONCE_CONFLICT',transactionHash:e.hash});};
  const unusedNonce=async(state,store,e)=>{
    if(await settle(state,store,e))return false;
    const latest=await client.getTransactionCount({address,blockTag:'latest'}),pending=await client.getTransactionCount({address,blockTag:'pending'});
    if(BigInt(latest)!==BigInt(e.nonce)||BigInt(pending)!==BigInt(e.nonce))return conflict(state,store,e,'NONCE_ALREADY_CONSUMED_OR_PENDING');
    return true;
  };
  const assertBudget=async(state,gas,price,replacing,value=0n)=>{
    const fee=gas*price,previous=replacing?cost(replacing):0n,reserved=fee>previous?fee:previous;
    const spent=state.entries.reduce((sum,e)=>sum+cost(e),0n)-previous;
    need(spent+reserved<=budget,'MAINNET_SIGNER_BUDGET_EXCEEDED');need(await client.getBalance({address,blockTag:'pending'})>=reserved+reserve+value,'MAINNET_SIGNER_BALANCE_LOW');return fee;
  };
  // An uncertain delivery (transport failure, unrecognised error) is not a
  // verdict. Before the entry is left to the operator, the chain is asked for
  // the signed hash for a bounded time: a receipt settles it, a visible
  // transaction makes it submitted. Nothing is ever re-sent here, and the
  // probe never changes the nonce or the signed bytes.
  const probeUnknown=async(state,store,e,current,delivery)=>{
    if(unknownBroadcastProbeMs===0)return false;
    const began=now();let polls=0;
    while(true){
      polls++;
      try{if(await settle(state,store,e)){Object.assign(delivery,{status:'submitted',observedAfterMs:now()-began,probePolls:polls});await store.write(state);return true;}}
      catch(error){if(error?.code!=='MAINNET_RECEIPT_LOOKUP_FAILED')throw error;}
      let transaction=null;
      try{transaction=await client.getTransaction({hash:e.hash});}catch(error){if(!missingReceipt(error)&&!['RPC_TIMEOUT'].includes(error?.code))transaction=null;}
      if(transaction){
        transactionMatches(transaction,e,current);
        e.status='submitted';current.status='submitted';Object.assign(delivery,{status:'submitted',observedAfterMs:now()-began,probePolls:polls});await store.write(state);return true;
      }
      if(now()-began>=unknownBroadcastProbeMs)return false;
      await sleep(Math.min(unknownBroadcastProbeIntervalMs,Math.max(1,unknownBroadcastProbeMs-(now()-began))));
    }
  };
  return {
    address,chainId:4663,directory,
    async status(){return withStore(async state=>summary(state));},
    async prepare(intent){
      need(intent&&typeof intent.id==='string'&&/^[a-zA-Z0-9:_.-]{1,200}$/.test(intent.id)&&!intent.id.startsWith('treasury:'),'MAINNET_INTENT_ID_INVALID');
      need((intent.to===undefined||intent.to===null||isAddress(intent.to))&&HEX.test(intent.data)&&intent.data.length>2&&(intent.value===undefined||intent.value==='0'),'MAINNET_INTENT_INVALID');
      const normalized={to:intent.to?getAddress(intent.to):null,data:intent.data.toLowerCase(),value:'0'},intentDigest=digest(normalized);
      return withStore(async(state,store)=>{
        const old=state.entries.find(e=>e.id===intent.id);
        if(old){
          need(old.intentDigest===intentDigest,'MAINNET_INTENT_ID_REUSED');need(old.status!=='cancelled','MAINNET_RESERVATION_CANCELLED');
          if(old.status!=='rejected')return publicEntry(old);
          need(retryableReason(old.rejectionReason),'MAINNET_REJECTED_ATTEMPT_OPERATOR_REQUIRED');
          if(!await unusedNonce(state,store,old))return publicEntry(old);
          const quoted=await quoteMainnetGasPrice({client,maxFeePerGasWei,explicitGasPrice:intent.gasPrice}),prior=BigInt(old.gasPrice);
          need(intent.gasPrice===undefined||quoted>=prior,'MAINNET_REPRICE_NOT_HIGHER');
          const price=quoted>prior?quoted:prior;
          await assertBudget(state,BigInt(old.gas),price,old,BigInt(old.value));old.attempts=clone(attemptsOf(old));
          if(price===prior){
            need(old.rawTransaction&&retryableReason(old.rejectionReason),'MAINNET_REJECTED_ATTEMPT_OPERATOR_REQUIRED');
            const block=await client.getBlock({blockTag:'latest'}),base=block.baseFeePerGas??await client.getGasPrice();
            need(typeof base==='bigint'&&base>=0n&&base<=prior,'MAINNET_REPRICE_NOT_HIGHER');old.status='signed';
          }else{
            need(old.attempts.length<MAX_ATTEMPTS,'MAINNET_ATTEMPT_LIMIT');old.status='prepared';old.gasPrice=String(price);old.feeCeilingWei=String(BigInt(old.gas)*price);delete old.hash;delete old.rawTransaction;
          }
          delete old.rejectionReason;await store.write(state);return publicEntry(old);
        }
        for(const e of state.entries)if(live(e))await settle(state,store,e);
        need(!state.entries.some(live),'MAINNET_ACCOUNT_PENDING_TRANSACTION');
        const latest=await client.getTransactionCount({address,blockTag:'latest'}),pending=await client.getTransactionCount({address,blockTag:'pending'});
        need(latest===pending,'MAINNET_EXTERNAL_PENDING_NONCE');const previous=state.entries.filter(e=>e.status!=='cancelled').at(-1);
        need(!previous||BigInt(pending)>BigInt(previous.nonce),'MAINNET_SIGNER_NONCE_REGRESSION');
        const price=await quoteMainnetGasPrice({client,maxFeePerGasWei,explicitGasPrice:intent.gasPrice});
        const estimate=await client.estimateGas({account:address,...(normalized.to?{to:normalized.to}:{}),data:normalized.data,value:0n});
        const gas=intent.gas===undefined?(estimate*125n+99n)/100n:integer(intent.gas,'MAINNET_GAS_LIMIT_INVALID');need(estimate>0n&&gas>=estimate,'MAINNET_GAS_LIMIT_TOO_LOW');
        const fee=await assertBudget(state,gas,price);
        const entry={id:intent.id,chainId:4663,...normalized,intentDigest,nonce:pending.toString(),gas:gas.toString(),gasPrice:price.toString(),feeCeilingWei:fee.toString(),status:'prepared'};
        state.entries.push(entry);await store.write(state);return publicEntry(entry);
      });
    },
    /** Only an instance built with treasuryAuthorizer (the sweeper) may call this.
     * Same lock, nonce, budget and reserve rules as prepare(); the authorizer
     * rechecks earned income against this locked ledger before anything is stored.
     * The ID is sequence-numbered, so a retry after a crash resumes, never duplicates. */
    async prepareTreasury({asset,amount,sequence}={}){
      need(typeof treasuryAuthorizer==='function','MAINNET_TREASURY_DISABLED');
      const shape=treasuryTransfer({asset,amount}),id=treasuryId(shape.treasuryAsset,sequence);
      const normalized={to:getAddress(shape.to),data:shape.data,value:shape.value},intentDigest=digest(normalized);
      return withStore(async(state,store)=>{
        const old=state.entries.find(e=>e.id===id);
        if(old){need(old.intentDigest===intentDigest&&old.kind===TREASURY_KIND,'MAINNET_INTENT_ID_REUSED');return publicEntry(old);}
        for(const e of state.entries)if(live(e))await settle(state,store,e);
        need(!state.entries.some(live),'MAINNET_ACCOUNT_PENDING_TRANSACTION');
        const latest=await client.getTransactionCount({address,blockTag:'latest'}),pending=await client.getTransactionCount({address,blockTag:'pending'});
        need(latest===pending,'MAINNET_EXTERNAL_PENDING_NONCE');const previous=state.entries.filter(e=>e.status!=='cancelled').at(-1);
        need(!previous||BigInt(pending)>BigInt(previous.nonce),'MAINNET_SIGNER_NONCE_REGRESSION');
        const price=await quoteMainnetGasPrice({client,maxFeePerGasWei});
        const estimate=await client.estimateGas({account:address,to:normalized.to,data:normalized.data,value:BigInt(normalized.value)});
        const gas=(estimate*125n+99n)/100n;need(estimate>0n&&gas<=TREASURY_MAX_GAS,'MAINNET_TREASURY_GAS_LIMIT');
        const fee=await assertBudget(state,gas,price,undefined,BigInt(normalized.value));
        const entry={id,chainId:4663,...normalized,intentDigest,nonce:pending.toString(),gas:gas.toString(),gasPrice:price.toString(),feeCeilingWei:fee.toString(),status:'prepared',
          kind:TREASURY_KIND,treasuryAsset:shape.treasuryAsset,treasuryAmount:shape.treasuryAmount};
        assertTreasuryEntry(entry,{address});
        await treasuryAuthorizer({phase:'prepare',entry:clone(entry),ledger:clone(state)});
        state.entries.push(entry);await store.write(state);return publicEntry(entry);
      });
    },
    async cancelPrepared(id){return withStore(async(state,store)=>{
      const e=state.entries.find(e=>e.id===id);need(e,'MAINNET_RESERVATION_UNKNOWN');need(e.status==='prepared'&&!e.hash&&!e.rawTransaction&&attemptsOf(e).length===0,'MAINNET_RESERVATION_ALREADY_SIGNED');
      e.status='cancelled';await store.write(state);return publicEntry(e);
    });},
    async recoverHash(id){return withStore(async state=>state.entries.find(e=>e.id===(typeof id==='string'?id:id?.id))?.hash??null);},
    async unsignedEvidence(id){return withStore(async state=>{
      const e=state.entries.find(e=>e.id===id);if(!e||!['prepared','cancelled'].includes(e.status)||e.hash||e.rawTransaction||attemptsOf(e).length)return null;
      return {id:e.id,chainId:4663,from:address,to:e.to,data:e.data,value:'0',status:e.status,unsigned:true};
    });},
    async reconcile(options){
      need(options===undefined||options&&Object.getPrototypeOf(options)===Object.prototype
        &&Reflect.ownKeys(options).length===1&&Object.hasOwn(options,'activeOnly')
        &&Object.hasOwn(Object.getOwnPropertyDescriptor(options,'activeOnly'),'value')
        &&typeof options.activeOnly==='boolean','MAINNET_RECONCILE_OPTIONS_INVALID');
      const activeOnly=options?.activeOnly===true;
      // connect() still validates the complete durable ledger, identity and
      // cumulative budget. Only terminal chain RPCs are omitted in this mode;
      // no-argument startup/audit reconciliation retains its full checks.
      return withStore(async(state,store)=>{
        const selected=state.entries.filter(e=>e.status!=='cancelled'&&(!activeOnly||live(e))&&attemptsOf(e).length);
        // Chain reads do not depend on ledger order: fetch them together with
        // bounded concurrency, then settle entries one at a time so every
        // ledger write stays sequential and identical to the serial audit.
        const attempts=selected.flatMap(attemptsOf),reads=new Map();let cursor=0;
        await Promise.all(Array.from({length:Math.min(8,attempts.length)},async()=>{
          for(;;){const a=attempts[cursor++];if(!a)return;if(!reads.has(a.hash))reads.set(a.hash,await inspect(a));}
        }));
        for(const e of selected)await settle(state,store,e,reads);
        return summary(state);
      });
    },
    async broadcast(reservation){return withStore(async(state,store)=>{
      const id=typeof reservation==='string'?reservation:reservation?.id,e=state.entries.find(e=>e.id===id);need(e,'MAINNET_RESERVATION_UNKNOWN');need(e.status!=='cancelled','MAINNET_RESERVATION_CANCELLED');
      if(e.hash&&['broadcasting','submitted','unknown','confirmed','reverted'].includes(e.status))return e.hash;
      need(!['rejected','conflicted'].includes(e.status),'MAINNET_REJECTED_ATTEMPT_REQUIRES_PREPARE');need(e.status==='prepared'||e.status==='signed','MAINNET_RESERVATION_INVALID');
      if(!await unusedNonce(state,store,e))return e.hash;
      need(await client.getBalance({address,blockTag:'pending'})>=cost(e)+reserve+BigInt(e.value),'MAINNET_SIGNER_BALANCE_LOW');
      // A relay instance never signs a treasury reservation; the sweeper instance
      // signs nothing else. The authorizer rechecks earned income under this lock.
      need((e.kind===TREASURY_KIND)===Boolean(treasuryAuthorizer),'MAINNET_TREASURY_SIGNER_FORBIDDEN');
      if(treasuryAuthorizer&&e.status==='prepared')await treasuryAuthorizer({phase:'broadcast',entry:publicEntry(e),ledger:clone(state)});
      if(beforeBroadcast)await beforeBroadcast(publicEntry(e));
      if(e.status==='prepared'){
        sign??=createCastKeystoreSigner({address,account,keystoreFile,passwordFile});const raw=await sign(clone({...e,chainId:4663})),tx=parseTransaction(raw);
        need(Number(tx.chainId)===4663&&BigInt(tx.nonce??0)===BigInt(e.nonce)&&BigInt(tx.value??0)===BigInt(e.value)&&(tx.to??null)?.toLowerCase()===(e.to??null)?.toLowerCase()&&(tx.data??'0x').toLowerCase()===e.data
          &&BigInt(tx.gas)===BigInt(e.gas)&&BigInt(tx.gasPrice)===BigInt(e.gasPrice)&&(await recoverTransactionAddress({serializedTransaction:raw})).toLowerCase()===address.toLowerCase(),'MAINNET_SIGNED_INTENT_MISMATCH');
        e.attempts=clone(attemptsOf(e));Object.assign(e,{status:'signed',rawTransaction:raw,hash:keccak256(raw)});
        need(e.attempts.length<MAX_ATTEMPTS&&!e.attempts.some(a=>a.hash===e.hash),'MAINNET_ATTEMPT_LIMIT');
        e.attempts.push({hash:e.hash,rawTransaction:raw,gasPrice:e.gasPrice,feeCeilingWei:e.feeCeilingWei,status:'signed',broadcasts:[]});await store.write(state);
      }
      // Recheck persisted signed bytes too. A restart or funds-only retry must
      // never rely on a checksum/hash while sending a different signed intent.
      const signed=parseTransaction(e.rawTransaction);
      need(keccak256(e.rawTransaction)===e.hash&&Number(signed.chainId)===4663&&BigInt(signed.nonce??0)===BigInt(e.nonce)&&BigInt(signed.value??0)===BigInt(e.value)
        &&(signed.to??null)?.toLowerCase()===(e.to??null)?.toLowerCase()&&(signed.data??'0x').toLowerCase()===e.data
        &&BigInt(signed.gas)===BigInt(e.gas)&&BigInt(signed.gasPrice)===BigInt(e.gasPrice)
        &&(await recoverTransactionAddress({serializedTransaction:e.rawTransaction})).toLowerCase()===address.toLowerCase(),'MAINNET_SIGNED_INTENT_MISMATCH');
      e.attempts??=clone(attemptsOf(e));const current=e.attempts.find(a=>a.hash===e.hash);need(current,'MAINNET_SIGNER_LEDGER_CORRUPT');current.broadcasts??=[];
      need(current.broadcasts.length<MAX_ATTEMPTS,'MAINNET_ATTEMPT_LIMIT');const delivery={status:'broadcasting'};current.broadcasts.push(delivery);current.status='broadcasting';e.status='broadcasting';await store.write(state);
      try{
        const actual=await client.request({method:'eth_sendRawTransaction',params:[e.rawTransaction]});
        need(actual?.toLowerCase()===e.hash.toLowerCase(),'MAINNET_BROADCAST_HASH_MISMATCH');e.status='submitted';current.status='submitted';delivery.status='submitted';await store.write(state);return e.hash;
      }catch(error){
        const classification=classifyMainnetBroadcastError(error);
        if(classification.delivery==='accepted-known'){e.status='submitted';current.status='submitted';delivery.status='submitted';await store.write(state);return e.hash;}
        if(classification.delivery==='rejected'){
          current.status='rejected';delivery.status='rejected';current.rejectionReason=classification.rejectionReason;delivery.rejectionReason=classification.rejectionReason;
          e.status=retryableReason(classification.rejectionReason)?'rejected':'conflicted';e.rejectionReason=classification.rejectionReason;await store.write(state);
          if(await settle(state,store,e))return e.hash;
          throw Object.assign(new Error('MAINNET_BROADCAST_REJECTED'),{code:'MAINNET_BROADCAST_REJECTED',rejectionReason:classification.rejectionReason,transactionHash:e.hash,retrySameId:e.status==='rejected'});
        }
        e.status='unknown';current.status='unknown';delivery.status='unknown';delivery.errorClass=errorClass(error);await store.write(state);
        if(await probeUnknown(state,store,e,current,delivery))return e.hash;
        throw Object.assign(new Error('MAINNET_BROADCAST_UNKNOWN'),{code:'MAINNET_BROADCAST_UNKNOWN',transactionHash:e.hash,errorClass:delivery.errorClass,probedMs:unknownBroadcastProbeMs});
      }
    });},
  };
}
