// SPDX-License-Identifier: Apache-2.0
// Test-only signing adapters. Keystore keys never leave cast; only public intents
// and fee reservations are persisted. This ledger also covers CLI wallet writes.
import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { createWalletClient, http, keccak256 } from 'viem';
import { ROOT, ensure, same, stringify, sha } from './runtime.mjs';

// User-authorized cumulative Robinhood testnet cap; mainnet remains forbidden.
const run=promisify(execFile),CAP=2100000000000000n;
const publicError=code=>Object.assign(new Error(code),{code});
function trustedRpc(input){
  let u;try{u=new URL(input);}catch{throw publicError('UNAPPROVED_SIGNING_RPC');}
  ensure(u.protocol==='https:'&&['rpc.testnet.chain.robinhood.com','robinhood-sepolia-rpc.publicnode.com'].includes(u.hostname)
    &&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/','UNAPPROVED_SIGNING_RPC');return u.href;
}
function validatePublicTransaction({rpcUrl,nonce,gasLimit,maxFeePerGas,to,data,value=0n}){
  trustedRpc(rpcUrl);
  ensure(typeof data==='string'&&/^0x(?:[0-9a-f]{2})*$/i.test(data)&&/^0x[0-9a-f]{40}$/i.test(to),'INVALID_SIGNING_TRANSACTION');
  ensure([nonce,gasLimit,maxFeePerGas,value].every(x=>BigInt(x)>=0n)&&BigInt(gasLimit)>0n&&BigInt(maxFeePerGas)>0n,'INVALID_SIGNING_TRANSACTION');
  ensure(data.length>2||BigInt(value)>0n,'INVALID_SIGNING_TRANSACTION');
}
const ledgerCost=ledger=>(ledger?.entries??[]).reduce((s,x)=>s+BigInt(x.status==='not-submitted'?0:x.feeWei??x.feeCeilingWei),0n);
export async function readCombinedTestnetFees(root=ROOT){
  const read=async file=>{try{return JSON.parse(await fs.readFile(path.join(root,file),'utf8'));}catch(e){if(e.code==='ENOENT')return null;throw e;}};
  const [old,phase,archive,service,ledger]=await Promise.all(['artifacts/testnet-deployment.json','artifacts/phase1/deployment-testnet.json',
    'artifacts/phase1/archived-testnet-fees.json','artifacts/testnet-service-transactions.json','artifacts/phase1-service/testnet/spending/ledger.json'].map(read));
  const sum=(a,f)=>(a??[]).reduce((s,x)=>s+BigInt(f(x)??0),0n);
  return sum(old?.steps,x=>x.feeWei)+sum(phase?.steps,x=>x.feeWei??(!['confirmed','reverted'].includes(x.status)?BigInt(x.gasLimit??0)*BigInt(x.maxFeePerGas??0):0n))
    +sum(archive?.entries,x=>x.feeWei)+sum(service?.transactions,x=>x.feeWei??x.feeCeilingWei)
    +sum(ledger?.entries,x=>x.status==='not-submitted'?0:x.feeWei??x.feeCeilingWei);
}

export async function createServiceSigner({client,profile,accounts,directory,validateRuntime=async()=>{},root=ROOT,
  signingEnabled=true,budgetBaseline=null,castBin=process.env.PHASE1_CAST_BIN??(process.platform==='darwin'?'/Users/leo/.foundry/bin/cast':'/usr/local/bin/cast'),rpcUrl=profile.chain.rpcUrl}){
  const chainId=profile.chain.id,testnet=chainId===46630;
  ensure([31340,46630].includes(chainId)&&profile.testOnly===true&&profile.productionReady===false,'TEST_CHAIN_REQUIRED');
  const identity=sha(JSON.stringify({chainId,genesis:profile.genesisHash,accounts:Object.fromEntries(Object.entries(accounts).map(([k,v])=>[k,v.address]))}));
  const ledgerFile=path.join(directory,'ledger.json'),lockFile=path.join(directory,'.spending.lock');
  if(budgetBaseline){
    ensure(testnet&&budgetBaseline.schema==='phase1-service-budget-baseline/v1'&&budgetBaseline.testOnly===true
      &&budgetBaseline.chainId===chainId&&budgetBaseline.genesisHash===profile.genesisHash
      &&budgetBaseline.artifactSHA256===profile.protocol.artifactSHA256&&budgetBaseline.spendingIdentity===identity
      &&[String(CAP),'2010000000000000','2000000000000000'].includes(budgetBaseline.budgetWei)&&/^(0|[1-9][0-9]*)$/.test(budgetBaseline.externalFeeWei)
      &&['read-only-fresh','migrated'].includes(budgetBaseline.ledgerMode),'INVALID_BUDGET_BASELINE');
    ensure(!signingEnabled||budgetBaseline.ledgerMode==='migrated'&&budgetBaseline.requireExistingLedger===true,'BUDGET_STATE_MIGRATION_REQUIRED');
  }
  await fs.mkdir(directory,{recursive:true,mode:0o700});
  const st=await fs.lstat(directory);ensure(st.isDirectory()&&!st.isSymbolicLink()&&(st.mode&0o077)===0,'UNSAFE_SPENDING_DIRECTORY');
  async function readLedger(){
    let ledger;try{const stat=await fs.lstat(ledgerFile);ensure(stat.isFile()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0,'UNSAFE_SPENDING_LEDGER');ledger=JSON.parse(await fs.readFile(ledgerFile,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
    ensure(ledger||!budgetBaseline?.requireExistingLedger,'MIGRATED_SPENDING_LEDGER_REQUIRED');
    if(ledger){ensure(ledger.schema==='phase1-service-spending/v1'&&Array.isArray(ledger.entries)&&ledger.identity===identity&&ledger.chainId===chainId&&ledger.genesisHash===profile.genesisHash,'SPENDING_IDENTITY_MISMATCH');
      ensure(budgetBaseline?.ledgerMode!=='read-only-fresh'||ledger.entries.length===0,'FRESH_READ_ONLY_LEDGER_NOT_EMPTY');}
    return ledger;
  }
  await readLedger();
  let tail=Promise.resolve();
  async function transaction(fn){
    const result=tail.then(async()=>{
      let lock;const token=randomBytes(16).toString('hex');
      // A very short file lock. Never remove an existing lock automatically.
      for(let attempt=0;attempt<100;attempt++){
        try{lock=await fs.open(lockFile,'wx',0o600);break;}catch(e){if(e.code!=='EEXIST')throw e;if(attempt===99)throw publicError('SPENDING_LEDGER_LOCKED');await new Promise(r=>setTimeout(r,50));}
      }
      try{
        await lock.writeFile(JSON.stringify({pid:process.pid,token}));await lock.sync();
        let ledger=await readLedger();
        ledger??={schema:'phase1-service-spending/v1',identity,chainId,genesisHash:profile.genesisHash,entries:[]};
        ensure(ledger.identity===identity&&ledger.chainId===chainId&&ledger.genesisHash===profile.genesisHash,'SPENDING_IDENTITY_MISMATCH');
        const save=async()=>{const tmp=`${ledgerFile}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`,f=await fs.open(tmp,'wx',0o600);try{await f.writeFile(stringify(ledger));await f.sync();}finally{await f.close();}await fs.rename(tmp,ledgerFile);const d=await fs.open(directory,'r');try{await d.sync();}finally{await d.close();}};
        return await fn(ledger,save);
      }finally{await lock.close();const current=JSON.parse(await fs.readFile(lockFile,'utf8'));ensure(current.token===token,'SPENDING_LOCK_CHANGED');await fs.unlink(lockFile);}
    });tail=result.catch(()=>{});return result;
  }
  const descriptor=intent=>accounts[intent.accountRole??(intent.kind==='asp'?'postman':'relayer')];
  async function identityCheck(){ensure(await client.getChainId()===chainId&&(await client.getBlock({blockNumber:0n})).hash===profile.genesisHash,'SIGNING_CHAIN_CHANGED');}
  async function budget(ledger,entry){
    if(!testnet)return;
    const existing=ledgerCost({entries:ledger.entries.filter(x=>x.ledgerKey!==entry.ledgerKey)});
    // readCombined includes the current persisted ledger; subtract it before
    // accounting this in-memory update, preventing double reservation.
    let persisted;try{persisted=JSON.parse(await fs.readFile(ledgerFile,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
    const persistedCost=ledgerCost(persisted);
    const canonical=path.join(root,'artifacts/phase1-service/testnet/spending/ledger.json');
    const external=budgetBaseline?BigInt(budgetBaseline.externalFeeWei):await readCombinedTestnetFees(root)-(path.resolve(ledgerFile)===path.resolve(canonical)?persistedCost:0n);
    const total=external+existing+BigInt(entry.feeCeilingWei);
    // Previously exported portable baselines keep their narrower historical cap.
    const effectiveCap=budgetBaseline?BigInt(budgetBaseline.budgetWei):CAP;
    ensure(total<=effectiveCap,'AGGREGATE_TESTNET_GAS_BUDGET_EXCEEDED');
  }
  async function prepare(intent){
    ensure(signingEnabled,'SIGNING_DISABLED');
    await identityCheck();await validateRuntime(intent);
    const account=descriptor(intent);ensure(account?.address,'UNKNOWN_SIGNER_ROLE');
    const value=BigInt(intent.value??0),data=intent.data,to=intent.to;
    ensure(value>=0n&&value<=1000000000000000n,'TEST_VALUE_LIMIT');
    if(testnet)trustedRpc(rpcUrl);
    return transaction(async(ledger,save)=>{
      const key=intent.ledgerKey??`service:${intent.id}`,fingerprint=sha(JSON.stringify({to:to.toLowerCase(),data:data.toLowerCase(),value:String(value),account:account.address.toLowerCase()}));
      let old=ledger.entries.find(x=>x.ledgerKey===key);
      ensure(!ledger.entries.some(x=>x!==old&&['broadcasting','submitted'].includes(x.status)&&!x.feeWei),'UNRESOLVED_SIGNING_INTENT');
      if(old){ensure(old.fingerprint===fingerprint,'SIGNING_INTENT_CONFLICT');if(old.hash)return structuredClone(old);ensure(old.status==='prepared'||old.status==='not-submitted','UNKNOWN_BROADCAST_OUTCOME');}
      const nonce=await client.getTransactionCount({address:account.address});
      ensure(nonce===await client.getTransactionCount({address:account.address,blockTag:'pending'}),'PENDING_NONCE');
      const gas=(await client.estimateGas({account:account.address,to,data,value}))*12n/10n+5000n,maxFeePerGas=(await client.getGasPrice())*2n||1n;
      if(testnet)validatePublicTransaction({rpcUrl,nonce,gasLimit:gas,maxFeePerGas,to,data,value});
      ensure(await client.getBalance({address:account.address})>value+gas*maxFeePerGas,'SIGNER_TEST_ETH_INSUFFICIENT');
      const entry={ledgerKey:key,fingerprint,account:account.address,accountRole:intent.accountRole??(intent.kind==='asp'?'postman':'relayer'),nonce,
        gasLimit:String(gas),maxFeePerGas:String(maxFeePerGas),feeCeilingWei:String(gas*maxFeePerGas),to,data,value:String(value),status:'prepared'};
      await budget(ledger,entry);if(old)Object.assign(old,entry);else ledger.entries.push(entry);await save();return structuredClone(entry);
    });
  }
  async function broadcast(reservation){
    ensure(signingEnabled,'SIGNING_DISABLED');
    await identityCheck();
    return transaction(async(ledger,save)=>{
      const entry=ledger.entries.find(x=>x.ledgerKey===reservation.ledgerKey);
      ensure(entry&&entry.fingerprint===reservation.fingerprint,'MISSING_SIGNING_RESERVATION');
      if(entry.hash)return entry.hash;
      ensure(entry.status==='prepared','UNKNOWN_BROADCAST_OUTCOME');await budget(ledger,entry);
      const account=accounts[entry.accountRole];ensure(account&&same(account.address,entry.account),'SIGNER_ACCOUNT_CHANGED');
      const nonce=await client.getTransactionCount({address:entry.account});ensure(nonce===entry.nonce&&nonce===await client.getTransactionCount({address:entry.account,blockTag:'pending'}),'NONCE_CHANGED');
      entry.status='broadcasting';await save();
      try{
        let hash;
        if(testnet){
          const env={...process.env};for(const key of Object.keys(env))if(/^(ETH_|CAST_|PRIVATE_KEY|CHAIN$|TEMPO_|TURNKEY_)/.test(key))delete env[key];
          const walletArgs=account.keystore?['--keystore',account.keystore,'--password-file',account.passwordFile]:['--account','deployer','--password',''];
          const address=await run(castBin,['wallet','address',...walletArgs],{env,timeout:30000});ensure(same(address.stdout.trim(),entry.account),'KEYSTORE_ADDRESS_MISMATCH');
          const args=['send','--rpc-url',trustedRpc(rpcUrl),'--chain','46630',...walletArgs,'--nonce',String(entry.nonce),'--gas-limit',entry.gasLimit,
            '--gas-price',entry.maxFeePerGas,'--priority-gas-price','0','--value',entry.value,'--async','--no-proxy','--rpc-timeout','30','--color','never',entry.to,'--data',entry.data];
          const result=await run(castBin,args,{env,timeout:60000,maxBuffer:1000000});hash=result.stdout.trim().split(/\s+/).find(x=>/^0x[0-9a-f]{64}$/i.test(x));ensure(hash,'MISSING_TRANSACTION_HASH');
        }else{
          const chain={id:31340,name:'Phase1 local',nativeCurrency:{name:'Ether',symbol:'ETH',decimals:18},rpcUrls:{default:{http:[rpcUrl]}}};
          hash=await createWalletClient({account:entry.account,chain,transport:http(rpcUrl)}).sendTransaction({to:entry.to,data:entry.data,value:BigInt(entry.value),nonce:entry.nonce,gas:BigInt(entry.gasLimit)});
        }
        entry.hash=hash;entry.status='submitted';await save();return hash;
      }catch{entry.status='broadcasting';await save();throw publicError('SIGNING_OUTCOME_UNKNOWN');}
    });
  }
  async function receipt(hash,reservation){
    await identityCheck();let receipt;
    try{receipt=await client.getTransactionReceipt({hash});}catch(e){if(e.name==='TransactionReceiptNotFoundError'||String(e).includes('could not be found'))return null;throw e;}
    const tx=await client.getTransaction({hash});
    ensure(same(tx.from,reservation.account)&&same(tx.to,reservation.to)&&tx.nonce===reservation.nonce&&keccak256(tx.input)===keccak256(reservation.data)&&tx.value===BigInt(reservation.value),'SIGNED_TRANSACTION_MISMATCH');
    ensure((await client.getBlock({blockNumber:receipt.blockNumber})).hash===receipt.blockHash,'RECEIPT_REORGANIZED');
    const result={status:receipt.status==='success'?'confirmed':'reverted',hash,blockNumber:String(receipt.blockNumber),blockHash:receipt.blockHash,gasUsed:String(receipt.gasUsed),feeWei:String(receipt.gasUsed*receipt.effectiveGasPrice)};
    await transaction(async(ledger,save)=>{const entry=ledger.entries.find(x=>x.ledgerKey===reservation.ledgerKey);ensure(entry&&entry.fingerprint===reservation.fingerprint&&entry.hash===hash,'SPENDING_RECEIPT_MISMATCH');if(entry.blockHash)ensure(entry.blockHash===receipt.blockHash,'RECORDED_RECEIPT_REORGANIZED');Object.assign(entry,result);await save();});return result;
  }
  async function combinedFees(){
    if(budgetBaseline)return BigInt(budgetBaseline.externalFeeWei)+ledgerCost(await readLedger());
    const historic=await readCombinedTestnetFees(root),canonical=path.join(root,'artifacts/phase1-service/testnet/spending/ledger.json');
    return historic+(path.resolve(ledgerFile)===path.resolve(canonical)?0n:ledgerCost(await readLedger()));
  }
  return{prepare,broadcast,receipt,verifyBudget:async(_jobs,reservation)=>transaction((ledger)=>budget(ledger,ledger.entries.find(x=>x.ledgerKey===reservation.ledgerKey)??reservation)),
    cancel:async reservation=>transaction(async(ledger,save)=>{const entry=ledger.entries.find(x=>x.ledgerKey===reservation.ledgerKey);if(entry?.status==='prepared'&&!entry.hash){entry.status='not-submitted';await save();}}),
    recoverHash:async reservation=>transaction(ledger=>ledger.entries.find(x=>x.ledgerKey===reservation.ledgerKey)?.hash??null),
    summary:async()=>({chainId,testOnly:true,signingEnabled,ledgerMode:budgetBaseline?.ledgerMode??'native',
      combinedFeeWei:testnet?String(await combinedFees()):null,budgetWei:testnet?String(budgetBaseline?BigInt(budgetBaseline.budgetWei):CAP):null})};
}
