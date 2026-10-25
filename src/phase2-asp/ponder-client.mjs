// SPDX-License-Identifier: Apache-2.0
// Optional public-log transport. RPC remains the independent contract/receipt verifier.
// An indexer's completeness declaration is a trust assumption, not an inclusion proof.
import { normalizeProfile } from './sdk.mjs';

const HASH=/^0x[0-9a-f]{64}$/i,ADDRESS=/^0x[0-9a-f]{40}$/i,DATA=/^0x(?:[0-9a-f]{2})*$/i;
const HTTP_HOSTS=['127.0.0.1','localhost','[::1]','host.docker.internal','ponder','ponder-indexer','indexer'];
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sameHash=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
function quantity(value){
  check(typeof value==='bigint'||typeof value==='number'&&Number.isSafeInteger(value)||typeof value==='string'&&/^(?:0|[1-9][0-9]{0,77}|0x[0-9a-f]{1,64})$/i.test(value),'PONDER_INVALID_QUANTITY');
  const result=BigInt(value);check(result>=0n&&result<(1n<<256n),'PONDER_INVALID_QUANTITY');return result;
}
const decimal=value=>quantity(value).toString();
function position(log){return [log.blockNumber,BigInt(log.transactionIndex),BigInt(log.logIndex)];}
function compare(a,b){for(let i=0;i<a.length;i++){if(a[i]<b[i])return -1;if(a[i]>b[i])return 1;}return 0;}
function normalizeLog(log,{strict=true}={}){
  check(log&&ADDRESS.test(log.address)&&HASH.test(log.blockHash)&&HASH.test(log.transactionHash)
    &&Array.isArray(log.topics)&&log.topics.length<=4&&log.topics.every(t=>HASH.test(t))&&DATA.test(log.data)
    &&(strict?log.removed===false:log.removed!==true),'PONDER_INVALID_LOG');
  const blockNumber=quantity(log.blockNumber),transactionIndex=quantity(log.transactionIndex),logIndex=quantity(log.logIndex);
  check(transactionIndex<=BigInt(Number.MAX_SAFE_INTEGER)&&logIndex<=BigInt(Number.MAX_SAFE_INTEGER),'PONDER_INVALID_LOG');
  return {address:log.address.toLowerCase(),blockNumber,blockHash:log.blockHash.toLowerCase(),transactionHash:log.transactionHash.toLowerCase(),
    transactionIndex:Number(transactionIndex),logIndex:Number(logIndex),data:log.data.toLowerCase(),topics:log.topics.map(t=>t.toLowerCase()),removed:false};
}
const logFingerprint=log=>JSON.stringify(normalizeLog(log,{strict:false}),(_,v)=>typeof v==='bigint'?v.toString():v);
function status(value){check(['success','reverted','0x1','0x0',1,0].includes(value),'PONDER_INVALID_RECEIPT');return ['success','0x1',1].includes(value)?'success':'reverted';}
function transactionFacts(tx){
  check(tx&&HASH.test(tx.hash)&&HASH.test(tx.blockHash)&&ADDRESS.test(tx.from)
    &&(tx.to===null||ADDRESS.test(tx.to))&&DATA.test(tx.input),'PONDER_INVALID_TRANSACTION');
  return {hash:tx.hash.toLowerCase(),blockHash:tx.blockHash.toLowerCase(),blockNumber:decimal(tx.blockNumber),
    from:tx.from.toLowerCase(),to:tx.to?.toLowerCase()??null,input:tx.input.toLowerCase(),nonce:decimal(tx.nonce),value:decimal(tx.value)};
}
async function readJSON(response,maxBytes){
  const declared=response.headers.get('content-length');
  if(declared!==null&&(!/^[0-9]+$/.test(declared)||BigInt(declared)>BigInt(maxBytes))){await response.body?.cancel();check(false,'PONDER_RESPONSE_TOO_LARGE');}
  if(!/^application\/json\b/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();check(false,'PONDER_INVALID_CONTENT_TYPE');}
  check(response.body?.getReader,'PONDER_INVALID_RESPONSE');
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{
    for(;;){const item=await reader.read();if(item.done)break;size+=item.value.byteLength;
      if(size>maxBytes){await reader.cancel();check(false,'PONDER_RESPONSE_TOO_LARGE');}chunks.push(Buffer.from(item.value));}
  }finally{reader.releaseLock();}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));}
  catch{check(false,'PONDER_INVALID_JSON');}
}

/**
 * Opt-in adapter; default application clients continue using RPC directly.
 * Only pool/registry log ranges use Ponder. Every other client method is retained.
 * The existing indexer still replays history and obtains independent RPC receipts;
 * this transport does not establish cryptographic log completeness or remove that work.
 */
export function createPhase2PonderClient({client,profile,baseURL,fetchImpl=globalThis.fetch,pageSize=500,maxPages=2000,
  maxLogs=1000000,maxResponseBytes=8*1024*1024,timeoutMs=15000,fallbackToRpc=true,mode='full',onDiagnostic}={}){
  const p=normalizeProfile(profile),tracked=new Set([p.pool,p.registry]);let origin;
  try{origin=new URL(baseURL);}catch{check(false,'PONDER_URL_REJECTED');}
  check(!origin.username&&!origin.password&&!origin.search&&!origin.hash&&origin.pathname==='/'
    &&(origin.protocol==='https:'||origin.protocol==='http:'&&HTTP_HOSTS.includes(origin.hostname)),'PONDER_URL_REJECTED');
  check(client&&['getChainId','getBlock','getLogs','getTransactionReceipt'].every(name=>typeof client[name]==='function')
    &&typeof fetchImpl==='function'&&typeof fallbackToRpc==='boolean'&&(onDiagnostic===undefined||typeof onDiagnostic==='function'),'PONDER_CLIENT_REQUIRED');
  check(['full','logs'].includes(mode),'PONDER_MODE_INVALID');
  for(const [value,max]of [[pageSize,1000],[maxPages,10000],[maxLogs,1000000],[maxResponseBytes,32*1024*1024],[timeoutMs,60000]])
    check(Number.isSafeInteger(value)&&value>0&&value<=max,'PONDER_LIMIT_INVALID');
  const diagnostic={enabled:true,mode,requests:0,fallbacks:0,lastStatus:'unused',lastError:null,
    completenessCryptographicallyVerified:false,independentRPCReceiptVerification:true};
  const note=(state,code=null)=>{diagnostic.lastStatus=state;diagnostic.lastError=code;try{onDiagnostic?.({...diagnostic});}catch{}};
  async function anchor(blockNumber){
    check(await client.getChainId()===p.chainId,'PONDER_RPC_CHAIN_MISMATCH');
    const block=await client.getBlock({blockNumber});
    check(quantity(block.number)===blockNumber&&HASH.test(block.hash),'PONDER_RPC_BLOCK_INVALID');
    return {blockNumber:blockNumber.toString(),blockHash:block.hash.toLowerCase()};
  }
  function envelope(value,schema,snapshot){
    check(value?.schema===schema&&value.chainId===p.chainId,'PONDER_RESPONSE_IDENTITY_MISMATCH');
    check(value.snapshot?.complete===true&&decimal(value.snapshot.blockNumber)===snapshot.blockNumber
      &&sameHash(value.snapshot.blockHash,snapshot.blockHash),'PONDER_SNAPSHOT_MISMATCH');
  }
  async function request(endpoint,parameters,snapshot){
    const url=new URL(endpoint,origin);
    for(const [key,value]of Object.entries({...parameters,chainId:p.chainId,snapshotBlockNumber:snapshot.blockNumber,snapshotBlockHash:snapshot.blockHash}))
      if(value!==undefined&&value!==null)url.searchParams.set(key,String(value));
    let response;diagnostic.requests++;
    try{response=await fetchImpl(url,{method:'GET',headers:{accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(timeoutMs)});}
    catch{throw Object.assign(new Error('PONDER_UNAVAILABLE'),{code:'PONDER_UNAVAILABLE'});}
    // Any non-success status is an unavailable indexer, never a verification
    // verdict: a 5xx from a failing indexer or an unexpected 4xx falls back to
    // RPC exactly like a lagging 409, instead of stopping the publisher or API.
    if(!response.ok){
      await response.body?.cancel();throw Object.assign(new Error('PONDER_UNAVAILABLE'),{code:'PONDER_UNAVAILABLE'});
    }
    try{return await readJSON(response,maxResponseBytes);}
    catch(error){if(error.code?.startsWith('PONDER_'))throw error;throw Object.assign(new Error('PONDER_UNAVAILABLE'),{code:'PONDER_UNAVAILABLE'});}
  }
  async function usePonder(run,fallback){
    try{const result=await run();note('verified');return result;}
    catch(error){note('rejected',error.code??'PONDER_VERIFICATION_FAILED');
      if(error.code==='PONDER_UNAVAILABLE'&&fallbackToRpc){diagnostic.fallbacks++;note('rpc-fallback',error.code);return fallback();}throw error;}
  }
  // Ponder handlers store transactions that emitted successful tracked events.
  // A reverted call to the pool has no indexed event and must remain RPC-only.
  const hasIndexedEvents=receipt=>['success','0x1',1].includes(receipt.status)
    &&receipt.logs?.some(log=>tracked.has(log.address?.toLowerCase()));
  const wrapped=Object.create(client);
  wrapped.ponderSourceStatus=()=>({...diagnostic});
  wrapped.getLogs=async options=>{
    // Filters outside the two configured contracts retain the original RPC semantics.
    if(!options||typeof options.address!=='string'||!tracked.has(options.address.toLowerCase())
      ||Object.keys(options).some(key=>!['address','fromBlock','toBlock'].includes(key)))return client.getLogs(options);
    const address=options.address.toLowerCase(),fromBlock=quantity(options.fromBlock),toBlock=quantity(options.toBlock);
    check(fromBlock<=toBlock,'PONDER_INVALID_RANGE');
    return usePonder(async()=>{
      const snapshot=await anchor(toBlock),logs=[],cursors=new Set(),positions=new Set(),headers=new Map();let cursor=null,previous=null;
      for(let page=0;page<maxPages;page++){
        const value=await request('/v1/logs',{address,fromBlock:fromBlock.toString(),toBlock:toBlock.toString(),limit:pageSize,cursor},snapshot);
        envelope(value,'lincoln-ponder-logs/v1',snapshot);
        check(value.address?.toLowerCase()===address&&decimal(value.fromBlock)===fromBlock.toString()&&decimal(value.toBlock)===toBlock.toString()
          &&Array.isArray(value.logs)&&value.logs.length<=pageSize,'PONDER_RANGE_MISMATCH');
        for(const raw of value.logs){
          const log=normalizeLog(raw),next=position(log),key=`${log.blockNumber}:${log.logIndex}`;
          check(log.address===address&&log.blockNumber>=fromBlock&&log.blockNumber<=toBlock,'PONDER_LOG_OUT_OF_RANGE');
          check((previous===null||compare(previous,next)<0)&&!positions.has(key),'PONDER_LOG_ORDER_INVALID');
          previous=next;positions.add(key);logs.push(log);check(logs.length<=maxLogs,'PONDER_LOG_LIMIT_EXCEEDED');
          const number=log.blockNumber.toString();
          if(!headers.has(number))headers.set(number,await anchor(log.blockNumber));
          check(headers.get(number).blockHash===log.blockHash,'PONDER_LOG_BLOCK_MISMATCH');
        }
        check(value.nextCursor===null||typeof value.nextCursor==='string'&&/^[A-Za-z0-9_-]{1,2048}$/.test(value.nextCursor),'PONDER_CURSOR_INVALID');
        if(value.nextCursor===null){check((await anchor(toBlock)).blockHash===snapshot.blockHash,'PONDER_SNAPSHOT_REORGANIZED');return logs;}
        check(value.logs.length>0&&!cursors.has(value.nextCursor),'PONDER_CURSOR_INVALID');
        cursors.add(value.nextCursor);cursor=value.nextCursor;
      }
      check(false,'PONDER_PAGE_LIMIT_EXCEEDED');
    },()=>client.getLogs(options));
  };
  // Log transport alone is enough for an API using the existing complete RPC
  // receipt checks. Full mode adds an indexer/RPC crosscheck for explicit probes.
  if(mode==='logs')return wrapped;
  wrapped.getTransactionReceipt=async options=>{
    const receipt=await client.getTransactionReceipt(options);
    if(!hasIndexedEvents(receipt))return receipt;
    return usePonder(async()=>{
      const snapshot=await anchor(quantity(receipt.blockNumber));
      const value=await request('/v1/receipt',{hash:options.hash},snapshot);envelope(value,'lincoln-ponder-receipt/v1',snapshot);
      const indexed=value.receipt;
      check(indexed&&sameHash(indexed.transactionHash,receipt.transactionHash)&&sameHash(indexed.transactionHash,options.hash)
        &&sameHash(indexed.blockHash,receipt.blockHash)&&decimal(indexed.blockNumber)===decimal(receipt.blockNumber)
        &&status(indexed.status)===status(receipt.status)&&Array.isArray(indexed.logs)&&indexed.logs.length===receipt.logs.length
        &&indexed.logs.every((log,i)=>logFingerprint(log)===logFingerprint(receipt.logs[i])),'PONDER_RECEIPT_MISMATCH');
      check(sameHash(receipt.blockHash,snapshot.blockHash)&&(await anchor(quantity(receipt.blockNumber))).blockHash===snapshot.blockHash,'PONDER_SNAPSHOT_REORGANIZED');
      return receipt;
    },()=>receipt);
  };
  if(typeof client.getTransaction==='function')wrapped.getTransaction=async options=>{
    const transaction=await client.getTransaction(options);
    if(transaction.blockNumber===null||transaction.blockNumber===undefined||transaction.blockHash===null)return transaction;
    const receipt=await client.getTransactionReceipt({hash:options.hash});
    check(sameHash(receipt.transactionHash,transaction.hash)&&sameHash(transaction.hash,options.hash)
      &&sameHash(receipt.blockHash,transaction.blockHash)&&decimal(receipt.blockNumber)===decimal(transaction.blockNumber),'PONDER_RPC_RECEIPT_MISMATCH');
    if(!hasIndexedEvents(receipt))return transaction;
    return usePonder(async()=>{
      const snapshot=await anchor(quantity(transaction.blockNumber));
      const value=await request('/v1/transaction',{hash:options.hash},snapshot);envelope(value,'lincoln-ponder-transaction/v1',snapshot);
      check(JSON.stringify(transactionFacts(value.transaction))===JSON.stringify(transactionFacts(transaction))
        &&sameHash(transaction.hash,options.hash)&&(value.transaction.chainId===undefined||quantity(value.transaction.chainId)===BigInt(p.chainId)),'PONDER_TRANSACTION_MISMATCH');
      check(sameHash(transaction.blockHash,snapshot.blockHash)&&(await anchor(quantity(transaction.blockNumber))).blockHash===snapshot.blockHash,'PONDER_SNAPSHOT_REORGANIZED');
      return transaction;
    },()=>transaction);
  };
  return wrapped;
}
