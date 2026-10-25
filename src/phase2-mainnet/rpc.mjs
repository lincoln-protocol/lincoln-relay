// SPDX-License-Identifier: Apache-2.0
// Private endpoints remain in this process: never put them in public profiles,
// argv, environment values, transport metadata, or persisted errors.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {isIP} from 'node:net';
import {createPublicClient,defineChain,http,webSocket} from 'viem';
import {MAINNET_RPC} from './signer.mjs';
import {attachMainnetBroadcastClassification} from './broadcast-errors.mjs';

export const MAINNET_RPC_FILE='/run/secrets/mainnet-rpc-url';
export const MAINNET_GENESIS_HASH='0xaad15f3d702aaea00caf3e9bb56395efe9127bc3b31b24921abf1eee3409305c';
// Multicall3 at its canonical cross-chain address, verified deployed on
// Robinhood Chain. viem aggregates the contract reads a pool sync issues in
// one tick (root, leaf index, policy, caps, governance window) into one
// aggregate3 eth_call at the same pinned block: one billed request per batch
// instead of one per getter, with identical per-call decoding and reverts.
export const MAINNET_MULTICALL3='0xcA11bde05977b3631167028862bE2a173976CA11';
const MAINNET_READ_BATCH={multicall:{batchSize:32768,wait:0}};
const ROBINHOOD_CHAIN=defineChain({id:4663,name:'Robinhood Chain',nativeCurrency:{name:'Ether',symbol:'ETH',decimals:18},
  rpcUrls:{default:{http:[MAINNET_RPC]}},contracts:{multicall3:{address:MAINNET_MULTICALL3}}});
const fail=code=>Object.assign(new Error(code),{code});
const need=(ok,code)=>{if(!ok)throw fail(code);};
const own=(value,key)=>{try{return value&&typeof value==='object'?Object.getOwnPropertyDescriptor(value,key)?.value:undefined;}catch{return undefined;}};

function publicHost(hostname){
  const host=hostname.toLowerCase().replace(/^\[|\]$/g,'').replace(/\.$/,'');
  if(!host||host==='localhost'||!host.includes('.')&&isIP(host)!==6||/(?:^|\.)(?:localhost|local|internal|home|lan)$/.test(host))return false;
  if(isIP(host)===4){
    const [a,b]=host.split('.').map(Number);
    return !(a===0||a===10||a===127||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&[0,168].includes(b)
      ||a===100&&b>=64&&b<=127||a===198&&[18,19].includes(b)||a>=224);
  }
  // Only globally routed IPv6 unicast. This also rejects IPv4-mapped literals,
  // loopback, unspecified, link-local, unique-local and multicast addresses.
  if(isIP(host)===6)return /^[23][0-9a-f]{3}:/.test(host);
  return true;
}

export function validateMainnetRPCURL(value){
  need(typeof value==='string'&&value.length>0&&value.length<=8192&&!/\s/.test(value),'MAINNET_RPC_URL_INVALID');
  let url;try{url=new URL(value);}catch{throw fail('MAINNET_RPC_URL_INVALID');}
  need(url.protocol==='https:'&&!url.hash&&!value.includes('#')&&!url.username&&!url.password&&publicHost(url.hostname),'MAINNET_RPC_URL_INVALID');
  return value;
}

/** No explicit file => optional fixed secret mount => public official default.
 * An explicitly configured missing or unsafe file always fails closed.
 */
export async function resolveMainnetRPC({env=process.env}={}){
  need(env.PHASE2_MAINNET_RPC_URL===undefined,'MAINNET_RPC_URL_ENV_FORBIDDEN');
  const explicit=env.PHASE2_MAINNET_RPC_FILE!==undefined,filename=explicit?env.PHASE2_MAINNET_RPC_FILE:MAINNET_RPC_FILE;
  need(typeof filename==='string'&&path.isAbsolute(filename)&&path.normalize(filename)===filename,'MAINNET_RPC_FILE_INVALID');
  let handle;
  try{
    handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const stat=await handle.stat();
    need(stat.isFile()&&stat.nlink===1&&stat.size>0&&stat.size<=8192&&(stat.mode&0o7777)===0o600
      &&(typeof process.getuid!=='function'||stat.uid===process.getuid())&&await fs.realpath(filename)===filename,'MAINNET_RPC_FILE_INVALID');
    // Keep the read bounded even if the file changes after fstat.
    const buffer=Buffer.alloc(8193);let length=0;
    while(length<buffer.length){const {bytesRead}=await handle.read(buffer,length,buffer.length-length,null);if(!bytesRead)break;length+=bytesRead;}
    need(length>0&&length<=8192,'MAINNET_RPC_FILE_INVALID');const bytes=buffer.subarray(0,length);
    let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{throw fail('MAINNET_RPC_FILE_INVALID');}
    return {url:validateMainnetRPCURL(text.replace(/\r?\n$/,'')),source:'secret-file'};
  }catch(error){
    if(!explicit&&error.code==='ENOENT')return {url:MAINNET_RPC,source:'official-default'};
    if(['MAINNET_RPC_FILE_INVALID','MAINNET_RPC_URL_INVALID'].includes(error.code))throw error;
    throw fail('MAINNET_RPC_FILE_INVALID');
  }finally{await handle?.close();}
}

/** Read only enum/numeric own properties. Never preserve original messages,
 * nested data, URL, response headers, raw transactions, or the original cause.
 */
export function sanitizeMainnetRPCError(error){
  const chain=[],seen=new Set();for(let current=error;current&&typeof current==='object'&&!seen.has(current)&&chain.length<12;current=own(current,'cause')){seen.add(current);chain.push(current);}
  const names=chain.map(e=>own(e,'name')),code=chain.map(e=>own(e,'code')).find(v=>Number.isSafeInteger(v));
  const timeout=names.includes('TimeoutError')||chain.some(e=>own(e,'code')==='ETIMEDOUT');
  const reverted=code===3||names.includes('ExecutionRevertedError')||names.includes('ContractFunctionRevertedError');
  const clean=fail(timeout?'MAINNET_RPC_TIMEOUT':reverted?'MAINNET_RPC_EXECUTION_REVERTED':'MAINNET_RPC_REQUEST_FAILED');
  clean.name=timeout?'TimeoutError':reverted?'ExecutionRevertedError':names.includes('HttpRequestError')?'HttpRequestError':'RpcRequestError';
  // viem's readContract wrapper drops the numeric cause when constructing its
  // typed revert. This fixed standard phrase preserves revert classification
  // without retaining the provider's potentially credential-bearing reason.
  if(reverted)clean.message='execution reverted';
  if(code!==undefined)clean.code=code;
  const status=chain.map(e=>own(e,'status')).find(v=>Number.isSafeInteger(v)&&v>=100&&v<=599);
  if(status!==undefined)clean.status=status;
  return attachMainnetBroadcastClassification(clean,error);
}

const READS=new Set(['eth_chainId','eth_getBlockByNumber','eth_getBlockByHash','eth_getCode','eth_call','eth_getLogs',
  'eth_getBalance','eth_getTransactionCount','eth_getTransactionReceipt','eth_getTransactionByHash','eth_gasPrice','eth_estimateGas']);
const LANE_BACKOFF_MS=60000;
// A transport-level failure (socket, HTTP, timeout) may move a read to the next
// lane. A JSON-RPC rejection or revert is the node's answer and is never retried.
// viem reports a socket that could not connect or closed as code -1 (unknown),
// never as a numbered JSON-RPC error.
const transportFailure=clean=>clean.name==='TimeoutError'||clean.name==='HttpRequestError'||clean.name==='RpcRequestError'&&(clean.code===undefined||clean.code===-1);

/** Reads travel over up to three lanes, in order: one multiplexed WebSocket
 * (opt-in), JSON-RPC batches over HTTP, then single HTTP requests. A lane that
 * fails at the transport level is skipped for a minute; broadcasts and unknown
 * methods always use exactly ONE single HTTP attempt.
 */
export function mainnetRPCTransport(url,{batch=true,webSocket:socket=false}={}){
  validateMainnetRPCURL(url);
  const options={timeout:20000,retryCount:0,fetchOptions:{redirect:'error'}};
  const direct=http(url,options),grouped=batch?http(url,{...options,batch:{batchSize:16,wait:8}}):null;
  // viem's own reconnect loop logs its errors, which name the endpoint. Keep it
  // off: a failed socket is closed and discarded here, and the lane reopens a
  // fresh connection after its backoff. Nothing from this lane is ever logged.
  // viem's keep-alive timer would hold the process open, so a stalled socket is
  // detected by the request timeout instead and then discarded.
  const streamed=socket?webSocket(url.replace(/^https:/,'wss:'),{timeout:20000,retryCount:0,keepAlive:false,reconnect:false}):null;
  return config=>{
    const transport=direct(config),lanes=[[grouped?.(config),'batch'],[streamed?.(config),'socket']].filter(([lane])=>lane).reverse();
    const disabledUntil=new Map();let socketOpened=false;
    const discardSocket=()=>{const lane=lanes.find(([,name])=>name==='socket')?.[0];if(!lane||!socketOpened)return Promise.resolve();socketOpened=false;
      return Promise.resolve().then(()=>lane.value?.getRpcClient?.()).then(client=>client?.close()).catch(()=>{});};
    const request=async(args,requestOptions)=>{
      const settings={...requestOptions,retryCount:0};
      if(READS.has(args?.method))for(const [lane,name] of lanes){
        if(Date.now()<(disabledUntil.get(name)??0))continue;
        try{const result=await lane.request(args,settings);if(name==='socket')socketOpened=true;return result;}
        catch(error){
          const clean=sanitizeMainnetRPCError(error);if(!transportFailure(clean))throw clean;
          disabledUntil.set(name,Date.now()+LANE_BACKOFF_MS);
          if(name==='socket'){socketOpened=true;void discardSocket();}
        }
      }
      // Broadcasts and unknown methods get exactly ONE transport attempt. Only
      // enumerated idempotent reads may retry explicit transient availability
      // errors; deterministic RPC rejections/reverts are never retried here.
      for(let attempt=0;;attempt++)try{return await transport.request(args,settings);}
      catch(error){
        const clean=sanitizeMainnetRPCError(error),transient=clean.name==='TimeoutError'
          ||clean.name==='HttpRequestError'&&(clean.status===undefined||[408,429,502,503,504].includes(clean.status));
        if(!READS.has(args?.method)||!transient||attempt>=2)throw clean;
        await new Promise(resolve=>setTimeout(resolve,attempt===0?250:750));
      }
    };
    // close() releases an open socket lane so one-shot commands can exit.
    return {config:{...transport.config,request,retryCount:0},request,value:{close:()=>discardSocket()}};
  };
}

export async function assertMainnetRPCIdentity(client,{expectedGenesisHash=MAINNET_GENESIS_HASH}={}){
  need(expectedGenesisHash===MAINNET_GENESIS_HASH,'MAINNET_RUNTIME_CHAIN_IDENTITY_MISMATCH');
  need(await client.getChainId()===4663&&(await client.getBlock({blockNumber:0n})).hash===MAINNET_GENESIS_HASH,'MAINNET_RUNTIME_CHAIN_IDENTITY_MISMATCH');
}

/** PHASE2_MAINNET_RPC_BATCH=0 turns the JSON-RPC batch lane off, so concurrent reads
 * travel as concurrent single requests. Providers that answer a batch's items one
 * after another (dRPC) make a batch of sixteen receipts take sixteen round trips;
 * the same reads as single requests run in parallel and cost the same per item.
 * The default stays on for providers that run batch items in parallel. */
export function mainnetRPCTransportOptions(env={}){
  need(env.PHASE2_MAINNET_RPC_WEBSOCKET===undefined||['0','1'].includes(env.PHASE2_MAINNET_RPC_WEBSOCKET),'MAINNET_RPC_WEBSOCKET_INVALID');
  need(env.PHASE2_MAINNET_RPC_BATCH===undefined||['0','1'].includes(env.PHASE2_MAINNET_RPC_BATCH),'MAINNET_RPC_BATCH_INVALID');
  return {batch:env.PHASE2_MAINNET_RPC_BATCH!=='0',webSocket:env.PHASE2_MAINNET_RPC_WEBSOCKET==='1'};
}

export async function createMainnetRuntimeClient({env=process.env,expectedGenesisHash=MAINNET_GENESIS_HASH}={}){
  const {url}=await resolveMainnetRPC({env});
  const client=createPublicClient({chain:ROBINHOOD_CHAIN,transport:mainnetRPCTransport(url,mainnetRPCTransportOptions(env)),cacheTime:0,batch:MAINNET_READ_BATCH});
  Object.defineProperty(client,'close',{value:async()=>{await client.transport.close?.();},enumerable:false});
  await assertMainnetRPCIdentity(client,{expectedGenesisHash});
  return client;
}
