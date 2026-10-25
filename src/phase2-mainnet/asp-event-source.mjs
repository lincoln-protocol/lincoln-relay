// SPDX-License-Identifier: Apache-2.0
// WebSocket messages are wake hints only. Canonical HTTP/operator snapshots
// remain the only authority for roots, confirmations, signatures and spending.
import fs from 'node:fs/promises';
import {constants,watch} from 'node:fs';
import path from 'node:path';
import {keccak256,toBytes} from 'viem';

const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const address=v=>typeof v==='string'&&/^0x[0-9a-f]{40}$/i.test(v);
const hash=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/i.test(v);
const rpcQuantity=v=>typeof v==='string'&&/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/i.test(v);
const qty=v=>typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v);
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
export const ASP_COMMITMENT_TOPIC=keccak256(toBytes('NewCommitment(uint256,uint256,bytes)'));
export const ASP_PUBLICATION_EVENT_FILE='publication-event.json';

/** The socket heartbeat is one eth_blockNumber per ASP_EVENT_HEARTBEAT_MS on the
 * open connection; the answer must arrive and the height must advance within
 * ASP_EVENT_STALE_MS or the connection is replaced. Providers bill every frame
 * on a socket like a request, so a newHeads subscription (one frame per block,
 * ten blocks a second here) is deliberately not used: the commitment log
 * subscription is the only stream, and it is silent until a deposit lands.
 */
export const ASP_EVENT_HEARTBEAT_MS=15000,ASP_EVENT_STALE_MS=45000;

/** Construct ONLY with the already validated runtime HTTP secret. This object
 * deliberately exposes neither endpoint, socket, error objects nor transports.
 * start() opens one connection; import/construction opens no network resource.
 */
export function createASPEventSource({rpcURL,profiles,WebSocketImpl=globalThis.WebSocket,heartbeatMs=ASP_EVENT_HEARTBEAT_MS,staleMs=ASP_EVENT_STALE_MS}={}){
  need(Array.isArray(profiles)&&profiles.length>0&&profiles.length<=32,'ASP_EVENT_ROSTER_REQUIRED');
  const pools=profiles.map(p=>p.pool?.address?.toLowerCase()),chainId=profiles[0].chain?.id,genesis=profiles[0].genesisHash;
  need(pools.every(address)&&new Set(pools).size===pools.length&&Number.isSafeInteger(chainId)&&chainId>0&&hash(genesis)
    &&profiles.every(p=>p.chain?.id===chainId&&p.genesisHash===genesis),'ASP_EVENT_ROSTER_INVALID');
  need(Number.isSafeInteger(heartbeatMs)&&heartbeatMs>=50&&heartbeatMs<=60000&&Number.isSafeInteger(staleMs)&&staleMs>=2*heartbeatMs&&staleMs<=600000,'ASP_EVENT_OPTIONS_INVALID');
  let endpoint;try{endpoint=new URL(rpcURL);}catch{throw new Error('ASP_EVENT_RPC_INVALID');}
  need(endpoint.protocol==='https:'&&!endpoint.username&&!endpoint.password&&!endpoint.hash,'ASP_EVENT_RPC_INVALID');
  endpoint.protocol='wss:';
  need(typeof WebSocketImpl==='function','ASP_EVENT_WEBSOCKET_UNAVAILABLE');
  const approvedPools=new Set(pools);let socket=null,retry=null,deadline=null,watchdog=null,pulse=null,wake=null,stopped=true,generation=0,attempt=0;
  let observation='stopped';
  function clearTimers(){clearTimeout(retry);clearTimeout(deadline);clearInterval(watchdog);clearInterval(pulse);retry=null;deadline=null;watchdog=null;pulse=null;}
  function notify(reason){if(stopped)return;try{wake?.(reason);}catch{/* canonical polling remains independent of this hint */}}
  function connect(){
    if(stopped)return;retry=null;const tag=++generation;observation='connecting';let ws;
    try{ws=new WebSocketImpl(endpoint.href);}catch{return reconnect(tag);}
    socket=ws;let lastMessage=Date.now(),lastProgress=Date.now(),lastHeight=null,pulsePending=false;
    let chainOK=false,genesisOK=!hash(genesis),subscribed=false,logsSubscription=null,ready=false;
    function send(id,method,params){if(stopped||tag!==generation)return false;try{ws.send(JSON.stringify({jsonrpc:'2.0',id,method,params}));return true;}catch{reconnect(tag);return false;}}
    function subscribe(){if(!chainOK||!genesisOK||subscribed)return;subscribed=true;send(3,'eth_subscribe',['logs',{address:pools,topics:[ASP_COMMITMENT_TOPIC]}]);}
    deadline=setTimeout(()=>reconnect(tag),10000);deadline.unref?.();
    // Replayed frames, unrelated frames or JSON-RPC chatter cannot keep a dead
    // connection alive: only an answered heartbeat with a higher height counts.
    watchdog=setInterval(()=>{const now=Date.now();if(now-lastMessage>staleMs||ready&&now-lastProgress>staleMs)reconnect(tag);},Math.max(50,Math.floor(staleMs/4)));watchdog.unref?.();
    ws.addEventListener('open',()=>{if(stopped||tag!==generation)return;
      send(1,'eth_chainId',[]);if(hash(genesis))send(2,'eth_getBlockByNumber',['0x0',false]);
    });
    ws.addEventListener('message',event=>{
      if(stopped||tag!==generation)return;lastMessage=Date.now();
      // No provider payload/error may escape this closure or reach logging.
      if(typeof event.data!=='string'||event.data.length>262144)return reconnect(tag);
      let message;try{message=JSON.parse(event.data);}catch{return reconnect(tag);}
      if(!message||typeof message!=='object'||Array.isArray(message))return reconnect(tag);
      if(message.id!==undefined){
        if(message.error)return reconnect(tag);
        if(message.id===1){if(message.result!==`0x${chainId.toString(16)}`)return reconnect(tag);chainOK=true;subscribe();}
        else if(message.id===2){if(!same(message.result?.hash,genesis))return reconnect(tag);genesisOK=true;subscribe();}
        else if(message.id===3){if(!subscribed||typeof message.result!=='string'||message.result.length===0||message.result.length>256)return reconnect(tag);
          if(logsSubscription!==null&&logsSubscription!==message.result)return reconnect(tag);
          logsSubscription=message.result;
          if(!ready){ready=true;clearTimeout(deadline);deadline=null;attempt=0;observation='subscribed';lastProgress=Date.now();
            pulse=setInterval(()=>{if(pulsePending)return;pulsePending=true;send(5,'eth_blockNumber',[]);},heartbeatMs);pulse.unref?.();
            // Includes the initial connection and every reconnection. A silent
            // gap may contain deposits even when no later matching log arrives.
            notify('connection-ready');}
        }
        else if(message.id===5){
          // An unsolicited or malformed heartbeat answer is a protocol violation.
          if(!ready||!pulsePending||!rpcQuantity(message.result))return reconnect(tag);
          pulsePending=false;const height=BigInt(message.result);
          if(lastHeight===null||height>lastHeight){lastHeight=height;lastProgress=Date.now();}
        }
        return;
      }
      if(message.method!=='eth_subscription'||logsSubscription===null||message.params?.subscription!==logsSubscription)return;
      const data=message.params?.result;
      // A removed log still wakes canonical reconciliation, never approval.
      if(address(data?.address)&&approvedPools.has(data.address.toLowerCase())&&same(data?.topics?.[0],ASP_COMMITMENT_TOPIC)
        &&Array.isArray(data.topics)&&data.topics.length===3&&hash(data.blockHash))notify('commitment');
    });
    ws.addEventListener('close',()=>reconnect(tag));ws.addEventListener('error',()=>reconnect(tag));
  }
  function reconnect(tag){
    if(stopped||tag!==generation)return;generation++;clearTimeout(deadline);clearInterval(watchdog);clearInterval(pulse);deadline=null;watchdog=null;pulse=null;
    const previous=socket;socket=null;try{previous?.close();}catch{}
    observation='retrying';const ms=Math.min(30000,1000*2**Math.min(attempt++,5));
    // HTTP reconciliation can proceed during a WSS outage as well as after it.
    notify('connection-interrupted');
    retry=setTimeout(connect,ms);retry.unref?.();
  }
  return {
    start(onWake){need(stopped&&typeof onWake==='function','ASP_EVENT_SOURCE_ALREADY_STARTED');stopped=false;wake=onWake;attempt=0;connect();},
    close(){stopped=true;generation++;clearTimers();wake=null;const previous=socket;socket=null;try{previous?.close();}catch{}observation='stopped';},
    status(){return {status:observation,poolCount:pools.length};}
  };
}

async function readPublicJSON(filename,max){
  const handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await handle.stat();need(stat.isFile()&&stat.size<=max&&await fs.realpath(filename)===filename,'ASP_EVENT_FILE_INVALID');
    return JSON.parse(await handle.readFile('utf8'));
  }finally{await handle.close();}
}

// An unchanged published signal is re-verified against the canonical state at
// this cadence (a revocation or a closed accepted-policy window changes no
// public file). Each verification is a pool sync, or a snapshot inside the
// service's fresh window, so this bounds RPC spend per subscribed pool.
export const ASP_EVENT_CANONICAL_REVERIFY_MS=15000;
/** One watcher/poll/snapshot per service, shared by bounded SSE subscribers.
 * Signal files are only hints too: current.json and one canonical indexer sync
 * must agree before an event is emitted. No chain scan is done per subscriber.
 */
export function createASPPublicationEvents({profile,associationSetFile,sync,maxClients=16,pollIntervalMs=1000,now=Date.now}={}){
  need(typeof sync==='function'&&Number.isSafeInteger(maxClients)&&maxClients>0&&maxClients<=64
    &&Number.isSafeInteger(pollIntervalMs)&&pollIntervalMs>=250&&pollIntervalMs<=5000,'ASP_EVENT_OPTIONS_INVALID');
  const configured=typeof associationSetFile==='string'&&associationSetFile.length>0;
  const currentFile=configured?path.resolve(associationSetFile):null,directory=configured?path.dirname(currentFile):null;
  const signalFile=configured?path.join(directory,ASP_PUBLICATION_EVENT_FILE):null;
  const pool=profile?.pool?.address,scope=String(profile?.pool?.scope),registry=profile?.registry?.address,chainId=profile?.chain?.id;
  need(address(pool)&&address(registry)&&qty(scope)&&Number.isSafeInteger(chainId),'ASP_EVENT_PROFILE_INVALID');
  const clients=new Set();let watcher=null,poll=null,heartbeat=null,debounce=null,inFlight=null,pending=false,closed=false,last=null,verifiedCurrentToken=null,canonicalVerifiedAt=null,generation=0;
  const send=(res,bytes)=>{
    if(res.destroyed||res.writableEnded)return false;
    // Never queue an unbounded stream for a slow client. It can reconnect and
    // retrieve the same latest confirmed epoch without losing transaction state.
    try{if(res.writableLength>16384||!res.write(bytes)){res.destroy();return false;}return true;}
    catch{res.destroy();return false;}
  };
  const eventBytes=value=>`event: published\ndata: ${JSON.stringify(value)}\n\n`;
  const fresh=value=>value&&BigInt(value.validUntil)>BigInt(Math.floor(now()/1000));
  async function refresh(){
    if(closed||clients.size===0)return;if(inFlight){pending=true;return inFlight;}
    const tag=generation;
    inFlight=(async()=>{
      try{
        const signal=await readPublicJSON(signalFile,65536);
        need(signal?.schema==='phase2-asp-confirmed-publication/v1'&&signal.chainId===chainId&&same(signal.registry,registry)
          &&signal.activeFile===path.basename(currentFile)&&qty(signal.epoch)&&BigInt(signal.epoch)>0n&&qty(signal.root)
          &&qty(signal.validUntil)&&qty(signal.lastPublicationTimestamp)&&hash(signal.cidDigest)
          &&Array.isArray(signal.pools)&&signal.pools.some(p=>same(p.pool,pool)&&p.scope===scope),'ASP_EVENT_PUBLICATION_INVALID');
        const value={epoch:signal.epoch,root:signal.root,validUntil:signal.validUntil,lastPublicationTimestamp:signal.lastPublicationTimestamp};
        if(!fresh(value)){last=null;canonicalVerifiedAt=null;return;}
        const unchanged=last&&JSON.stringify(last)===JSON.stringify(value);
        const stat=await fs.lstat(currentFile,{bigint:true});
        need(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=80n*1024n*1024n,'ASP_EVENT_CURRENT_SET_MISMATCH');
        const fileToken=`${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
        if(!unchanged||fileToken!==verifiedCurrentToken){
          const current=await readPublicJSON(currentFile,80*1024*1024);
          need(current?.schema==='phase2-asp-operator-association-set/v1'&&current.chainId===chainId&&same(current.registry,registry)
            &&current.root===signal.root&&same(current.digest,signal.cidDigest)&&Array.isArray(current.leaves)
            &&Array.isArray(current.pools)&&current.pools.some(p=>same(p.pool,pool)&&p.scope===scope),'ASP_EVENT_CURRENT_SET_MISMATCH');
          verifiedCurrentToken=fileToken;
        }
        if(closed||tag!==generation||!fresh(value))return;
        // A published epoch can be revoked or leave its accepted-policy window
        // without either public file changing. Bound the shared canonical cache;
        // a new subscriber never bypasses this validation through the fast path.
        const age=canonicalVerifiedAt===null?Infinity:Number(now())-canonicalVerifiedAt;
        if(!unchanged||!Number.isFinite(age)||age<0||age>=ASP_EVENT_CANONICAL_REVERIFY_MS){
          const snapshot=await sync();
          need(snapshot.chainId===chainId&&same(snapshot.pool,pool)&&String(snapshot.scope)===scope
            &&snapshot.asp?.epoch===signal.epoch&&snapshot.asp.root===signal.root&&snapshot.asp.validUntil===signal.validUntil
            &&same(snapshot.asp.cidDigest,signal.cidDigest)&&snapshot.asp.expired===false&&snapshot.asp.spendable!==false
            &&Array.isArray(snapshot.asp.leaves),'ASP_EVENT_CANONICAL_STATE_MISMATCH');
          canonicalVerifiedAt=Number(now());
        }
        if(closed||tag!==generation||!fresh(value))return;
        if(unchanged){for(const res of clients)if(!res.aspPublishedEpoch){if(send(res,eventBytes(value)))res.aspPublishedEpoch=`${value.epoch}:${value.root}`;}return;}
        last=value;const bytes=eventBytes(value);for(const res of clients)if(send(res,bytes))res.aspPublishedEpoch=`${value.epoch}:${value.root}`;
      }catch{last=null;verifiedCurrentToken=null;canonicalVerifiedAt=null;/* missing, mismatched or unavailable publication is never emitted */}
    })().finally(()=>{inFlight=null;if(pending){pending=false;schedule();}});
    return inFlight;
  }
  function schedule(){if(debounce||closed||clients.size===0)return;debounce=setTimeout(()=>{debounce=null;void refresh();},25);debounce.unref?.();}
  function start(){
    generation++;
    try{watcher=watch(directory,(_type,name)=>{if(name===null||[ASP_PUBLICATION_EVENT_FILE,path.basename(currentFile)].includes(String(name)))schedule();});watcher.on('error',()=>{watcher?.close();watcher=null;});watcher.unref?.();}catch{}
    poll=setInterval(()=>{void refresh();},pollIntervalMs);poll.unref?.();
    heartbeat=setInterval(()=>{for(const res of clients)send(res,': heartbeat\n\n');},15000);heartbeat.unref?.();
    schedule();
  }
  function stop(){generation++;clearInterval(poll);clearInterval(heartbeat);clearTimeout(debounce);poll=null;heartbeat=null;debounce=null;watcher?.close();watcher=null;last=null;verifiedCurrentToken=null;canonicalVerifiedAt=null;pending=false;}
  return {
    subscribe(_req,res){
      if(!configured||closed)return false;
      if(clients.size>=maxClients){res.writeHead(503,{'Content-Type':'application/json','Retry-After':'5','Cache-Control':'no-store'});res.end('{"error":"ASP_EVENT_CAPACITY_REACHED"}');return true;}
      res.writeHead(200,{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache, no-transform',
        'X-Content-Type-Options':'nosniff','X-Accel-Buffering':'no'});res.flushHeaders?.();
      res.on('error',()=>res.destroy());
      clients.add(res);res.once('close',()=>{clients.delete(res);if(clients.size===0)stop();});
      send(res,': connected\n\n');
      if(clients.size===1)start();else schedule();
      return true;
    },
    async close(){closed=true;stop();for(const res of clients)res.destroy();clients.clear();await inFlight?.catch(()=>{});},
    status(){return {configured,subscribers:clients.size,maxClients};}
  };
}
