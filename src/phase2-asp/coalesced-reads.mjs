// SPDX-License-Identifier: Apache-2.0
// Pool syncs that run in the same moment are answered by one request where the
// RPC allows it: eth_getLogs accepts an address list, so the roster's log
// windows ending at the same block go out as one call, and identical getBlock,
// getBlockNumber and getLogs calls share one in-flight request. Every caller
// still receives exactly the logs it asked for (its address, its range), so the
// range checks in state.mjs are unchanged. Providers charge one request for the
// merged call whether they bill per request or per method weight.
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const isAddress=v=>typeof v==='string'&&/^0x[0-9a-fA-F]{40}$/.test(v);
const quantity=v=>typeof v==='bigint'?v:BigInt(v);

/** Calls arriving within this window are merged; a sync's pools each issue their
 * log reads a few milliseconds apart after their shared head read. */
export const COALESCE_WINDOW_MS=40;
/** A merged window never spans more than this many blocks, so one pool far behind
 * (a cold checkpoint) cannot widen everyone else's request. state.mjs reads in
 * 2000-block chunks, so steady-state windows always fit. */
export const COALESCE_MAX_SPAN=2000n;

export function withCoalescedReads(client,{windowMs=COALESCE_WINDOW_MS,maxSpan=COALESCE_MAX_SPAN,setTimer=setTimeout}={}){
  need(client&&typeof client.getLogs==='function'&&typeof client.getBlock==='function'&&typeof client.getBlockNumber==='function','COALESCED_READ_CLIENT_REQUIRED');
  need(Number.isSafeInteger(windowMs)&&windowMs>=0&&windowMs<=1000&&typeof maxSpan==='bigint'&&maxSpan>=1n&&maxSpan<=100000n&&typeof setTimer==='function','COALESCED_READ_OPTIONS_INVALID');
  const wrapped=Object.create(client),inFlight=new Map(),open=[],stats={requests:0,merged:0,shared:0,fallbacks:0};
  // One request for identical concurrent calls. A settled answer is forgotten at
  // once, or after `linger` more milliseconds for reads whose callers in one
  // sync pass arrive a few milliseconds apart (a numbered block header: the same
  // pinned block for every pool). A failure is never replayed.
  function share(key,run,linger=0){
    let pending=inFlight.get(key);
    if(pending){stats.shared++;return pending;}
    const forget=()=>{if(inFlight.get(key)===pending)inFlight.delete(key);};
    pending=run().then(value=>{if(linger>0){const timer=setTimer(forget,linger);timer.unref?.();}else forget();return value;},error=>{forget();throw error;});
    inFlight.set(key,pending);return pending;
  }
  wrapped.getBlock=options=>{
    if(options&&typeof options.blockNumber==='bigint'&&Object.keys(options).length===1)return share(`block:${options.blockNumber}`,()=>client.getBlock(options),windowMs);
    return client.getBlock(options);
  };
  wrapped.getBlockNumber=options=>options===undefined?share('head',()=>client.getBlockNumber()):client.getBlockNumber(options);
  wrapped.getLogs=options=>{
    const simple=options&&isAddress(options.address)&&typeof options.fromBlock==='bigint'&&typeof options.toBlock==='bigint'
      &&options.fromBlock<=options.toBlock&&Object.keys(options).every(key=>['address','fromBlock','toBlock'].includes(key));
    if(!simple)return client.getLogs(options);
    return share(`logs:${options.address.toLowerCase()}:${options.fromBlock}:${options.toBlock}`,()=>enqueue(options));
  };
  wrapped.coalescedReadStatus=()=>({...stats,openWindows:open.length});
  function enqueue(options){
    return new Promise((resolve,reject)=>{
      const entry={options,address:options.address.toLowerCase(),fromBlock:options.fromBlock,toBlock:options.toBlock,resolve,reject};
      for(const group of open){
        if(group.toBlock!==entry.toBlock)continue;
        const minFrom=entry.fromBlock<group.minFrom?entry.fromBlock:group.minFrom;
        if(group.toBlock-minFrom>=maxSpan)continue;
        group.entries.push(entry);group.minFrom=minFrom;return;
      }
      const group={toBlock:entry.toBlock,minFrom:entry.fromBlock,entries:[entry],timer:null};
      open.push(group);
      // Not unref'd: callers are waiting on this timer, and a one-shot process
      // must not exit before their logs are fetched.
      group.timer=setTimer(()=>{const at=open.indexOf(group);if(at>=0)open.splice(at,1);void flush(group);},windowMs);
    });
  }
  async function flush(group){
    const {entries}=group;
    if(entries.length===1){const [entry]=entries;stats.requests++;return client.getLogs(entry.options).then(entry.resolve,entry.reject);}
    const addresses=[...new Set(entries.map(entry=>entry.address))];
    let logs;
    try{stats.requests++;logs=await client.getLogs({address:addresses,fromBlock:group.minFrom,toBlock:group.toBlock});need(Array.isArray(logs),'COALESCED_LOGS_INVALID');}
    catch{
      // The merged request was refused (a result cap, an address-list limit):
      // every caller gets its own original request instead, exactly as before.
      stats.fallbacks++;
      await Promise.all(entries.map(entry=>client.getLogs(entry.options).then(entry.resolve,entry.reject)));
      return;
    }
    stats.merged+=entries.length-1;
    for(const entry of entries){
      try{
        entry.resolve(logs.filter(log=>typeof log?.address==='string'&&log.address.toLowerCase()===entry.address
          &&log.blockNumber!=null&&quantity(log.blockNumber)>=entry.fromBlock&&quantity(log.blockNumber)<=entry.toBlock));
      }catch(error){entry.reject(error);}
    }
  }
  return wrapped;
}
