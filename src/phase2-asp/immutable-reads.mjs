// SPDX-License-Identifier: Apache-2.0
// Process-local reuse of reads whose answer cannot change: the genesis header
// and deployed runtime code. Every other read keeps its exact RPC semantics.
//
// Each pool sync re-reads the genesis block and the runtime code of its four
// pinned contracts at the current head. Code is immutable once deployed, so a
// result verified at an earlier block still answers a read at a later block;
// it is re-read from the RPC after ttlMs so a provider fault or an unexpected
// code change is still bounded in time. Empty code, failed reads and reads at
// a block below the verified block are never served from this cache.
const IMMUTABLE_READ_TTL_MS=600000,MAX_CODE_ENTRIES=1024;
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const addressOf=value=>typeof value==='string'&&/^0x[0-9a-f]{40}$/i.test(value)?value.toLowerCase():null;
const onlyKeys=(options,keys)=>options&&typeof options==='object'&&Object.keys(options).every(key=>keys.includes(key)||options[key]===undefined);

export function withImmutableReadCache(client,{ttlMs=IMMUTABLE_READ_TTL_MS,now=Date.now}={}){
  check(client&&typeof client.getBlock==='function'&&typeof client.getCode==='function','IMMUTABLE_READ_CLIENT_REQUIRED');
  check(Number.isSafeInteger(ttlMs)&&ttlMs>=1000&&ttlMs<=86400000&&typeof now==='function','IMMUTABLE_READ_OPTIONS_INVALID');
  let genesis=null;const codes=new Map();
  const wrapped=Object.create(client);
  wrapped.getBlock=options=>{
    // Only the exact header read the sync issues (`{blockNumber:0n}`) is kept.
    if(!onlyKeys(options,['blockNumber','includeTransactions'])||options.blockNumber!==0n||options.includeTransactions)return client.getBlock(options);
    if(!genesis){
      genesis=Promise.resolve(client.getBlock(options));
      genesis.catch(()=>{genesis=null;});
    }
    return genesis;
  };
  wrapped.getCode=options=>{
    const address=onlyKeys(options,['address','blockNumber','blockTag'])?addressOf(options.address):null;
    const at=options?.blockNumber;
    if(address===null||!(at===undefined||typeof at==='bigint'))return client.getCode(options);
    const entry=codes.get(address),time=now();
    if(entry&&entry.value&&time-entry.at<=ttlMs&&(at===undefined||at>=entry.blockNumber))return entry.value;
    if(entry?.pending&&(at===undefined||at>=entry.blockNumber))return entry.pending;
    const pending=Promise.resolve(client.getCode(options)).then(value=>{
      // Deployed code only: an empty or malformed answer is handed back as is
      // and read again next time, so a not-yet-deployed address never sticks.
      const keep=typeof value==='string'&&/^0x[0-9a-f]{2,}$/i.test(value);
      if(codes.get(address)?.pending===pending)codes.set(address,keep?{value,at:now(),blockNumber:at??0n}:undefined);
      if(!keep)codes.delete(address);
      return value;
    },error=>{if(codes.get(address)?.pending===pending)codes.delete(address);throw error;});
    codes.set(address,{pending,blockNumber:at??0n});
    while(codes.size>MAX_CODE_ENTRIES)codes.delete(codes.keys().next().value);
    return pending;
  };
  wrapped.immutableReadStatus=()=>({genesisCached:genesis!==null,codeEntries:codes.size,ttlMs});
  return wrapped;
}
export {IMMUTABLE_READ_TTL_MS};
