// SPDX-License-Identifier: Apache-2.0
// Public logs only. A pinned RPC remains a trust assumption, not a completeness proof.
import { createHash } from 'node:crypto';
import { setTimeout as retryDelay } from 'node:timers/promises';
import { poseidon } from 'maci-crypto/build/ts/hashing.js';
import { BlockNotFoundError, decodeEventLog, keccak256, parseAbi } from 'viem';
import { openServiceStore } from '../phase1-service/store.mjs';
import { normalizeProfile, NOTE_MODEL, associationSetDigest, profileReleaseFlags } from './sdk.mjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ZERO = '0x0000000000000000000000000000000000000000';
const balanceABI = parseAbi(['function balanceOf(address) view returns (uint256)']);
const CAP_EVENTS = new Set(['CapsUpdated','CapIncreaseProposed','CapIncreaseCancelled','DepositsPaused']);
// Capability-like, process-local evidence: only this module can mark the exact
// checkpoint object produced after a successful complete sync. Disk reloads,
// clones and caller-reconstructed checkpoints never inherit this receipt cache.
// No watermark or trust bit is persisted in the checkpoint/schema/identity.
const verifiedReceiptCheckpoints = new WeakMap();
// Four exact successful objects at most per profile/ABI: latest, a recent
// rollback point, a point waiting to mature, and a safety-tag-observed point.
// They are only recovery candidates, never persisted trust or an RPC authority.
const retainedCheckpoints = new Map();
// Decoding is a pure function of (ABI, topics, data). Each sync replays the
// whole verified log history, so decode every distinct log once per process.
// The key is a SHA-256 of exactly those inputs (log data is attacker-chosen;
// no weak hash), and cached events are frozen so no caller can alter a shared one.
const DECODED = new Map(), DECODED_MAX = 20000;
function freezeEvent(event) {
  for (const value of Object.values(event.args ?? {})) if (value && typeof value === 'object') Object.freeze(value);
  if (event.args && typeof event.args === 'object') Object.freeze(event.args);
  return Object.freeze(event);
}
function decodeCached(abiKey, abi, log) {
  const key = createHash('sha256').update(abiKey).update('\0').update(log.topics.join(',')).update('\0').update(log.data).digest('base64');
  let event = DECODED.get(key);
  if (event === undefined) {
    event = freezeEvent(decodeEventLog({ abi, topics: log.topics, data: log.data, strict: true }));
    DECODED.set(key, event);
    if (DECODED.size > DECODED_MAX) DECODED.delete(DECODED.keys().next().value);
  }
  return event;
}
const safetyProbes = new WeakMap();
const RECOVERY_PROFILE_BYTES=16*1024*1024,RECOVERY_TOTAL_BYTES=128*1024*1024;
const RECOVERY_PROFILES=32,RECOVERY_SPACING=64n,SAFETY_PROBE_MS=30_000;
let retainedBytes=0;
const CAP_GETTERS = [
  ['maxDeposit',['uint128']],['maxTotal',['uint128']],['accountedBalance',['uint256']],
  ['pendingCaps',['uint128','uint128','uint64']],['depositsPaused',['bool']],['CAP_INCREASE_DELAY',['uint64']],
];
function hasDepositCaps(abi) {
  const functions=CAP_GETTERS.map(([name])=>abi.filter(item=>item.type==='function'&&item.name===name));
  if(functions.every(items=>items.length===0))return false;
  check(functions.every((items,index)=>items.length===1&&items[0].inputs?.length===0
    &&['view','pure'].includes(items[0].stateMutability)
    &&JSON.stringify(items[0].outputs?.map(output=>output.type))===JSON.stringify(CAP_GETTERS[index][1])),
    'POOL_CAPS_ARTIFACT_ABI_INVALID');
  return true;
}
function capQuantity(value,bits=128) {
  const n=qty(value);check(n<(1n<<BigInt(bits)),'INVALID_POOL_CAPS');return n;
}
function capPair(deposit,total) {
  const maxDeposit=capQuantity(deposit),maxTotal=capQuantity(total);
  check(maxDeposit>0n&&maxDeposit<=maxTotal,'INVALID_POOL_CAPS');return {maxDeposit,maxTotal};
}
const emptyCapProposal=()=>({maxDeposit:0n,maxTotal:0n,eta:0n});
// Guardian registry surface (audit M1/M2). Merged into the artifact ABI so these
// events decode even with an artifact built before the guardian registry.
const GOVERNANCE_ABI = parseAbi([
  'event ProviderRotationProposed(address indexed currentProvider, address indexed nextProvider, uint64 readyAt)',
  'event ProviderRotationCancelled(address indexed nextProvider)',
  'event ProviderRotated(address indexed previousProvider, address indexed nextProvider)',
  'event ProviderSuspended(address indexed provider, uint64 revokedThroughEpoch)',
  'event ProviderResumed(address indexed provider)',
  'function ACCEPTED_POLICY_WINDOW() view returns (uint64)',
  'function SUPERSEDED_POLICY_GRACE() view returns (uint256)',
  'function providerSuspended() view returns (bool)',
  'function revokedThroughEpoch() view returns (uint64)',
  'function policyAt(uint64 epoch) view returns (uint256 root, uint64 validUntil, uint64 supersededAt)',
  'function acceptedPolicy(uint64 epoch) view returns (uint256 root, uint64 validUntil)',
]);
const withGovernance = abi => {
  const present = new Set(abi.map(item => `${item.type}:${item.name}`));
  return [...abi, ...GOVERNANCE_ABI.filter(item => !present.has(`${item.type}:${item.name}`))];
};
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const wire = value => JSON.parse(JSON.stringify(value, (_, v) => typeof v === 'bigint' ? String(v) : v));
const check = (value, code) => { if (!value) throw Object.assign(new Error(code), { code }); };
const hash = value => typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value);
const qty = value => { check(typeof value === 'bigint' || typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value), 'INVALID_STATE_QUANTITY'); const n = BigInt(value); check(n >= 0n, 'INVALID_STATE_QUANTITY'); return n; };

async function readPinnedBlock(client,blockNumber){
  // Load-balanced RPC backends can learn a numbered head at different times.
  // Retry only this read at exactly the same height, at most three attempts;
  // never pick another head or relax the final canonical-hash comparison.
  const waits=[100,250];
  for(let attempt=0;;attempt++){
    try{return await client.getBlock({blockNumber});}
    catch(error){if(!(error instanceof BlockNotFoundError)||attempt>=waits.length)throw error;await retryDelay(waits[attempt]);}
  }
}

function checkpointCopy(checkpoint,identity,abiFingerprint,strict=false){
  try{
    const marked=verifiedReceiptCheckpoints.get(checkpoint),{digest,...body}=structuredClone(checkpoint);
    check(body.schema==='phase2-asp-public-checkpoint/v1'&&body.identity===identity&&sha(body)===digest
      &&Array.isArray(body.logs)&&Array.isArray(body.registryLogs),'INVALID_CHECKPOINT');
    const trusted=!!marked&&marked.identity===identity&&marked.digest===digest&&marked.blockNumber===body.blockNumber
      &&marked.blockHash===body.blockHash&&marked.abiFingerprint===abiFingerprint;
    return {body,previous:qty(body.blockNumber),trusted};
  }catch(error){if(strict)throw error;return null;}
}
function recoveryKey(identity,abiFingerprint){return `${identity}:${abiFingerprint}`;}
function saveRecovery(key,bucket){
  const previous=retainedCheckpoints.get(key);if(previous)retainedBytes-=previous.bytes;
  retainedCheckpoints.delete(key);
  bucket.bytes=Array.from(new Set([bucket.latest,bucket.recent,bucket.pending,bucket.safe].filter(Boolean)))
    .reduce((sum,checkpoint)=>sum+(verifiedReceiptCheckpoints.get(checkpoint)?.bytes??RECOVERY_PROFILE_BYTES+1),0);
  if(bucket.bytes<=RECOVERY_PROFILE_BYTES){retainedCheckpoints.set(key,bucket);retainedBytes+=bucket.bytes;}
  while(retainedCheckpoints.size>RECOVERY_PROFILES||retainedBytes>RECOVERY_TOTAL_BYTES){
    const oldest=retainedCheckpoints.keys().next().value;
    retainedBytes-=retainedCheckpoints.get(oldest).bytes;retainedCheckpoints.delete(oldest);
  }
}
async function observedSafety(client,chainKey){
  // The shared API/Ponder wrappers inherit the same getBlock function. Only
  // optional safety-tag hints are shared for 30 seconds; numbered canonical
  // anchor/final reads are always fresh and never use this cache.
  if(typeof client.getBlock!=='function')return null;
  let sources=safetyProbes.get(client.getBlock);
  if(!sources){sources=new Map();safetyProbes.set(client.getBlock,sources);}
  const cached=sources.get(chainKey),now=Date.now();
  if(cached&&(!cached.settled||now-cached.started<SAFETY_PROBE_MS))return cached.promise;
  const probe={started:now,settled:false,promise:null};
  const promise=(async()=>{
    for(const blockTag of ['safe','finalized'])try{
      const block=await client.getBlock({blockTag});
      if(block&&hash(block.hash)&&typeof block.number==='bigint'&&block.number>=0n)return {number:block.number,hash:block.hash};
    }catch{/* Unsupported tags or an outage must not stop normal synchronization. */}
    return null;
  })().finally(()=>{probe.settled=true;});
  probe.promise=promise;sources.set(chainKey,probe);
  while(sources.size>4)sources.delete(sources.keys().next().value);
  return promise;
}
function retainCheckpoint({client,identity,abiFingerprint,checkpoint,head,chainId,genesisHash}){
  const key=recoveryKey(identity,abiFingerprint),old=retainedCheckpoints.get(key);
  const bucket=old?{...old}:{latest:null,recent:null,pending:null,safe:null,bytes:0};
  if(bucket.latest&&head>qty(bucket.latest.blockNumber)
    &&(!bucket.recent||head-qty(bucket.recent.blockNumber)>=RECOVERY_SPACING))bucket.recent=bucket.latest;
  bucket.latest=checkpoint;
  if(!bucket.pending&&(!bucket.safe||head>qty(bucket.safe.blockNumber)))bucket.pending=checkpoint;
  saveRecovery(key,bucket);
  const pending=bucket.pending;
  if(!retainedCheckpoints.has(key)||!pending||qty(pending.blockNumber)>=head)return;
  // This optional, shared background observation never delays a state response.
  // Promotion re-reads the numbered header; recovery repeats that read again.
  void (async()=>{
    const safety=await observedSafety(client,`${chainId}:${genesisHash}`);
    const snapshot=checkpointCopy(pending,identity,abiFingerprint);
    if(!safety||!snapshot?.trusted||snapshot.previous>safety.number||safety.number>head)return;
    const canonical=(await readPinnedBlock(client,snapshot.previous)).hash===snapshot.body.blockHash;
    const current=retainedCheckpoints.get(key);
    if(!current||current.pending!==pending)return;
    if(!canonical){saveRecovery(key,{...current,pending:current.latest!==pending?current.latest:null});return;}
    const next={...current,safe:pending,pending:null};
    if(current.latest&&qty(current.latest.blockNumber)>snapshot.previous)next.pending=current.latest;
    saveRecovery(key,next);
  })().catch(()=>{});
}

// Poseidon trees are pure functions of their ordered leaves. A process keeps
// the most recent ones so every readiness poll, association-set check and
// snapshot does not rebuild the same tree again; the key is the exact content.
const TREE_CACHE = new Map(), TREE_CACHE_SIZE = 64;
export function phase2Tree(leaves, depth = 20) {
  check(depth === 20 && Array.isArray(leaves) && leaves.length <= 2 ** depth, 'INVALID_TREE');
  const key = leaves.length + ':' + createHash('sha256').update(leaves.map(String).join(',')).digest('hex');
  const cached = TREE_CACHE.get(key);
  if (cached) { TREE_CACHE.delete(key); TREE_CACHE.set(key, cached); return cached; }
  const tree = buildPhase2Tree(leaves, depth);
  TREE_CACHE.set(key, tree);
  while (TREE_CACHE.size > TREE_CACHE_SIZE) TREE_CACHE.delete(TREE_CACHE.keys().next().value);
  return tree;
}
function buildPhase2Tree(leaves, depth) {
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(poseidon([zeros[i], zeros[i]]));
  const levels = [leaves.map(value => { const n = qty(value); check(n > 0n && n < FIELD, 'INVALID_COMMITMENT'); return n; })];
  for (let i = 0; i < depth; i++) {
    const layer = levels[i], parents = [];
    for (let j = 0; j < layer.length; j += 2) parents.push(poseidon([layer[j], layer[j + 1] ?? zeros[i]]));
    levels.push(parents);
  }
  return { root: levels[depth][0] ?? zeros[depth], zeros, proof(index) {
    check(Number.isSafeInteger(index) && index >= 0 && index < leaves.length, 'INVALID_LEAF_INDEX');
    let cursor = index; const siblings = [], pathIndices = [];
    for (let i = 0; i < depth; i++) { siblings.push(levels[i][cursor ^ 1] ?? zeros[i]); pathIndices.push(cursor & 1); cursor = Math.floor(cursor / 2); }
    return { siblings, pathIndices };
  } };
}

export function phase2Identity(profile) {
  const p=normalizeProfile(profile);
  check(hash(profile.genesisHash) && [profile.pool,profile.verifier,profile.exitVerifier,profile.registry].every(pin=>hash(pin?.runtimeCodeHash)), 'PINNED_ASP_DEPLOYMENT_REQUIRED');
  check(profile.registry.provider.toLowerCase()===p.provider,'ASP_PROVIDER_MISMATCH');
  return sha(wire({chain:p.chainId,noteModel:NOTE_MODEL,genesis:profile.genesisHash,pool:profile.pool,verifier:profile.verifier,exitVerifier:profile.exitVerifier,registry:profile.registry,artifactSHA256:profile.artifactSHA256}));
}
function sortedLogs(logs) {
  return logs.sort((a,b)=>Number(BigInt(a.blockNumber)-BigInt(b.blockNumber))||Number(BigInt(a.transactionIndex)-BigInt(b.transactionIndex))||Number(BigInt(a.logIndex)-BigInt(b.logIndex)));
}
function logIdentity(log,address,start,head) {
  check(log.address.toLowerCase()===address.toLowerCase() && log.removed!==true && qty(log.blockNumber)<=head && qty(log.blockNumber)>=start,'INVALID_LOG');
  check(hash(log.blockHash)&&hash(log.transactionHash)&&/^(0|[1-9][0-9]*)$/.test(String(log.logIndex))&&/^(0|[1-9][0-9]*)$/.test(String(log.transactionIndex)),'INVALID_LOG_IDENTITY');
}
function metadata(log) {return {transactionHash:log.transactionHash,blockNumber:String(log.blockNumber),blockHash:log.blockHash};}
function addGroup(groups,log,event) {
  let group=groups.get(log.transactionHash);
  if(!group){group={logs:[],events:[],meta:metadata(log)};groups.set(log.transactionHash,group);}
  check(group.meta.blockHash===log.blockHash&&group.meta.blockNumber===String(log.blockNumber),'INCONSISTENT_TRANSACTION_LOGS');
  group.logs.push(log);group.events.push(event);
}
async function verifyReceipts(client,streams,verifiedThrough=null) {
  // A canonical, same-object in-process checkpoint may authenticate its exact
  // immutable history prefix. Every group outside it still gets the independent
  // RPC receipt/completeness checks; cold/reorg/unmarked reads verify all groups.
  const jobs=streams.flatMap(([address,groups])=>Array.from(groups,([transactionHash,group])=>({address,transactionHash,group})))
    .filter(({group})=>verifiedThrough===null||qty(group.meta.blockNumber)>verifiedThrough);
  const receipts=new Map();let cursor=0;
  // Sixteen receipts in flight per pool: a cold or unmarked read verifies every historical
  // receipt, and at one round trip each this bounds a restart to minutes, not an hour.
  await Promise.all(Array.from({length:Math.min(16,jobs.length)},async()=>{
    for(;;){
      const job=jobs[cursor++];if(!job)return;
      const {address,transactionHash,group}=job;
      if(!receipts.has(transactionHash))receipts.set(transactionHash,client.getTransactionReceipt({hash:transactionHash}));
      const receipt=await receipts.get(transactionHash);
      check(receipt.status==='success'&&receipt.transactionHash===transactionHash&&receipt.blockHash===group.meta.blockHash&&String(receipt.blockNumber)===group.meta.blockNumber,'NONCANONICAL_RECEIPT');
      const logs=receipt.logs.filter(log=>log.address.toLowerCase()===address.toLowerCase());
      check(logs.length===group.logs.length&&logs.every((log,i)=>String(log.logIndex)===String(group.logs[i].logIndex)&&log.data.toLowerCase()===group.logs[i].data.toLowerCase()&&JSON.stringify(log.topics.map(t=>t.toLowerCase()))===JSON.stringify(group.logs[i].topics.map(t=>t.toLowerCase()))),'INCOMPLETE_TRANSACTION_LOGS');
    }
  }));
}
function validatePoolSequences(groups,deposits) {
  for(const group of groups.values()) {
    // Keep management logs in receipt verification, while allowing a guardian
    // contract to emit them during an otherwise valid pool transaction.
    const events=group.events.filter(event=>!CAP_EVENTS.has(event.eventName));
    let cursor=0;
    while(cursor<events.length) {
      const first=events[cursor];
      if(first.eventName==='NewCommitment') {
        const dynamic=events[cursor+1];
        check(dynamic?.eventName==='DynamicDeposited'&&first.args.commitment===dynamic.args.commitment&&first.args.encryptedOutput===dynamic.args.encryptedTemplate,'INCOMPLETE_DYNAMIC_DEPOSIT_EVENTS');cursor+=2;
      } else {
        check(first.eventName==='NewNullifier','INCOMPLETE_TRANSACTION_EVENTS');
        const second=events[cursor+1];
        if(second?.eventName==='HolderExited') {
          check(first.args.nullifier===second.args.nullifier,'HOLDER_EXIT_NULLIFIER_MISMATCH');cursor+=2;
          if(events[cursor]?.eventName==='Ragequit') {
            const a=events[cursor++].args,b=second.args,deposit=deposits.find(d=>d.commitment===String(a.commitment));
            check(a.commitment===b.commitment&&a.nullifier===b.nullifier&&a.value===b.value&&deposit&&deposit.originalDepositor.toLowerCase()===a.depositor.toLowerCase()&&b.recipient.toLowerCase()===a.depositor.toLowerCase()&&b.fee===0n,'INVALID_RAGEQUIT_EVENTS');
          }
        } else {
          check(second?.eventName==='NewNullifier','INCOMPLETE_TRANSACTION_EVENTS');cursor+=2;
          let inserted=0;while(events[cursor]?.eventName==='NewCommitment'){cursor++;inserted++;}
          const transaction=events[cursor++],flow=events[cursor++];
          check(inserted<=2&&transaction?.eventName==='Transacted'&&flow?.eventName==='PublicFlow','INCOMPLETE_TRANSACTION_EVENTS');
          const a=transaction.args,b=flow.args;
          check(a.processor.toLowerCase()===b.processor.toLowerCase()&&a.publicIn===b.publicIn&&a.publicOut===b.publicOut&&a.fee===b.fee,'PUBLIC_FLOW_MISMATCH');
        }
      }
    }
  }
}

/** Public pool and ASP logs, with an optional independently supplied public set. */
export async function syncPhase2State({client,profile,artifacts,checkpoint=null,associationSet,associationSetLoader}) {
  // Freeze the inputs actually used by this asynchronous read. In particular,
  // a caller must not mutate a previously marked log/ABI after its digest was
  // checked but while the canonical-header RPC is awaiting a response.
  profile=structuredClone(profile);
  const identity=phase2Identity(profile),p=normalizeProfile(profile),pool=p.pool,registry=p.registry;
  const poolABI=structuredClone(artifacts?.Phase2ASPPool?.abi),artifactRegistryABI=structuredClone(artifacts?.Phase2ASPRegistry?.abi);
  check(Array.isArray(poolABI)&&poolABI.some(a=>a.type==='event'&&a.name==='HolderExited')&&Array.isArray(artifactRegistryABI),'ASP_ARTIFACT_ABI_REQUIRED');
  const cappedPool=hasDepositCaps(poolABI),caps={current:null,pending:emptyCapProposal(),paused:false};
  const registryABI=withGovernance(artifactRegistryABI);
  const abiFingerprint=sha({poolABI,artifactRegistryABI,governanceABI:GOVERNANCE_ABI});
  const [chainId,genesis,head]=await Promise.all([client.getChainId(),readPinnedBlock(client,0n),client.getBlockNumber()]);
  check(chainId===p.chainId,'CHAIN_ID_MISMATCH');check(genesis.hash===profile.genesisHash,'GENESIS_MISMATCH');
  const block=await readPinnedBlock(client,head),timestamp=qty(block.timestamp);
  await Promise.all([profile.pool,profile.verifier,profile.exitVerifier,profile.registry].map(async pin=>{
    const code=await client.getCode({address:pin.address,blockNumber:head});
    check(code&&code!=='0x'&&keccak256(code)===pin.runtimeCodeHash,'RUNTIME_CODE_MISMATCH');
  }));
  const poolStart=qty(profile.pool.startBlock),registryStart=qty(profile.registry.startBlock);
  let poolFrom=poolStart,registryFrom=registryStart,logs=[],registryLogs=[],resumed=false,verifiedThrough=null;
  if(checkpoint) {
    let candidate=checkpointCopy(checkpoint,identity,abiFingerprint,true);
    if(candidate.previous>head||(await readPinnedBlock(client,candidate.previous)).hash!==candidate.body.blockHash){
      // Only a genuine, unchanged in-process input may borrow another local
      // checkpoint. Disk/cloned/ABI-changed inputs cannot inherit this evidence.
      const bucket=candidate.trusted?retainedCheckpoints.get(recoveryKey(identity,abiFingerprint)):null;
      candidate=null;
      const points=bucket?Array.from(new Set([bucket.latest,bucket.recent,bucket.pending,bucket.safe].filter(point=>point&&point!==checkpoint)))
        .map(point=>checkpointCopy(point,identity,abiFingerprint)).filter(saved=>saved?.trusted&&saved.previous<=head):[];
      for(const saved of points.sort((a,b)=>Number(b.previous-a.previous))){
        if((await readPinnedBlock(client,saved.previous)).hash===saved.body.blockHash){candidate=saved;break;}
      }
    }
    if(candidate){
      const {body,previous,trusted}=candidate;
      // Fetch/sort into fresh arrays. A failed attempt must not append to the
      // last committed checkpoint and invalidate its digest for the retry.
      logs=body.logs;registryLogs=body.registryLogs;poolFrom=previous+1n;registryFrom=previous+1n;resumed=true;
      if(trusted)verifiedThrough=previous;
    }
  }
  async function fetch(address,from,target) {
    for(let cursor=from;cursor<=head;cursor+=2000n){
      const toBlock=cursor+1999n<head?cursor+1999n:head,received=wire(await client.getLogs({address,fromBlock:cursor,toBlock}));
      // A provider must not inject an unverified historical group below the
      // anchor by returning logs outside the explicitly requested delta range.
      check(Array.isArray(received)&&received.every(log=>qty(log.blockNumber)>=cursor&&qty(log.blockNumber)<=toBlock),'RPC_LOG_RANGE_MISMATCH');
      target.push(...received);
    }
  }
  await Promise.all([fetch(pool,poolFrom,logs),fetch(registry,registryFrom,registryLogs)]);
  sortedLogs(logs);sortedLogs(registryLogs);
  const positions=new Set(),commitments=[],receipts=[],nullifiers=[],nullifierBlocks=[],deposits=[],exits=[],flows=[],seen=new Set(),nfs=new Set(),groups=new Map(),policyGroups=new Map();
  let reserve=0n;
  for(const log of logs) {
    logIdentity(log,pool,poolStart,head);const key=`${log.blockNumber}:${log.logIndex}`;check(!positions.has(key),'DUPLICATE_LOG');positions.add(key);
    let event;try{event=decodeCached(abiFingerprint+':pool',poolABI,log);}catch{throw new Error('UNKNOWN_POOL_LOG');}
    addGroup(groups,log,event);
    const a=event.args,meta=metadata(log);
    if(CAP_EVENTS.has(event.eventName)) {
      check(cappedPool,'POOL_CAPS_ARTIFACT_ABI_OUTDATED');
      if(event.eventName==='CapsUpdated') {
        caps.current=capPair(a.maxDeposit,a.maxTotal);caps.pending=emptyCapProposal();
      } else if(event.eventName==='CapIncreaseProposed') {
        const proposed=capPair(a.maxDeposit,a.maxTotal),eta=capQuantity(a.eta,64);
        check(caps.current&&eta>0n&&proposed.maxDeposit>=caps.current.maxDeposit&&proposed.maxTotal>=caps.current.maxTotal
          &&(proposed.maxDeposit>caps.current.maxDeposit||proposed.maxTotal>caps.current.maxTotal),'INVALID_POOL_CAPS_EVENT');
        caps.pending={...proposed,eta};
      } else if(event.eventName==='CapIncreaseCancelled') {
        check(caps.pending.eta>0n,'INVALID_POOL_CAPS_EVENT');caps.pending=emptyCapProposal();
      } else {
        check(typeof a.paused==='boolean','INVALID_POOL_CAPS_EVENT');caps.paused=a.paused;
      }
    } else if(event.eventName==='NewCommitment') {
      const c=String(a.commitment),index=Number(a.index);
      check(index===commitments.length&&!seen.has(c)&&BigInt(c)>0n&&BigInt(c)<FIELD&&/^0x[0-9a-f]{512}$/i.test(a.encryptedOutput),'INVALID_COMMITMENT_EVENT');
      seen.add(c);commitments.push(c);receipts.push({commitment:c,index,encryptedOutput:a.encryptedOutput,...meta});
    } else if(event.eventName==='NewNullifier') {
      const nf=String(a.nullifier);check(!nfs.has(nf)&&BigInt(nf)>0n&&BigInt(nf)<FIELD,'DUPLICATE_NULLIFIER');nfs.add(nf);nullifiers.push(nf);nullifierBlocks.push(meta.blockNumber);
    } else if(event.eventName==='DynamicDeposited') {
      const value=BigInt(a.value),precommitment=BigInt(a.precommitment),commitment=BigInt(a.commitment),output=receipts.at(-1);
      check(value>0n&&value<(1n<<128n)&&precommitment>0n&&precommitment<FIELD&&poseidon([value,precommitment])===commitment,'INVALID_DYNAMIC_DEPOSIT');
      check(output&&output.commitment===String(commitment)&&output.transactionHash===log.transactionHash&&output.encryptedOutput===a.encryptedTemplate,'DYNAMIC_DEPOSIT_RECEIPT_MISMATCH');
      Object.assign(output,{kind:'dynamic',value:String(value),precommitment:String(precommitment),encryptedTemplate:a.encryptedTemplate,originalDepositor:a.processor.toLowerCase()});
      const deposit={commitment:String(commitment),value:String(value),precommitment:String(precommitment),originalDepositor:a.processor.toLowerCase(),...meta};deposits.push(deposit);
      reserve+=value;flows.push({kind:'dynamic',processor:a.processor,publicIn:String(value),publicOut:'0',fee:'0',...meta});
    } else if(event.eventName==='PublicFlow') {
      check(a.publicIn===0n,'NORMAL_PUBLIC_FUNDING_FORBIDDEN');reserve-=BigInt(a.publicOut);check(reserve>=0n,'NEGATIVE_RESERVE');flows.push({...wire(a),kind:'normal',...meta});
    } else if(event.eventName==='HolderExited') {
      const value=BigInt(a.value),fee=BigInt(a.fee);
      check(value>0n&&value<(1n<<128n)&&fee>=0n&&fee<=value&&seen.has(String(a.commitment))&&nfs.has(String(a.nullifier)),'INVALID_HOLDER_EXIT_EVENT');
      reserve-=value;check(reserve>=0n,'NEGATIVE_RESERVE');exits.push({...wire(a),kind:'holder-exit',...meta});flows.push({kind:'holder-exit',processor:a.processor,recipient:a.recipient,publicIn:'0',publicOut:String(value),fee:String(fee),...meta});
    } else if(event.eventName==='Ragequit') {
      const exit=exits.at(-1);check(exit&&exit.commitment===String(a.commitment)&&exit.transactionHash===log.transactionHash,'INVALID_RAGEQUIT_EVENTS');exit.kind='ragequit';
    } else check(event.eventName==='Transacted','UNEXPECTED_POOL_EVENT');
  }
  validatePoolSequences(groups,deposits);
  let latest={root:'0',epoch:'0',validUntil:'0',cidDigest:'0x'+'00'.repeat(32)};
  const policies=[];
  // Provider governance replayed from logs, then cross-checked against storage.
  const gov={provider:null,pending:null,suspended:false,revokedThroughEpoch:0n,rotated:false,events:0};
  const adopt=address=>{const a=address.toLowerCase();if(gov.provider===null)gov.provider=a;check(gov.provider===a,'INVALID_PROVIDER_EVENT');};
  for(const log of registryLogs) {
    logIdentity(log,registry,registryStart,head);const key=`${log.blockNumber}:${log.logIndex}`;check(!positions.has(key),'DUPLICATE_LOG');positions.add(key);
    let event;try{event=decodeCached(abiFingerprint+':registry',registryABI,log);}catch{throw new Error('UNKNOWN_REGISTRY_LOG');}
    addGroup(policyGroups,log,event);const a=event.args;
    if(event.eventName==='PolicyUpdated') {
      const root=qty(a.root),epoch=qty(a.epoch),validUntil=qty(a.validUntil);
      check(!gov.suspended&&root>0n&&root<FIELD&&epoch===BigInt(latest.epoch)+1n&&epoch<(1n<<64n)&&validUntil>0n&&validUntil<(1n<<64n)&&hash(a.cidDigest)&&!/^0x0{64}$/i.test(a.cidDigest),'INVALID_ASP_POLICY_EVENT');
      latest={root:String(root),epoch:String(epoch),validUntil:String(validUntil),cidDigest:a.cidDigest.toLowerCase()};policies.push({...latest,...metadata(log)});
      continue;
    }
    gov.events++;
    if(event.eventName==='ProviderRotationProposed') {
      adopt(a.currentProvider);const next=a.nextProvider.toLowerCase();check(next!==ZERO&&next!==gov.provider,'INVALID_PROVIDER_EVENT');gov.pending=next;
    } else if(event.eventName==='ProviderRotationCancelled') {
      check(gov.pending!==null&&gov.pending===a.nextProvider.toLowerCase(),'INVALID_PROVIDER_EVENT');gov.pending=null;
    } else if(event.eventName==='ProviderRotated') {
      adopt(a.previousProvider);const next=a.nextProvider.toLowerCase();check(gov.pending===next,'INVALID_PROVIDER_EVENT');
      Object.assign(gov,{provider:next,pending:null,suspended:false,rotated:true});
    } else if(event.eventName==='ProviderSuspended') {
      adopt(a.provider);const revoked=qty(a.revokedThroughEpoch);check(revoked===BigInt(latest.epoch),'INVALID_PROVIDER_EVENT');
      Object.assign(gov,{suspended:true,revokedThroughEpoch:revoked});
    } else if(event.eventName==='ProviderResumed') {
      adopt(a.provider);gov.suspended=false;
    } else check(false,'UNEXPECTED_REGISTRY_EVENT');
  }
  const tree=phase2Tree(commitments),read=functionName=>client.readContract({address:pool,abi:poolABI,functionName,blockNumber:head});
  const readRegistry=(functionName,args)=>client.readContract({address:registry,abi:registryABI,functionName,args,blockNumber:head});
  const [,poolValues,registryValues,actualBalance,capValues]=await Promise.all([
    verifyReceipts(client,[[pool,groups],[registry,policyGroups]],verifiedThrough),
    Promise.all(['currentRoot','nextLeafIndex','SCOPE','VERIFIER','HOLDER_EXIT_VERIFIER','ASSET','ASP_REGISTRY'].map(read)),
    Promise.all(['PROVIDER','latestPolicy','cidDigest'].map(name=>readRegistry(name))),
    p.asset===ZERO?client.getBalance({address:pool,blockNumber:head}):client.readContract({address:p.asset,abi:balanceABI,functionName:'balanceOf',args:[pool],blockNumber:head}),
    cappedPool?Promise.all(CAP_GETTERS.map(([name])=>read(name))):null,
  ]);
  const [root,index,scope,verifier,exitVerifier,asset,aspRegistry]=poolValues;
  check(root===tree.root&&BigInt(index)===BigInt(commitments.length),'INCOMPLETE_OR_INCONSISTENT_LOGS');
  check(String(scope)===String(p.scope)&&verifier.toLowerCase()===profile.verifier.address.toLowerCase()&&exitVerifier.toLowerCase()===profile.exitVerifier.address.toLowerCase()&&asset.toLowerCase()===p.asset&&aspRegistry.toLowerCase()===registry,'POOL_IDENTITY_MISMATCH');
  let depositCaps=null;
  if(cappedPool) {
    const [deposit,total,accounted,proposal,paused,delay]=capValues,current=capPair(deposit,total);
    const accountedBalance=capQuantity(accounted,256),capIncreaseDelaySeconds=capQuantity(delay,64);
    check(Array.isArray(proposal)&&proposal.length===3&&typeof paused==='boolean'&&capIncreaseDelaySeconds>0n,'INVALID_POOL_CAPS');
    const eta=capQuantity(proposal[2],64),pending=eta===0n?emptyCapProposal():{...capPair(proposal[0],proposal[1]),eta};
    if(eta===0n)check(capQuantity(proposal[0])===0n&&capQuantity(proposal[1])===0n,'INVALID_POOL_CAPS');
    else check(pending.maxDeposit>=current.maxDeposit&&pending.maxTotal>=current.maxTotal
      &&(pending.maxDeposit>current.maxDeposit||pending.maxTotal>current.maxTotal),'INVALID_POOL_CAPS');
    check(accountedBalance===reserve,'POOL_ACCOUNTED_BALANCE_MISMATCH');
    check(caps.current&&current.maxDeposit===caps.current.maxDeposit&&current.maxTotal===caps.current.maxTotal
      &&paused===caps.paused&&pending.maxDeposit===caps.pending.maxDeposit&&pending.maxTotal===caps.pending.maxTotal
      &&pending.eta===caps.pending.eta,'POOL_CAPS_STATE_MISMATCH');
    depositCaps=wire({...current,accountedBalance,pendingCaps:pending,depositsPaused:paused,capIncreaseDelaySeconds});
  }
  const [provider,onchainPolicy,cidDigest]=registryValues;
  // The pinned provider may only differ after a rotation observed in canonical logs.
  const liveProvider=provider.toLowerCase(),providerCurrent=liveProvider===p.provider;
  check((gov.provider===null||gov.provider===liveProvider)&&(providerCurrent||gov.rotated),'ASP_POLICY_IDENTITY_MISMATCH');
  check(Array.isArray(onchainPolicy)&&onchainPolicy.length===3&&String(onchainPolicy[0])===latest.root&&String(onchainPolicy[1])===latest.epoch&&String(onchainPolicy[2])===latest.validUntil&&cidDigest.toLowerCase()===latest.cidDigest,'ASP_POLICY_IDENTITY_MISMATCH');
  // Policies a pool accepts at this block, read from the registry itself (audit M2):
  // the latest plus recently superseded epochs in their grace period, minus revoked ones.
  // The registry generation comes only from the artifact ABI, which must match the
  // deployment; a legacy ABI never triggers the new getters. Governance events under a
  // legacy ABI prove a mismatch. A guardian registry with a legacy ABI and no events
  // yet is handled as legacy: latest epoch only, which is stricter, never looser.
  const guardianRegistry=artifactRegistryABI.some(item=>item.type==='function'&&item.name==='ACCEPTED_POLICY_WINDOW');
  check(guardianRegistry||gov.events===0,'ASP_ARTIFACT_ABI_OUTDATED');
  let acceptedPolicies=[],suspended=false,revokedThroughEpoch=0n;
  if(guardianRegistry) {
    const [window,grace,liveSuspended,liveRevoked]=await Promise.all(['ACCEPTED_POLICY_WINDOW','SUPERSEDED_POLICY_GRACE','providerSuspended','revokedThroughEpoch'].map(name=>readRegistry(name)));
    suspended=liveSuspended;revokedThroughEpoch=qty(liveRevoked);
    check(suspended===gov.suspended&&revokedThroughEpoch===gov.revokedThroughEpoch,'ASP_GOVERNANCE_STATE_MISMATCH');
    // Every epoch in the window is read at the same pinned block; the reads are
    // independent, so they are issued together instead of one epoch at a time.
    const epochs=[];for(let epoch=BigInt(latest.epoch);epoch>0n&&BigInt(latest.epoch)-epoch<qty(window);epoch--)epochs.push(epoch);
    const stored=await Promise.all(epochs.map(epoch=>Promise.all([readRegistry('acceptedPolicy',[epoch]),readRegistry('policyAt',[epoch])])));
    epochs.forEach((epoch,i)=>{
      const [[root,validUntil],[storedRoot,storedUntil,supersededAt]]=stored[i],logged=policies[Number(epoch)-1];
      check(String(storedRoot)===logged.root&&String(storedUntil)===logged.validUntil,'ASP_POLICY_IDENTITY_MISMATCH');
      if(qty(root)===0n)return;
      check(String(root)===logged.root&&String(validUntil)===logged.validUntil,'ASP_POLICY_IDENTITY_MISMATCH');
      const graceEnd=qty(supersededAt)===0n?qty(validUntil):qty(supersededAt)+qty(grace);
      acceptedPolicies.push({root:logged.root,epoch:String(epoch),validUntil:logged.validUntil,cidDigest:logged.cidDigest,
        acceptedUntil:String(graceEnd<qty(validUntil)?graceEnd:qty(validUntil))});
    });
  } else if(BigInt(latest.epoch)>0n&&BigInt(latest.validUntil)>timestamp) {
    acceptedPolicies.push({root:latest.root,epoch:latest.epoch,validUntil:latest.validUntil,cidDigest:latest.cidDigest,acceptedUntil:latest.validUntil});
  }
  // Contexts bind the pinned provider, so after a rotation no spend can match.
  if(!providerCurrent)acceptedPolicies=[];
  const asp={...latest,provider:liveProvider,leaves:null,expired:BigInt(latest.epoch)===0n||BigInt(latest.validUntil)<=timestamp,
    providerRotated:!providerCurrent,suspended,revokedThroughEpoch:String(revokedThroughEpoch),acceptedPolicies,
    spendable:acceptedPolicies.some(policy=>policy.epoch===latest.epoch)};
  let providedSet=associationSet;
  if(providedSet===undefined&&associationSetLoader){check(typeof associationSetLoader==='function','INVALID_ASSOCIATION_SET_LOADER');providedSet=await associationSetLoader({...asp,blockNumber:String(head),blockHash:block.hash,blockTimestamp:String(timestamp)});}
  if(providedSet!==undefined&&providedSet!==null) {
    check(providedSet&&Array.isArray(providedSet.leaves),'INVALID_ASSOCIATION_SET');
    const leaves=providedSet.leaves.map(value=>String(qty(value)));
    let selected=latest;
    if(providedSet.policy!==undefined){
      const requested=providedSet.policy;
      selected=acceptedPolicies.find(policy=>policy.epoch===requested?.epoch&&policy.root===requested?.root
        &&policy.validUntil===requested?.validUntil&&policy.cidDigest===requested?.cidDigest);
      check(selected&&providerCurrent&&!suspended&&BigInt(selected.epoch)>revokedThroughEpoch
        &&BigInt(selected.validUntil)>timestamp&&BigInt(selected.acceptedUntil)>timestamp,'ASSOCIATION_SET_POLICY_NOT_ACCEPTED');
    }
    check(associationSetDigest(leaves).toLowerCase()===selected.cidDigest&&String(phase2Tree(leaves).root)===selected.root,'ASSOCIATION_SET_POLICY_MISMATCH');
    if(selected.epoch!==latest.epoch){
      asp.latestPolicy={...latest};
      Object.assign(asp,{root:selected.root,epoch:selected.epoch,validUntil:selected.validUntil,cidDigest:selected.cidDigest,
        acceptedUntil:selected.acceptedUntil,expired:false,spendable:true,selection:'accepted-previous'});
    }
    asp.leaves=leaves;
  }
  check(actualBalance>=reserve,'POOL_UNDERFUNDED');
  const [finalBlock,finalChainId]=await Promise.all([readPinnedBlock(client,head),client.getChainId()]);
  check(finalBlock.hash===block.hash&&finalChainId===p.chainId,'SNAPSHOT_REORGANIZED');
  const body={schema:'phase2-asp-public-checkpoint/v1',identity,blockNumber:String(head),blockHash:block.hash,logs,registryLogs};
  const nextCheckpoint={...body,digest:sha(body)};
  const result={schema:'phase2-asp-public-state/v1',noteModel:NOTE_MODEL,chainId:p.chainId,pool,scope:String(p.scope),...profileReleaseFlags(profile),identity,
    blockNumber:String(head),blockHash:block.hash,blockTimestamp:String(timestamp),root:String(tree.root),commitments,receipts,nullifiers,nullifierBlocks,deposits,exits,flows,policies,asp,
    reserve:String(reserve),actualBalance:String(actualBalance),depositCaps,resumed,checkpoint:nextCheckpoint,
    trustAssumptions:['Pinned RPC supplies complete canonical logs; no independent storage proof.','Association-set root and ABI digest match the pinned registry; provider policy remains a trust assumption.','Checkpoints are trusted local files, not HTTP imports.']};
  // Mark only after receipt checks, full log/state/Merkle replay, all current
  // storage/code/balance/policy reads and the final canonical-head recheck pass.
  verifiedReceiptCheckpoints.set(nextCheckpoint,Object.freeze({identity,digest:nextCheckpoint.digest,
    blockNumber:nextCheckpoint.blockNumber,blockHash:nextCheckpoint.blockHash,abiFingerprint,bytes:Buffer.byteLength(JSON.stringify(nextCheckpoint))}));
  try{retainCheckpoint({client,identity,abiFingerprint,checkpoint:nextCheckpoint,head,chainId:p.chainId,genesisHash:profile.genesisHash});}
  catch{/* Optional recovery retention can never reject a fully verified state. */}
  return result;
}
// The on-disk state is a restart cache of public chain data (re-verified on
// load), so it need not be rewritten on every sync: at most every 30 s, and on close.
export const INDEXER_PERSIST_INTERVAL_MS=30000;
export async function createPhase2Indexer({client,profile,artifacts,directory,associationSet,associationSetLoader,now=Date.now,persistIntervalMs=INDEXER_PERSIST_INTERVAL_MS}) {
  const store=await openServiceStore({directory,identity:phase2Identity(profile),filename:'state.json'});
  let current=await store.read(),inFlight=null,closed=false,closePromise=null,completedAt=null,version=0,persistedAt=null,persisted=current;
  // Each returned clone remembers which completed sync it came from, so a
  // caller can reuse work (serialisation, validators) per snapshot without the
  // snapshot itself carrying an extra wire field.
  const issued=new WeakMap(),issue=(value,at)=>{issued.set(value,at);return value;};
  return {async sync({maxAgeMs=0}={}){
    check(!closed,'INDEXER_CLOSED');
    check(Number.isSafeInteger(maxAgeMs)&&maxAgeMs>=0&&maxAgeMs<=30000,'INVALID_SNAPSHOT_AGE');
    // Overlapping state/readiness polls share one fresh, verified snapshot.
    // The next completed sync always reads a new head: no stale TTL cache,
    // except that a caller may explicitly accept a snapshot completed in this
    // process within the last maxAgeMs (readiness and configuration polls).
    if(maxAgeMs>0&&current&&completedAt!==null&&now()-completedAt<=maxAgeMs)return issue(structuredClone(current),version);
    if(!inFlight){
      const run=Promise.resolve().then(async()=>{
        const next=await syncPhase2State({client,profile,artifacts,checkpoint:current?.checkpoint,associationSet,associationSetLoader});
        if(persistedAt===null||now()-persistedAt>=persistIntervalMs){await store.write(next);persistedAt=now();persisted=next;}
        current=next;completedAt=now();version++;return {next,at:version};
      });
      inFlight=run;
      run.then(()=>{if(inFlight===run)inFlight=null;},()=>{if(inFlight===run)inFlight=null;});
    }
    const {next,at}=await inFlight;return issue(structuredClone(next),at);
  },snapshot(){return current?structuredClone(current):null;},
  /** The latest completed snapshot without cloning or syncing, for read-only
   * HTTP handlers that answer from it while a refresh runs in the background.
   * Callers must not mutate it. Null before the first sync in this process. */
  latest(){return current&&completedAt!==null?{snapshot:issue(current,version),version,completedAt}:null;},
  /** Monotonic id of the completed sync a returned snapshot came from, or null for a foreign object. */
  versionOf(snapshot){return issued.get(snapshot)??null;},close(){
    if(!closePromise){closed=true;closePromise=(async()=>{await inFlight?.catch(()=>{});
      if(current&&current!==persisted)await store.write(current).catch(()=>{});await store.close();})();}
    return closePromise;
  }};
}
export const syncPhase2ASPState=syncPhase2State;
export const createPhase2ASPIndexer=createPhase2Indexer;
