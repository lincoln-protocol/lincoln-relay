// SPDX-License-Identifier: Apache-2.0
// Production HTTP adapter. The shared signer alone owns raw transactions/nonces.
import {createHash} from 'node:crypto';
import {monitorEventLoopDelay} from 'node:perf_hooks';
import {buildStateDelta,STATE_DELTA_MAX_AGE_BLOCKS,STATE_DELTA_PATH,STATE_DELTA_SCHEMA} from './state-delta.mjs';
import {createBoundedHttpServer,normalizeHttpLimits,serviceJson,serviceJsonVersioned} from '../phase2-asp/http.mjs';
import {relayStage,relayJobRecovery,relayErrorReply,validRelayJobId} from '../phase2-asp/relay-errors.mjs';
import {DEFAULT_PUBLISHER_STATUS} from '../phase2-asp/publisher-status.mjs';
import {createASPPublicationEvents} from './asp-event-source.mjs';
import {openServiceStore} from '../phase1-service/store.mjs';
import {createNetworkPolicy} from '../phase1-service/network.mjs';
import {createPhase2Indexer,phase2Identity} from '../phase2-asp/state.mjs';
import {normalizeProfile,PRODUCTION_PROFILE_SCHEMA,profileReleaseFlags} from '../phase2-asp/sdk.mjs';
import {validateRelayRequest,validateIntentState,assertRagequitRecipient,normalizeServiceRoutes,verifyRouteLive,verifyRelayReceipt,serviceRoutesForFeePolicy} from '../phase2-asp/service.mjs';
import {FEE_ADAPTER_TYPES} from '../phase2-fees/sdk.mjs';
import {normalizeServiceFeePolicy,quoteServiceFee,validateCommercialFee,SERVICE_FEE_POLICY_V2} from '../phase2-fees/policy.mjs';
import {createQuoteGate,quotePhase2Aggregate} from '../phase2-aggregator/quotes.mjs';
import {createFeeQuoteBook} from './fee-quotes.mjs';
import {createSwapEconomicGuard} from './swap-economics.mjs';
import {TREASURY_SAFE} from './treasury-intent.mjs';
import {normalizePointsRequest,normalizePointsIssuer,findRelayFeeLog,POINTS_STATUSES} from '../phase2-points/relay.mjs';

const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
// Public reads answer from the latest verified snapshot: as is when it is at
// most SNAPSHOT_FRESH_MS old, and while at most SNAPSHOT_STALE_MS old with one
// background refresh started. Job submission always syncs a fresh snapshot.
export const SNAPSHOT_FRESH_MS=3000,SNAPSHOT_STALE_MS=30000;
// One process-wide event-loop delay monitor (all pools share the loop). The
// last completed 60 s window is reported by /readyz so CPU stalls are visible.
const loopDelay=monitorEventLoopDelay({resolution:10});loopDelay.enable();
let loopWindow=null;
const loopSample=()=>{const ms=v=>Math.round(v/1e4)/100;return {windowSeconds:60,p50:ms(loopDelay.percentile(50)),p99:ms(loopDelay.percentile(99)),max:ms(loopDelay.max)};};
setInterval(()=>{loopWindow=loopSample();loopDelay.reset();},60000).unref();
const wire=value=>JSON.parse(JSON.stringify(value,(_,v)=>typeof v==='bigint'?String(v):v));
const hash=value=>typeof value==='string'&&/^0x[0-9a-f]{64}$/i.test(value);
const publicJob=job=>Object.fromEntries(['id','kind','routeId','status','hash','nonce','blockHash','blockNumber','feeWei','feeCeilingWei','attemptHashes','rejectionReason','safeSameIdRetry','points','pointsStatus','pointsReceipt'].filter(k=>job[k]!==undefined).map(k=>[k,job[k]]));
const terminal=status=>['confirmed','reverted','cancelled'].includes(status);
// Complete v1 history remains durable and queryable. This bounded emergency
// expansion does not archive, prune or release any historical reservation.
export const MAINNET_RELAY_JOB_HISTORY_LIMIT=4096;
const exact=(value,keys)=>{need(value&&Object.getPrototypeOf(value)===Object.prototype,'INVALID_OBJECT');const own=Reflect.ownKeys(value);need(own.length===keys.length&&own.every(k=>typeof k==='string'&&keys.includes(k)&&Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value')),'UNEXPECTED_FIELDS');};
const amount=value=>{need(typeof value==='string'&&/^[1-9][0-9]{0,38}$/.test(value)&&BigInt(value)<(1n<<128n),'INVALID_QUOTE_REQUEST');return BigInt(value);};

/** v2 pins each paid swap to both the approved rate and fee treasury. The
 * legacy selector stays unchanged for existing v1 policies and testnet jobs. */
export function mainnetRoutesForFeePolicy(routes,policy){
  if(policy?.schema!==SERVICE_FEE_POLICY_V2)return serviceRoutesForFeePolicy(routes,policy);
  return routes.filter(entry=>FEE_ADAPTER_TYPES.includes(entry.route.adapterType)&&entry.route.feeBps===policy.swap.bps
    &&entry.route.treasury?.toLowerCase()===policy.swap.treasury);
}

/** No proving witnesses or private keys are accepted over this API. */
export async function createMainnetASPService({client,profile,artifacts,directory,executor=null,signingEnabled=false,routes=[],associationSetLoader,associationSet,quoteRoute,serviceFeePolicy=null,gasPricingPolicy=null,assetPriceSource=null,maxGas=5000000n,host='127.0.0.1',port=0,networkPolicy=createNetworkPolicy(),listen=true,httpOptions={},errorLogger,publisherStatusLoader,associationSetFile,reconcileIntervalMs=10000,snapshotStaleMs=SNAPSHOT_STALE_MS,pointsReceipts=null}={}){
  const httpLimits=normalizeHttpLimits(httpOptions);
  need(errorLogger===undefined||typeof errorLogger==='function','INVALID_ERROR_LOGGER');need(publisherStatusLoader===undefined||typeof publisherStatusLoader==='function','INVALID_PUBLISHER_STATUS_LOADER');
  need(assetPriceSource===null||['snapshot','status','close'].every(key=>typeof assetPriceSource[key]==='function'),'INVALID_ASSET_PRICE_SOURCE');
  need(Number.isSafeInteger(reconcileIntervalMs)&&reconcileIntervalMs>=10&&reconcileIntervalMs<=60000,'MAINNET_SERVICE_OPTIONS_INVALID');
  need(Number.isSafeInteger(snapshotStaleMs)&&snapshotStaleMs>=SNAPSHOT_FRESH_MS&&snapshotStaleMs<=60000,'MAINNET_SERVICE_OPTIONS_INVALID');
  profile=structuredClone(profile);routes=structuredClone(routes);artifacts=structuredClone(artifacts);
  const feePolicy=serviceFeePolicy===null?null:normalizeServiceFeePolicy(serviceFeePolicy);
  normalizeProfile(profile);need(profile.schema===PRODUCTION_PROFILE_SCHEMA,'MAINNET_PRODUCTION_PROFILE_REQUIRED');
  need(typeof signingEnabled==='boolean'&&typeof maxGas==='bigint'&&maxGas>0n,'MAINNET_SERVICE_OPTIONS_INVALID');
  need(!signingEnabled||executor&&executor.address?.toLowerCase()===profile.relayer?.toLowerCase()&&['prepare','broadcast','recoverHash','reconcile','status','cancelPrepared'].every(k=>typeof executor[k]==='function'),'MAINNET_EXPLICIT_SHARED_SIGNER_REQUIRED');
  const configuredRoutes=normalizeServiceRoutes(profile,routes),availableRoutes=mainnetRoutesForFeePolicy(configuredRoutes,feePolicy),identity=phase2Identity(profile),processor=profile.relayer?.toLowerCase()??null;
  const routeAdapters=new Set(configuredRoutes.map(entry=>entry.route.adapter.toLowerCase()));
  const indexer=await createPhase2Indexer({client,profile,artifacts,directory:`${directory}/indexer`,associationSetLoader,associationSet});
  const publicationEvents=createASPPublicationEvents({profile,associationSetFile,sync:()=>indexer.sync()});
  let store;try{store=await openServiceStore({directory:`${directory}/relay`,identity,filename:'jobs.json'});}catch(error){await indexer.close();throw error;}
  let state,tail=Promise.resolve(),queued=0,closed=false;
  // Relay fees go straight to the governance Safe; the relay's own address stays
  // accepted for proofs built before clients read feeRecipient from /v3/config.
  const feeRecipients=processor?[processor,TREASURY_SAFE]:[];
  const options={profile,artifacts,processor,routes,routeArtifacts:artifacts,feeRecipients};
  // Optional points receipts: after a confirmed job the relay key signs an EIP-712
  // receipt naming the user's claim address. Never part of the relayed transaction.
  let points=null;try{points=pointsReceipts===null?null:normalizePointsIssuer(pointsReceipts,{relayer:profile.relayer});}catch(error){await Promise.allSettled([indexer.close(),store.close()]);throw error;}
  try{
    state=await store.read()??{schema:'phase2-mainnet-relay-jobs/v1',identity,processor,jobs:[]};
    need(state.schema==='phase2-mainnet-relay-jobs/v1'&&state.identity===identity&&state.processor===processor&&Array.isArray(state.jobs)&&state.jobs.length<=MAINNET_RELAY_JOB_HISTORY_LIMIT,'MAINNET_RELAY_STORE_INVALID');
    const ids=new Set(),nullifiers=new Set();
    for(const job of state.jobs){
      need(job&&typeof job.id==='string'&&!ids.has(job.id)&&['prepared','pending','unknown','rejected','conflicted','confirmed','reverted','cancelled'].includes(job.status),'MAINNET_RELAY_STORE_INVALID');ids.add(job.id);
      const intent=validateRelayRequest(job.request,options);
      need(job.id===intent.id&&job.kind===intent.kind&&job.routeId===intent.routeId&&job.fingerprint===intent.fingerprint&&job.sharedId===`relay:${identity}:${job.id}`&&JSON.stringify(job.nullifiers)===JSON.stringify(intent.nullifiers),'MAINNET_RELAY_STORE_INTENT_MISMATCH');
      if(job.hash!==undefined)need(hash(job.hash),'MAINNET_RELAY_STORE_HASH_INVALID');
      if(job.points!==undefined){normalizePointsRequest(job.points);need(POINTS_STATUSES.includes(job.pointsStatus),'MAINNET_RELAY_STORE_INVALID');}
      if(job.attemptHashes!==undefined)need(Array.isArray(job.attemptHashes)&&job.attemptHashes.length<=32&&job.attemptHashes.every(hash),'MAINNET_RELAY_STORE_HASH_INVALID');
      if(!['reverted','cancelled'].includes(job.status))for(const nf of job.nullifiers){need(!nullifiers.has(nf),'MAINNET_RELAY_DUPLICATE_NULLIFIER');nullifiers.add(nf);}
    }
  }catch(error){await Promise.allSettled([indexer.close(),store.close()]);throw error;}
  let feeQuotes=null;
  try{
    need(gasPricingPolicy!==null||!state.jobs.some(job=>job.request.feeQuoteId),'FEE_QUOTE_POLICY_REQUIRED_FOR_RECOVERY');
    if(gasPricingPolicy!==null)feeQuotes=await createFeeQuoteBook({client,profile,serviceFeePolicy:feePolicy,policy:gasPricingPolicy,directory,maxGas,feeRecipients,
      ...(assetPriceSource?{assetPriceLoader:()=>assetPriceSource.snapshot()}:{}),});
  }catch(error){await Promise.allSettled([indexer.close(),store.close()]);throw error;}
  const swapEconomics=feeQuotes?createSwapEconomicGuard({feeQuotes}):null;
  let persistedIds=new Set(state.jobs.map(job=>job.id)),persistenceUncertain=false;const activeSubmissions=new Map();
  const save=()=>relayStage('persistence',async()=>{try{await store.write(state);persistedIds=new Set(state.jobs.map(job=>job.id));persistenceUncertain=false;}catch(error){persistenceUncertain=true;throw error;}});
  const recovery=id=>relayJobRecovery({id,job:state.jobs.find(job=>job.id===id),persisted:persistedIds.has(id),uncertain:persistenceUncertain,inFlight:activeSubmissions.has(id)});
  const failure=(error,request={})=>relayErrorReply(error,{service:'phase2-mainnet',chainId:4663,errorLogger,...request});
  const serial=fn=>{need(queued<16&&!closed,'MAINNET_RELAY_QUEUE_UNAVAILABLE');queued++;const run=tail.then(fn).finally(()=>queued--);tail=run.catch(()=>{});return run;};
  async function applyEntry(job,entry){
      const intent=validateRelayRequest(job.request,options);
      if(entry){
        need(entry.chainId===4663&&entry.to?.toLowerCase()===intent.to&&entry.data.toLowerCase()===intent.data&&entry.value==='0','MAINNET_RELAY_SHARED_INTENT_MISMATCH');
        need(BigInt(entry.gas)>0n&&BigInt(entry.gas)<=maxGas&&BigInt(entry.gasPrice)>0n&&BigInt(entry.feeCeilingWei)===BigInt(entry.gas)*BigInt(entry.gasPrice),'MAINNET_RELAY_SHARED_FEE_MISMATCH');
        const attempts=entry.attempts??(entry.hash?[{hash:entry.hash,status:entry.status}]:[]),knownHashes=new Set([...attempts.map(attempt=>attempt.hash),...(entry.hash?[entry.hash]:[])]);
        need([...knownHashes].every(hash)&&(!job.hash||knownHashes.has(job.hash))&&(job.attemptHashes??[]).every(value=>knownHashes.has(value)),'MAINNET_RELAY_SHARED_HASH_MISMATCH');
        if(knownHashes.size)job.attemptHashes=[...knownHashes];
        if(entry.hash)job.hash=entry.hash;
        job.nonce=entry.nonce;job.feeCeilingWei=entry.feeCeilingWei;
        job.safeSameIdRetry=entry.status==='rejected'||['prepared','signed'].includes(entry.status)&&attempts.every(attempt=>['rejected','signed'].includes(attempt.status));
        if(entry.rejectionReason)job.rejectionReason=entry.rejectionReason;else delete job.rejectionReason;
        if(entry.status==='cancelled'){need(!job.hash,'MAINNET_RELAY_CANCELLED_HASH');job.status='cancelled';return;}
        if(['rejected','conflicted'].includes(entry.status)){job.status=entry.status;return;}
        if(['prepared','signed'].includes(entry.status)){job.status='prepared';return;}
        if(entry.hash){
          const receipt=await verifyRelayReceipt({...job,to:intent.to,gas:entry.gas,gasPrice:entry.gasPrice,status:terminal(job.status)?job.status:'pending'},{client,processor});
          if(receipt){Object.assign(job,{status:receipt.status==='success'?'confirmed':'reverted',blockHash:receipt.blockHash,blockNumber:String(receipt.blockNumber),feeWei:String(receipt.gasUsed*receipt.effectiveGasPrice)});if(receipt.status==='success'&&pointsPending(job))await issuePoints(job,intent,receipt);}
          else job.status=entry.status==='unknown'?'unknown':'pending';
        }
      }else if(job.hash){
        // Without the shared fee journal there is insufficient authenticated
        // intent information to claim settlement or enable another broadcast.
        job.status='unknown';
      }
  }
  async function reconcile({full=false}={}){
    // Startup still audits retained terminal receipts. Ordinary runtime only
    // follows unsettled jobs; an idle pool makes no signer/RPC/store calls.
    const selected=state.jobs.map((job,index)=>({job,index})).filter(({job})=>full?job.status!=='cancelled':!terminal(job.status));
    if(!full&&!selected.length){if(persistenceUncertain)await save();return;}
    const ledger=executor?await(full?executor.reconcile():executor.reconcile({activeOnly:true})):null;
    const entries=new Map((ledger?.entries??[]).map(entry=>[entry.id,entry])),updates=[];
    for(const {job,index} of selected){
      // Publish a coherent snapshot to readers only after every receipt check
      // has succeeded, rather than exposing half-applied async mutations.
      const next=structuredClone(job);await applyEntry(next,entries.get(job.sharedId));
      if(JSON.stringify(next)!==JSON.stringify(job))updates.push({index,next});
    }
    for(const {index,next} of updates)state.jobs[index]=next;
    if(full||updates.length||persistenceUncertain)await save();
  }
  const readJob=id=>{const job=state.jobs.find(job=>job.id===id);need(job,'JOB_NOT_FOUND');return wire(publicJob(job));};
  const jobCapacity=()=>{const total=state.jobs.length,settled=state.jobs.filter(job=>terminal(job.status)).length;
    return{schema:'lincoln-mainnet-job-capacity/v1',total,nonterminal:total-settled,terminal:settled,
      limit:MAINNET_RELAY_JOB_HISTORY_LIMIT,remaining:MAINNET_RELAY_JOB_HISTORY_LIMIT-total,
      acceptingNewJobs:signingEnabled&&!closed&&total<MAINNET_RELAY_JOB_HISTORY_LIMIT};};
  // Receipt issuance never blocks settlement: a failed signature or delivery is
  // retried on the next reconcile and surfaces as pointsStatus on the job.
  const pointsPending=job=>points!==null&&job.points!==undefined&&(['pending','sign-failed'].includes(job.pointsStatus)||job.pointsStatus==='issued'&&points.forwardUrl!==null);
  async function issuePoints(job,intent,receipt){
    try{
      if(job.pointsReceipt===undefined){
        // Points count only fees the treasury Safe received, so a fee this relay keeps gets no receipt.
        const log=findRelayFeeLog(receipt.logs??[],{kind:intent.kind,pool:profile.pool.address,adapter:intent.routeEntry?.route?.adapter??null,processor,feeRecipients:[TREASURY_SAFE]});
        if(!log){job.pointsStatus='no-fee';job.pointsReceipt=null;return;}
        job.pointsReceipt=await points.sign({chainId:4663,season:points.season,txHash:job.hash,logIndex:log.logIndex,claimant:job.points.claimant,referrer:job.points.referrer});job.pointsStatus='issued';
      }
      if(points.forwardUrl!==null&&job.pointsStatus==='issued'){
        const response=await fetch(`${points.forwardUrl}/v1/receipts`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(job.pointsReceipt),signal:AbortSignal.timeout(5000)});
        const reply=await response.json().catch(()=>({}));
        if(response.ok)job.pointsStatus='delivered';else if(reply.error==='RECEIPT_CONFLICT')job.pointsStatus='conflict';
      }
    }catch(error){if(job.pointsStatus!=='issued')job.pointsStatus='sign-failed';failure(error,{method:'RECONCILE',path:'/v3/jobs/points'});}
  }
  async function assertSpend(intent){
    const snapshot=await relayStage('state',()=>indexer.sync());validateIntentState(intent,snapshot,{profile,routeAdapters});await assertRagequitRecipient(client,intent,{profile,routeAdapters,blockNumber:BigInt(snapshot.blockNumber)});
    if(['transact','swap'].includes(intent.kind))need(await client.readContract({address:profile.pool.address,abi:artifacts.Phase2ASPPool.abi,functionName:'knownRoot',args:[intent.signals[0]]}),'UNKNOWN_PROOF_ROOT');
    if(intent.routeEntry)await verifyRouteLive(client,intent.routeEntry,artifacts);
  }
  async function cancelUnbroadcast(job){
    if(!job||job.hash)return false;
    const entry=(await executor.status()).entries.find(e=>e.id===job.sharedId);
    if(entry?.hash||entry?.attempts?.length){await applyEntry(job,entry);await save();return false;}
    if(entry){need(entry.status==='prepared'||entry.status==='cancelled','MAINNET_RELAY_RESERVATION_STATE_UNKNOWN');if(entry.status==='prepared')await executor.cancelPrepared(job.sharedId);}
    job.status='cancelled';await save();return true;
  }
  async function submit(body){
    const id=validRelayJobId(body?.id)?body.id:null;if(id)activeSubmissions.set(id,(activeSubmissions.get(id)??0)+1);
    try{return await submitIntent(body);}finally{if(id){const remaining=activeSubmissions.get(id)-1;if(remaining)activeSubmissions.set(id,remaining);else activeSubmissions.delete(id);}}
  }
  async function submitIntent(body){
    need(signingEnabled&&executor&&!closed,'RELAY_DISABLED');
    // `points` is stripped before validation: it is not part of the relayed transaction or its fingerprint.
    let pointsRequest=null;
    if(body&&Object.getPrototypeOf(body)===Object.prototype&&Object.hasOwn(body,'points')){need(points!==null,'POINTS_RECEIPTS_DISABLED');const {points:requested,...rest}=body;pointsRequest=await relayStage('validation',()=>normalizePointsRequest(requested));body=rest;}
    const intent=await relayStage('validation',()=>validateRelayRequest(body,options));
    return serial(async()=>{
      await relayStage('reconcile',reconcile);let job=state.jobs.find(j=>j.id===intent.id);
      let feeQuote=null;
      if(job){need(job.fingerprint===intent.fingerprint,'ID_CONFLICT');if(terminal(job.status)||['pending','unknown','conflicted'].includes(job.status)||job.hash&&!job.safeSameIdRetry)return publicJob(job);
        // Existing signed/pending/unknown jobs never obtain a replacement quote.
        // An accepted but still unsigned dynamic job retains its original cap.
        if(job.request.feeQuoteId)feeQuote=await feeQuotes.validate(intent,job.request.feeQuoteId,{allowExpired:true});
      }
      else{
        if(feeQuotes&&['transact','holderExit'].includes(intent.kind)){
          need(intent.feeQuoteId,'FEE_QUOTE_REQUIRED');feeQuote=await feeQuotes.validate(intent,intent.feeQuoteId);
        }else{
          need(!intent.feeQuoteId,feeQuotes?'FEE_QUOTE_NOT_APPLICABLE':'FEE_QUOTE_DISABLED');
          validateCommercialFee(intent,feePolicy);
        }
        need(state.jobs.length<MAINNET_RELAY_JOB_HISTORY_LIMIT,'RELAY_CAPACITY_REACHED');
        need(!state.jobs.some(j=>!['reverted','cancelled'].includes(j.status)&&j.nullifiers.some(n=>intent.nullifiers.includes(n))),'NULLIFIER_RESERVED');
      }
      let gas,gasPrice,estimatedGasUnits,currentGasQuote;
      const baseFeeBilling=feeQuote?.executionGasPriceWei!==undefined;
      function checkFeeCost(current,{checkedGas=gas,checkedPrice=gasPrice}={}){
        try{feeQuotes.checkCost({quote:feeQuote,gas:checkedGas,gasPriceWei:checkedPrice,
          ...(baseFeeBilling?{estimatedGasUnits,baseFeePerGas:current.baseFeePerGas}:{})});}
        catch(error){
          if(error.code==='FEE_QUOTE_COST_EXCEEDED')error.feeRequote={
            // A price-only movement must not request less gas than the model
            // (or a larger shape floor already approved by the client).
            rawGasUnits:String(estimatedGasUnits>BigInt(feeQuote.rawGasUnits)?estimatedGasUnits:BigInt(feeQuote.rawGasUnits)),
            gasPriceWei:baseFeeBilling?current.billingGasPriceWei:current.gasPriceWei};
          throw error;
        }
      }
      try{
        await assertSpend(intent);const estimate=await relayStage('estimate',()=>client.estimateGas({account:processor,to:intent.to,data:intent.data,value:0n}));
        estimatedGasUnits=estimate+10000n;gas=estimate*12n/10n+10000n;need(gas<=maxGas,'RELAY_GAS_LIMIT');
        if(feeQuote){
          currentGasQuote=await feeQuotes.quoteGas();
          gasPrice=baseFeeBilling?feeQuote.executionGasPriceWei:feeQuote.gasPriceWei;
          checkFeeCost(currentGasQuote,{checkedPrice:baseFeeBilling?gasPrice:currentGasQuote.gasPriceWei});
        }else if(!job&&swapEconomics&&intent.kind==='swap'){
          gasPrice=(await feeQuotes.quoteGas()).gasPriceWei;await swapEconomics.submission({intent,gas,gasPriceWei:gasPrice});
        }
      }
      catch(error){if(job)await cancelUnbroadcast(job);throw error;}
      // Rejected proofs/RPC estimates never reserve a local nullifier.
      if(!job){
        if(feeQuote)await feeQuotes.bind(intent.feeQuoteId,intent.fingerprint,intent.id);
        job={id:intent.id,kind:intent.kind,routeId:intent.routeId,request:wire(body),fingerprint:intent.fingerprint,nullifiers:intent.nullifiers,sharedId:`relay:${identity}:${intent.id}`,status:'prepared',...(pointsRequest?{points:pointsRequest,pointsStatus:'pending'}:{})};state.jobs.push(job);await save();
      }
      let reservation;
      try{
        reservation=await relayStage('signing',()=>executor.prepare({id:job.sharedId,to:intent.to,data:intent.data,value:'0',gas:String(gas),...(gasPrice?{gasPrice:String(gasPrice)}:{})}));
        if(feeQuote)checkFeeCost(currentGasQuote,{checkedGas:reservation.gas,checkedPrice:reservation.gasPrice});
        if(swapEconomics&&intent.kind==='swap'&&gasPrice)await swapEconomics.submission({intent,gas:reservation.gas,gasPriceWei:reservation.gasPrice});
      }
      catch(error){await cancelUnbroadcast(job);throw error;}
      need(BigInt(reservation.gas)<=maxGas,'RELAY_GAS_LIMIT');
      try{
        await assertSpend(intent);
        // Recheck the current base fee immediately before calling the signer.
        // Prepared intents are still unsigned and can be cancelled safely;
        // signed/pending/unknown jobs take the original-ID recovery path above.
        if(feeQuote&&baseFeeBilling)checkFeeCost(await feeQuotes.quoteGas(),{checkedGas:reservation.gas,checkedPrice:reservation.gasPrice});
      }catch(error){await cancelUnbroadcast(job);throw error;}
      try{job.hash=await relayStage('broadcast',()=>executor.broadcast(reservation));need(hash(job.hash),'MAINNET_RELAY_BROADCAST_HASH_INVALID');job.status='pending';}
      catch(error){failure(error,{method:'POST',path:'/v3/jobs',jobRecovery:recovery(intent.id)});const entry=(await executor.status()).entries.find(value=>value.id===job.sharedId);
        if(entry?.hash||entry?.attempts?.length){await applyEntry(job,entry);await save();return publicJob(job);}await cancelUnbroadcast(job);throw error;}
      await save();await relayStage('reconcile',reconcile);return readJob(job.id);
    });
  }
  const unknownPublisher=()=>structuredClone(DEFAULT_PUBLISHER_STATUS);
  let publisherStatus=unknownPublisher();async function refreshPublisher(snapshot){if(publisherStatusLoader)try{publisherStatus=await publisherStatusLoader(snapshot);}catch{publisherStatus=unknownPublisher();}return structuredClone(publisherStatus);}
  const config=()=>({profile,processor,feeRecipient:processor?TREASURY_SAFE:null,relaySigning:signingEnabled,pointsReceipts:points===null?null:{season:points.season,signer:points.signerAddress,forwarding:points.forwardUrl!==null},stateDelta:{schema:STATE_DELTA_SCHEMA,path:'/v3/state/since/<blockNumber>',maxAgeBlocks:STATE_DELTA_MAX_AGE_BLOCKS},associationPolicy:'current-note',publicExitsRequireASP:false,routes:availableRoutes.map(({id,route,targetProfile})=>({id,route,targetProfile})),serviceFees:feePolicy,...(feeQuotes?{feeQuotes:feeQuotes.publicConfig()}:{}),...structuredClone(publisherStatusLoader?.snapshot?.()??publisherStatus),...profileReleaseFlags(profile)});
  async function routeQuote(options){
    const result=await quoteRoute(options);
    if(!swapEconomics)return result;
    const entry=availableRoutes.find(entry=>entry.id===options.route.id);need(entry,'UNKNOWN_ROUTE');
    return swapEconomics.quote({quote:result,entry});
  }
  async function quote(body){exact(body,['amountIn','routeId','slippageBPS']);const amountIn=amount(body.amountIn);need(Number.isSafeInteger(body.slippageBPS)&&body.slippageBPS>=1&&body.slippageBPS<=500,'INVALID_QUOTE_LIMITS');const entry=availableRoutes.find(r=>r.id===body.routeId);need(entry&&typeof quoteRoute==='function','QUOTE_UNAVAILABLE');return routeQuote({client,sourceProfile:profile,targetProfile:entry.targetProfile,route:{...entry.route,id:entry.id},amountIn,slippageBPS:body.slippageBPS});}
  function fees(body){
    need(feePolicy!==null,'SERVICE_FEE_POLICY_DISABLED');
    if(feeQuotes&&body?.schema==='lincoln-fee-request/v3')return feeQuotes.quote(body);
    exact(body,['kind','grossAmount']);
    need(!feeQuotes||['ragequit','deposit'].includes(body.kind),'FEE_QUOTE_REQUEST_REQUIRED');
    return quoteServiceFee({policy:feePolicy,kind:body.kind,grossAmount:body.grossAmount});
  }
  async function aggregateQuote(body){
    exact(body,['targetPool','amountIn','slippageBPS']);const amountIn=amount(body.amountIn);
    need(typeof body.targetPool==='string'&&/^0x[0-9a-f]{40}$/i.test(body.targetPool),'INVALID_ADDRESS');
    need(Number.isSafeInteger(body.slippageBPS)&&body.slippageBPS>=1&&body.slippageBPS<=500,'INVALID_QUOTE_LIMITS');
    const selected=availableRoutes.filter(entry=>entry.geometry.targetPool===body.targetPool.toLowerCase());need(selected.length>0&&typeof quoteRoute==='function','QUOTE_UNAVAILABLE');
    return quotePhase2Aggregate({client,sourceProfile:profile,targetProfile:selected[0].targetProfile,routes:selected,amountIn,slippageBPS:body.slippageBPS,quoteRoute:routeQuote,
      feeBpsForRoute:entry=>FEE_ADAPTER_TYPES.includes(entry.route.adapterType)?entry.route.feeBps:0});
  }
  const quoteGate=createQuoteGate();
  const json=(res,status,value)=>serviceJson(res,status,wire(value));
  // Large snapshot documents are serialised once per completed sync (plus the
  // small publisher status they embed) and answered with a validator, so a
  // polling client that already holds the body gets a 304 instead of ~1 MB.
  const snapshotBodies=new Map();
  function snapshotJson(req,res,name,snapshot,extra,build){
    const version=indexer.versionOf(snapshot),extraKey=JSON.stringify(extra??null),cached=snapshotBodies.get(name);
    if(version===null)return json(res,200,build());
    if(!cached||cached.version!==version||cached.extraKey!==extraKey){
      const bytes=JSON.stringify(wire(build())),etag='"'+createHash('sha256').update(bytes).digest('hex').slice(0,32)+'"';
      snapshotBodies.set(name,{version,extraKey,bytes,etag});
    }
    return serviceJsonVersioned(req,res,snapshotBodies.get(name));
  }
  /** Latest snapshot for public reads; never makes a request wait on a sync it can avoid. */
  async function readSnapshot(){
    const latest=indexer.latest();
    if(latest){
      const age=Date.now()-latest.completedAt;
      if(age<=SNAPSHOT_FRESH_MS)return latest.snapshot;
      if(age<=snapshotStaleMs){void indexer.sync().catch(()=>{});return latest.snapshot;}
    }
    return indexer.sync();
  }
  // Canonical hash of a client's base block, shared by concurrent clients for a few seconds.
  const baseHashes=new Map();
  async function canonicalHash(number,snapshot){
    if(String(number)===snapshot.blockNumber)return snapshot.blockHash;
    const memo=baseHashes.get(number);if(memo&&Date.now()-memo.at<=SNAPSHOT_FRESH_MS)return memo.hash;
    const block=await client.getBlock({blockNumber:BigInt(number)});need(block&&/^0x[0-9a-f]{64}$/i.test(block.hash),'RPC_BLOCK_INVALID');
    baseHashes.set(number,{hash:block.hash,at:Date.now()});while(baseHashes.size>256)baseHashes.delete(baseHashes.keys().next().value);
    return block.hash;
  }
  // Association sets this process has served, by root, to send a set change as an append.
  const servedSets=new Map();
  const noteSet=asp=>{if(Array.isArray(asp?.leaves)&&!servedSets.has(asp.root)){servedSets.set(asp.root,asp.leaves);while(servedSets.size>32)servedSets.delete(servedSets.keys().next().value);}};
  async function stateDelta(from,snapshot,publisher){
    const head=BigInt(snapshot.blockNumber);
    // Refuse before any RPC read for a base this relay will not serve.
    if(from>head||head-from>BigInt(STATE_DELTA_MAX_AGE_BLOCKS))return buildStateDelta({snapshot,from,baseBlockHash:null,publisher});
    noteSet(snapshot.asp);
    return buildStateDelta({snapshot,from,baseBlockHash:await canonicalHash(from,snapshot),publisher,servedSet:root=>servedSets.get(root)});
  }
  async function body(req){need(req.headers['content-type']?.split(';')[0]==='application/json','JSON_REQUIRED');let size=0;const chunks=[];for await(const chunk of req){size+=chunk.length;need(size<=32768,'BODY_TOO_LARGE');chunks.push(chunk);}try{return JSON.parse(Buffer.concat(chunks));}catch{throw new Error('INVALID_JSON');}}
  const server=createBoundedHttpServer(async(req,res)=>{const jobRead=req.method==='GET'&&/^\/v3\/jobs\/[A-Za-z0-9_-]{8,80}$/.test(req.url);let jobId=jobRead?req.url.split('/').at(-1):null;const jobRequest=req.method==='POST'&&req.url==='/v3/jobs';res.relayErrorReply=error=>failure(error,{method:req.method,path:req.url,jobRecovery:jobRequest||jobRead?{...recovery(jobId),...((jobRequest||jobRead)&&error.message==='REQUEST_DEADLINE_EXCEEDED'?{jobMayContinue:true,retrySameId:false}:{})}:undefined});try{
    need(networkPolicy.allows(req.headers.host,req.headers.origin),'HOST_OR_ORIGIN_DENIED');const url=new URL(req.url,'http://127.0.0.1');need(!url.search,'QUERY_NOT_SUPPORTED');
    if(url.pathname==='/v3/events'){
      if(req.method!=='GET')return json(res,405,{error:'METHOD_NOT_ALLOWED'});
      if(!publicationEvents.subscribe(req,res))return json(res,503,{error:'ASP_EVENTS_UNAVAILABLE'});
      return;
    }
    if(req.method==='GET'&&url.pathname==='/livez')return json(res,200,{ok:true});
    if(req.method==='GET'&&['/healthz','/readyz','/v3/readyz'].includes(url.pathname)){
      // Readiness, configuration, state and association-set reads may reuse a
      // snapshot completed within the last three seconds; spend validation
      // (job submission) always takes a fresh canonical snapshot.
      const s=await readSnapshot(),feeStatus=feeQuotes?.publicConfig(),feeCapacity=feeQuotes?.capacity(),priceStatus=assetPriceSource?.status();
      const quotesReady=feeStatus?.available!==false&&feeCapacity?.canIssue!==false;
      return json(res,200,{ok:true,chainId:4663,blockNumber:s.blockNumber,relaySigning:signingEnabled,jobCapacity:jobCapacity(),
        normalSpendingReady:!s.asp.expired&&s.asp.spendable!==false&&Array.isArray(s.asp.leaves)&&quotesReady,publicExitsReady:true,
        ...(feeStatus?{feeQuotesReady:quotesReady,feeQuoteUnavailableReason:feeStatus.unavailableReason??feeCapacity.reason,
          feeQuoteCapacity:feeCapacity}:{}),
        ...(priceStatus?{swapPricingReady:priceStatus.available===true,priceFeed:priceStatus}:{}),
        asp:{root:s.asp.root,epoch:s.asp.epoch,validUntil:s.asp.validUntil,expired:s.asp.expired,setAvailable:Array.isArray(s.asp.leaves)},
        eventLoopDelayMs:loopWindow??loopSample(),
        ...await refreshPublisher(s),...profileReleaseFlags(profile)});
    }
    if(req.method==='GET'&&url.pathname==='/v3/config'){await refreshPublisher(await readSnapshot());return json(res,200,config());}
    if(req.method==='GET'&&url.pathname==='/v3/state'){const snapshot=await readSnapshot(),{checkpoint,nullifierBlocks,...s}=snapshot,publisher=await refreshPublisher(s);noteSet(s.asp);return snapshotJson(req,res,'state',snapshot,publisher,()=>({...s,...publisher}));}
    if(req.method==='GET'&&STATE_DELTA_PATH.test(url.pathname)){const snapshot=await readSnapshot(),publisher=await refreshPublisher(snapshot);
      try{return json(res,200,await stateDelta(BigInt(STATE_DELTA_PATH.exec(url.pathname)[1]),snapshot,publisher));}
      catch(error){if(error.status===409)return json(res,409,{error:error.code,blockNumber:snapshot.blockNumber,maxAgeBlocks:STATE_DELTA_MAX_AGE_BLOCKS});throw error;}}
    if(req.method==='GET'&&url.pathname==='/v3/association-set'){const s=await readSnapshot();noteSet(s.asp);need(Array.isArray(s.asp.leaves),'ASSOCIATION_SET_UNAVAILABLE');return snapshotJson(req,res,'association-set',s,null,()=>({schema:'phase2-asp-association-set/v1',chainId:s.chainId,pool:s.pool,blockNumber:s.blockNumber,blockHash:s.blockHash,...s.asp}));}
    if(req.method==='POST'&&url.pathname==='/v3/jobs'){const request=await body(req);jobId=validRelayJobId(request?.id)?request.id:null;const job=await submit(request);return json(res,200,{...job,...recovery(jobId)});}
    if(req.method==='POST'&&url.pathname==='/v3/quote'){const request=await body(req);return json(res,200,await relayStage('quote',()=>quoteGate(()=>quote(request))));}
    if(req.method==='POST'&&url.pathname==='/v3/fees'){const request=await body(req);return json(res,200,await relayStage('quote',()=>quoteGate(()=>fees(request))));}
    if(req.method==='POST'&&url.pathname==='/v3/aggregate-quote'){const request=await body(req);return json(res,200,await relayStage('quote',()=>quoteGate(()=>aggregateQuote(request))));}
    if(req.method==='GET'&&/^\/v3\/jobs\/[A-Za-z0-9_-]{8,80}$/.test(url.pathname)){const job=readJob(jobId);return json(res,200,{...job,...recovery(jobId)});}
    json(res,404,{error:'NOT_FOUND'});
  }catch(error){const reply=res.relayErrorReply(error);json(res,reply.status,reply.body);}},httpLimits);
  try{await reconcile({full:true});await refreshPublisher(await indexer.sync());if(listen)await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});}catch(error){await Promise.allSettled([indexer.close(),store.close(),feeQuotes?.close()]);throw error;}
  const reconcileTimer=setInterval(()=>{
    // Never build a timer queue behind submissions or reconciliation already
    // in progress. Status GETs do not enter this writer queue at all.
    if(closed||queued||!persistenceUncertain&&!state.jobs.some(job=>!terminal(job.status)))return;
    void serial(()=>relayStage('reconcile',()=>reconcile())).catch(error=>{failure(error,{method:'BACKGROUND',path:'/v3/jobs'});});
  },reconcileIntervalMs);reconcileTimer.unref?.();
  return {port:listen?server.address().port:null,host,config,submit,quote,fees,aggregateQuote,sync:()=>indexer.sync(),async job(id){return readJob(id);},async reconcile(){return serial(()=>relayStage('reconcile',()=>reconcile()));},async close(){
    closed=true;clearInterval(reconcileTimer);
    try{await publicationEvents.close();if(listen)await new Promise(resolve=>server.close(resolve));await tail;}
    finally{
      const results=await Promise.allSettled([indexer.close(),store.close(),feeQuotes?.close(),assetPriceSource?.close()]);
      const failure=results.find(result=>result.status==='rejected');if(failure)throw failure.reason;
    }
  }};
}
