#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Mainnet is a separate entry point. Signing is disabled unless explicitly set.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {loadProductionRuntimeRelease,withProductionReleaseValidation} from './artifacts.mjs';
import {createMainnetSigner,createCastTypedDataSigner,MAINNET_RPC} from './signer.mjs';
import {createMainnetRuntimeClient,assertMainnetRPCIdentity} from './rpc.mjs';
import {createMainnetASPService} from './service.mjs';
import {normalizeServiceRoutes} from '../phase2-asp/service.mjs';
import {createAssociationSetFileLoader} from '../phase2-asp/server.mjs';
import {normalizeProfile,PRODUCTION_PROFILE_SCHEMA} from '../phase2-asp/sdk.mjs';
import {createNetworkPolicy} from '../phase1-service/network.mjs';
import {FEE_ADAPTER_TYPES} from '../phase2-fees/sdk.mjs';
import {mainnetAPIExecutorFor} from './startup-signer.mjs';
import {loadFeeComponents} from '../phase2-fees/artifacts.mjs';
import {normalizeServiceFeePolicy,SERVICE_FEE_POLICY_V2} from '../phase2-fees/policy.mjs';
import {normalizeGasPricingPolicy} from './fee-quotes.mjs';
import {createTwapPriceSource} from './twap-prices.mjs';
import {createPublisherStatusLoader} from '../phase2-asp/publisher-status.mjs';
import {createPhase2PonderClient} from '../phase2-asp/ponder-client.mjs';
import {withImmutableReadCache} from '../phase2-asp/immutable-reads.mjs';
import {withCoalescedReads} from '../phase2-asp/coalesced-reads.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
async function readConfig(filename){
  filename=path.resolve(filename);const h=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await h.stat();need(stat.isFile()&&stat.size<=8*1024*1024&&await fs.realpath(filename)===filename,'MAINNET_RUNTIME_CONFIG_INVALID');return JSON.parse(await h.readFile('utf8'));}finally{await h.close();}
}
const quantity=(value,code)=>{need(typeof value==='string'&&/^[1-9][0-9]{0,38}$/.test(value),code);return BigInt(value);};
const environmentDigest=env=>createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.entries(env).sort(([a],[b])=>a<b?-1:a>b?1:0)))).digest('hex');

/** The existing fee-file mount can carry an explicitly enabled pricing policy.
 * Plain v1/v2 policies retain their existing fixed-fee behavior. Validate this
 * public envelope during preparation, before a signer can read any keystore.
 */
export function normalizeMainnetRuntimePricing(input){
  if(input?.schema!=='lincoln-relay-pricing/v1')return {serviceFeePolicy:normalizeServiceFeePolicy(input),gasPricingPolicy:null};
  const keys=['schema','serviceFees','gasPricing'];
  need(Object.getPrototypeOf(input)===Object.prototype&&Reflect.ownKeys(input).length===keys.length
    &&Reflect.ownKeys(input).every(key=>keys.includes(key)&&Object.hasOwn(Object.getOwnPropertyDescriptor(input,key),'value')),'MAINNET_RELAY_PRICING_INVALID');
  const serviceFeePolicy=normalizeServiceFeePolicy(input.serviceFees),gasPricingPolicy=normalizeGasPricingPolicy(input.gasPricing);
  need(serviceFeePolicy.schema===SERVICE_FEE_POLICY_V2,'MAINNET_DYNAMIC_FEES_V2_POLICY_REQUIRED');
  return {serviceFeePolicy,gasPricingPolicy};
}

/** An independently constructed factory cannot mint tickets accepted by the
 * private runtime instance. Its pure lifecycle is tested without any wallets.
 */
export function createEphemeralRuntimeTickets(){
  const scopes=new WeakMap(),tickets=new WeakMap();
  const authority=scope=>{const value=scopes.get(scope);need(value,'MAINNET_RUNTIME_PREPARATION_CLOSED_OR_FOREIGN');return value;};
  return Object.freeze({
    authority,
    async withScope(validationScope,callback){
      const scope=Object.freeze(Object.create(null)),state={validationScope,tickets:new Set()};scopes.set(scope,state);
      try{return await callback(scope);}finally{for(const ticket of state.tickets)tickets.delete(ticket);state.tickets.clear();scopes.delete(scope);}
    },
    issue(scope,env,data){const state=authority(scope),ticket=Object.freeze(Object.create(null));tickets.set(ticket,{scope,envDigest:environmentDigest(env),data});state.tickets.add(ticket);return ticket;},
    consume(ticket,env){
      const prepared=tickets.get(ticket),state=prepared&&scopes.get(prepared.scope);need(prepared&&state,'MAINNET_RUNTIME_TICKET_INVALID_OR_EXPIRED');
      need(prepared.envDigest===environmentDigest(env),'MAINNET_RUNTIME_TICKET_ENVIRONMENT_CHANGED');
      tickets.delete(ticket);state.tickets.delete(ticket);return prepared.data;
    },
  });
}
const runtimeTickets=createEphemeralRuntimeTickets();

/** The startup transaction owns every ticket. Warm-up tickets expire before a
 * candidate waits for its gate; only fresh post-gate tickets can be consumed.
 */
export async function withMainnetRuntimePreparation(callback){
  need(typeof callback==='function','MAINNET_RUNTIME_PREPARATION_INVALID');
  return withProductionReleaseValidation(validationScope=>runtimeTickets.withScope(validationScope,callback));
}

/** Pure preparation: validates the complete public release, routes and policy.
 * It never constructs an RPC client, signer, business store or HTTP listener.
 * A blue/green candidate keeps this process alive so activation can re-read all
 * pins while reusing only the existing content-bound in-process verifier cache.
 */
export async function prepareMainnetASPRuntime(env=process.env,{preparationScope}={}){
  if(preparationScope===undefined)return withMainnetRuntimePreparation(scope=>prepareMainnetASPRuntime(env,{preparationScope:scope}));
  const authority=runtimeTickets.authority(preparationScope);
  env=structuredClone(env);
  const root=await fs.realpath(env.PHASE2_MAINNET_ROOT??ROOT),config=await readConfig(env.PHASE2_MAINNET_PROFILE_PATH??path.join(root,'config/phase2-mainnet-deployed.json'));
  const poolId=env.PHASE2_MAINNET_POOL_ID??'eth';need(/^[a-z][a-z0-9_-]{0,63}$/.test(poolId),'MAINNET_POOL_ID_INVALID');
  const profile=config.schema===PRODUCTION_PROFILE_SCHEMA?config:config.profiles?.[poolId];normalizeProfile(profile);need(profile.schema===PRODUCTION_PROFILE_SCHEMA,'MAINNET_PRODUCTION_PROFILE_REQUIRED');
  // Validate actual final parameters and reproduced bytecode before opening any
  // socket, reading a keystore, or creating a signing reservation.
  const release=await loadProductionRuntimeRelease({rootDirectory:root,profile,validationScope:authority.validationScope});
  const {serviceFeePolicy,gasPricingPolicy}=env.PHASE2_MAINNET_SERVICE_FEES_FILE?normalizeMainnetRuntimePricing(await readConfig(env.PHASE2_MAINNET_SERVICE_FEES_FILE)):{serviceFeePolicy:null,gasPricingPolicy:null};
  need(profile.chain.rpcUrl===MAINNET_RPC,'MAINNET_OFFICIAL_RPC_REQUIRED');
  need(env.PHASE2_ASP_PONDER_MODE===undefined||env.PHASE2_ASP_PONDER_MODE==='logs','MAINNET_PONDER_LOGS_ONLY_REQUIRED');
  need(env.PHASE2_ASP_PONDER_FALLBACK===undefined||['rpc','reject'].includes(env.PHASE2_ASP_PONDER_FALLBACK),'INVALID_PONDER_FALLBACK');
  need(env.PHASE2_MAINNET_MIN_PUBLISH_INTERVAL_SECONDS===undefined||/^[1-9][0-9]{0,6}$/.test(env.PHASE2_MAINNET_MIN_PUBLISH_INTERVAL_SECONDS),'MAINNET_MIN_PUBLISH_INTERVAL_INVALID');
  need(env.PHASE2_MAINNET_SIGNING_ENABLED===undefined||['0','1'].includes(env.PHASE2_MAINNET_SIGNING_ENABLED),'MAINNET_SIGNING_FLAG_INVALID');
  const signingEnabled=env.PHASE2_MAINNET_SIGNING_ENABLED==='1',maxGas=quantity(env.PHASE2_MAINNET_MAX_GAS??'5000000','MAINNET_MAX_GAS_INVALID');
  if(gasPricingPolicy)need(BigInt(gasPricingPolicy.maxGasUnits)<=maxGas,'MAINNET_DYNAMIC_FEE_GAS_LIMIT_EXCEEDS_RUNTIME');
  const hasLedgerConfiguration=['PHASE2_MAINNET_GAS_BUDGET_WEI','PHASE2_MAINNET_MAX_FEE_PER_GAS_WEI','PHASE2_MAINNET_RESERVE_WEI'].some(name=>env[name]!==undefined);
  if(signingEnabled||hasLedgerConfiguration){
    quantity(env.PHASE2_MAINNET_GAS_BUDGET_WEI,'MAINNET_EXPLICIT_GAS_BUDGET_REQUIRED');quantity(env.PHASE2_MAINNET_MAX_FEE_PER_GAS_WEI,'MAINNET_EXPLICIT_GAS_PRICE_REQUIRED');
    if(gasPricingPolicy)need(BigInt(gasPricingPolicy.maxGasPriceWei)<=BigInt(env.PHASE2_MAINNET_MAX_FEE_PER_GAS_WEI),'MAINNET_DYNAMIC_FEE_PRICE_CAP_EXCEEDS_SIGNER');
    need(typeof env.PHASE2_MAINNET_RESERVE_WEI==='string'&&/^(0|[1-9][0-9]{0,38})$/.test(env.PHASE2_MAINNET_RESERVE_WEI),'MAINNET_EXPLICIT_RESERVE_REQUIRED');
    need(profile.relayer,'MAINNET_RELAYER_REQUIRED');
    if(signingEnabled)need(Number(Boolean(env.PHASE2_MAINNET_KEYSTORE_ACCOUNT))+Number(Boolean(env.PHASE2_MAINNET_KEYSTORE_FILE))===1&&env.PHASE2_MAINNET_PASSWORD_FILE,'MAINNET_EXPLICIT_KEYSTORE_REQUIRED');
  }
  // Optional points receipts, signed by the relay keystore after confirmation.
  // Only the plain settings cross the runtime ticket; the signer is built at start.
  let points=null;
  if(env.PHASE2_MAINNET_POINTS_SEASON!==undefined){
    need(signingEnabled,'MAINNET_POINTS_SIGNING_REQUIRED');need(/^[a-z0-9][a-z0-9_-]{0,63}$/.test(env.PHASE2_MAINNET_POINTS_SEASON),'MAINNET_POINTS_SEASON_INVALID');
    need(env.PHASE2_MAINNET_POINTS_URL===undefined||/^https?:\/\/[^\s/?#]+$/.test(env.PHASE2_MAINNET_POINTS_URL),'MAINNET_POINTS_URL_INVALID');
    points={season:env.PHASE2_MAINNET_POINTS_SEASON,forwardUrl:env.PHASE2_MAINNET_POINTS_URL??null};
  }
  const routes=config.routesByPool?.[poolId]??[];
  need(Array.isArray(routes),'MAINNET_ROUTES_INVALID');
  normalizeServiceRoutes(profile,routes);
  for(const entry of routes){
    normalizeProfile(entry.targetProfile);need(entry.targetProfile.schema===PRODUCTION_PROFILE_SCHEMA&&entry.targetProfile.artifactSHA256===release.artifactSHA256&&['joinsplit','holder-exit'].every(name=>entry.targetProfile.production.manifests[name].sha256===profile.production.manifests[name].sha256),'MAINNET_ROUTE_RELEASE_MISMATCH');
    // Route target parameter inventories are independent profile claims too.
    // Every target is checked; identical complete pins share only this scope's
    // already fully re-read release, never merely an artifact SHA or first route.
    await loadProductionRuntimeRelease({rootDirectory:root,profile:entry.targetProfile,validationScope:authority.validationScope});
  }
  const paidRoutes=routes.filter(entry=>FEE_ADAPTER_TYPES.includes(entry.route?.adapterType));
  let runtimeArtifacts=release.artifacts;
  if(paidRoutes.length){
    need(env.PHASE2_MAINNET_FEE_ARTIFACTS_PATH,'MAINNET_EXPLICIT_FEE_COMPONENT_REQUIRED');
    const components=await loadFeeComponents({filename:env.PHASE2_MAINNET_FEE_ARTIFACTS_PATH,rootDirectory:root,routes:paidRoutes,chainId:4663,validationScope:authority.validationScope});
    runtimeArtifacts={...runtimeArtifacts,...components.contracts};
  }
  const port=Number(env.PHASE2_MAINNET_PORT??8797),host=env.PHASE2_MAINNET_HOST??'127.0.0.1';
  need(Number.isSafeInteger(port)&&port>=0&&port<=65535&&['127.0.0.1','0.0.0.0','::1'].includes(host),'MAINNET_LISTEN_OPTIONS_INVALID');
  const networkPolicy=createNetworkPolicy({PHASE1_ALLOWED_HOSTS:env.PHASE2_MAINNET_ALLOWED_HOSTS,PHASE1_ALLOWED_ORIGINS:env.PHASE2_MAINNET_ALLOWED_ORIGINS});
  need(runtimeTickets.authority(preparationScope)===authority,'MAINNET_RUNTIME_PREPARATION_CLOSED_OR_FOREIGN');
  return runtimeTickets.issue(preparationScope,env,{root,poolId,...structuredClone({profile,serviceFeePolicy,gasPricingPolicy,runtimeArtifacts,routes,points}),signingEnabled,maxGas,host,port,networkPolicy,hasLedgerConfiguration});
}

export async function startMainnetASPRuntime(env=process.env,overrides={}){
  env=structuredClone(env);
  if(overrides.preparedRuntime===undefined)return withMainnetRuntimePreparation(async scope=>startMainnetASPRuntime(env,{...overrides,preparedRuntime:await prepareMainnetASPRuntime(env,{preparationScope:scope})}));
  // This is not an object-based verification bypass: only a still-open startup
  // transaction can mint a private, exact-environment, single-use capability.
  const {root,poolId,profile,serviceFeePolicy,gasPricingPolicy,runtimeArtifacts,routes,points,signingEnabled,maxGas,host,port,networkPolicy,hasLedgerConfiguration}=runtimeTickets.consume(overrides.preparedRuntime,env);
  const rpcClient=overrides.client??await createMainnetRuntimeClient({env,expectedGenesisHash:profile.genesisHash});
  // State syncs reuse the genesis header and verified runtime code between
  // runs (immutable-reads.mjs); the signer and price feed keep the plain client.
  // A multi-pool container passes one shared wrapper over its shared client, so
  // the roster's same-moment reads coalesce across pools, not only within one.
  need(overrides.stateReads===undefined||overrides.client!==undefined&&typeof overrides.stateReads?.coalescedReadStatus==='function','MAINNET_STATE_READS_INVALID');
  const stateReads=overrides.stateReads??withCoalescedReads(withImmutableReadCache(rpcClient));
  const client=env.PHASE2_ASP_PONDER_URL?createPhase2PonderClient({client:stateReads,profile,baseURL:env.PHASE2_ASP_PONDER_URL,
    mode:'logs',fallbackToRpc:env.PHASE2_ASP_PONDER_FALLBACK!=='reject'}):stateReads;
  if(overrides.client)await assertMainnetRPCIdentity(client,{expectedGenesisHash:profile.genesisHash});
  const publisherStatusLoader=overrides.publisherStatusLoader??createPublisherStatusLoader({client,profile,
    filename:env.PHASE2_MAINNET_PUBLISHER_STATUS_FILE,mirrorURL:env.PHASE2_MAINNET_PUBLISHER_STATUS_MIRROR_URL,
    minPublishIntervalSeconds:env.PHASE2_MAINNET_MIN_PUBLISH_INTERVAL_SECONDS===undefined?null:Number(env.PHASE2_MAINNET_MIN_PUBLISH_INTERVAL_SECONDS)});
  const executorOptions={client:rpcClient,address:profile.relayer,account:env.PHASE2_MAINNET_KEYSTORE_ACCOUNT,keystoreFile:env.PHASE2_MAINNET_KEYSTORE_FILE,passwordFile:env.PHASE2_MAINNET_PASSWORD_FILE,
    budgetWei:env.PHASE2_MAINNET_GAS_BUDGET_WEI,maxFeePerGasWei:env.PHASE2_MAINNET_MAX_FEE_PER_GAS_WEI,reserveWei:env.PHASE2_MAINNET_RESERVE_WEI,expectedGenesisHash:profile.genesisHash,root,
    unknownBroadcastProbeMs:overrides.unknownBroadcastProbeMs??45000};
  const executor=signingEnabled||hasLedgerConfiguration?(overrides.executorGroup===undefined?createMainnetSigner(executorOptions):
    mainnetAPIExecutorFor(overrides.executorGroup,executorOptions)):null;
  const pointsReceipts=points===null?null:{...points,signer:overrides.pointsSigner??createCastTypedDataSigner({address:profile.relayer,
    account:env.PHASE2_MAINNET_KEYSTORE_ACCOUNT,keystoreFile:env.PHASE2_MAINNET_KEYSTORE_FILE,passwordFile:env.PHASE2_MAINNET_PASSWORD_FILE})};
  const quoteRoute=overrides.quoteRoute??(async options=>{const {quotePhase2Route}=await import('../phase2-asp/quote.mjs');return quotePhase2Route(options);});
  const assetPriceSource=gasPricingPolicy?.priceFeed?await createTwapPriceSource({client:rpcClient,policy:gasPricingPolicy.priceFeed}):null;
  try{return await createMainnetASPService({client,profile,artifacts:runtimeArtifacts,executor,signingEnabled,routes,quoteRoute,serviceFeePolicy,gasPricingPolicy,assetPriceSource,publisherStatusLoader,pointsReceipts,maxGas,host,port,networkPolicy,
      associationSetFile:env.PHASE2_MAINNET_ASSOCIATION_SET_FILE,
      associationSetLoader:env.PHASE2_MAINNET_ASSOCIATION_SET_FILE?createAssociationSetFileLoader(env.PHASE2_MAINNET_ASSOCIATION_SET_FILE,{mirrorURL:env.PHASE2_MAINNET_ASSOCIATION_SET_MIRROR_URL}):undefined,
      directory:env.PHASE2_MAINNET_STATE_DIR??path.join(root,'.phase1-private/phase2-mainnet/api',poolId),listen:overrides.listen??true});}
  catch(error){await assetPriceSource?.close();throw error;}
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const service=await startMainnetASPRuntime();process.stdout.write(JSON.stringify({service:'phase2-mainnet-asp',host:service.host,port:service.port,relaySigning:service.config().relaySigning,releaseCandidate:true,testOnly:false,productionReady:false})+'\n');
    let stopping=false;for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{if(stopping)return;stopping=true;try{await service.close();process.exit(0);}catch{process.exit(1);}});
  }catch(error){process.stderr.write(/^[A-Z][A-Z0-9_]{1,80}$/.test(error.code??error.message)?error.code??error.message:'MAINNET_ASP_STARTUP_FAILED');process.exit(1);}
}
