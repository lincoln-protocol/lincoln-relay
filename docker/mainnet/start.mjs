#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Separate mainnet entry point. No signer, socket or RPC opens during planning.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {decodeFunctionData,encodeFunctionData,isAddress} from 'viem';
import {startMainnetASPRuntime,prepareMainnetASPRuntime,withMainnetRuntimePreparation} from '../../src/phase2-mainnet/server.mjs';
import {publicMirrorURL} from '../../src/phase2-asp/publisher-status.mjs';
import {loadProductionRelease} from '../../src/phase2-mainnet/artifacts.mjs';
import {createMainnetSigner,MAINNET_RPC} from '../../src/phase2-mainnet/signer.mjs';
import {createMainnetRuntimeClient,resolveMainnetRPC,MAINNET_RPC_FILE} from '../../src/phase2-mainnet/rpc.mjs';
import {createASPEventSource} from '../../src/phase2-mainnet/asp-event-source.mjs';
import {createASPOperator,DEFAULT_ASP_OPERATOR_POLICY} from '../../src/phase2-asp/asp-operator.mjs';
import {createASPPublisher} from '../../src/phase2-mainnet/asp-publisher.mjs';
import {createMainnetAPIExecutorGroup,finishMainnetAPIExecutorGroup} from '../../src/phase2-mainnet/startup-signer.mjs';
import {normalizeProfile,PRODUCTION_PROFILE_SCHEMA} from '../../src/phase2-asp/sdk.mjs';
import {createNetworkPolicy} from '../../src/phase1-service/network.mjs';
import {createPhase2PonderClient} from '../../src/phase2-asp/ponder-client.mjs';
import {readMainnetConfigurationDigest,readMainnetActivationRequest,waitForMainnetActivation,assertMainnetRoleQuiescent,acquireMainnetWriterLease} from '../../src/phase2-mainnet/activation.mjs';

export const MAINNET_CONTAINER_ROOT='/app';
export const MAINNET_STATE='/app/.phase1-private/phase2-mainnet';
export const MAINNET_CONFIG='/run/config/mainnet';
export const MAINNET_SAFE='0x9CF17a6E3c75D200f58283A165C442a8A3994555';
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const exact=(v,keys,code)=>need(v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===[...keys].sort().join(','),code);
const quantity=(v,{zero=false}={})=>typeof v==='string'&&/^(0|[1-9][0-9]{0,38})$/.test(v)&&(zero||BigInt(v)>0n);
const sameAddress=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
const fileName=v=>typeof v==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9._-]*\.json$/.test(v);

/** Legacy single-policy files remain valid. A map must cover every configured
 * pool exactly, so an ERC20 pool never silently inherits an ETH-denominated quote.
 */
export function mainnetServiceFeeFile(config,poolId){
  const value=config.serviceFeesFile;
  if(value===null||fileName(value))return value;
  exact(value,config.poolIds,'MAINNET_CONTAINER_FEE_POOL_MAP_INVALID');
  need(Object.values(value).every(fileName)&&config.poolIds.includes(poolId),'MAINNET_CONTAINER_FEE_POOL_MAP_INVALID');
  return value[poolId];
}
// Containers accept only the fixed secret mount. No URL value enters config,
// plan, command arguments, or the child runtime environment.
export function mainnetContainerRPCEnvironment(env={}){
  need(env.PHASE2_MAINNET_RPC_URL===undefined,'MAINNET_RPC_URL_ENV_FORBIDDEN');
  need(env.PHASE2_MAINNET_RPC_FILE===undefined||env.PHASE2_MAINNET_RPC_FILE===MAINNET_RPC_FILE,'MAINNET_CONTAINER_RPC_MOUNT_REQUIRED');
  need(env.PHASE2_MAINNET_RPC_WEBSOCKET===undefined||['0','1'].includes(env.PHASE2_MAINNET_RPC_WEBSOCKET),'MAINNET_RPC_WEBSOCKET_INVALID');
  return {...(env.PHASE2_MAINNET_RPC_FILE===undefined?{}:{PHASE2_MAINNET_RPC_FILE:MAINNET_RPC_FILE}),
    ...(env.PHASE2_MAINNET_RPC_WEBSOCKET===undefined?{}:{PHASE2_MAINNET_RPC_WEBSOCKET:env.PHASE2_MAINNET_RPC_WEBSOCKET})};
}
export function mainnetContainerMirrorEnvironment(env={}){
  const result={};
  for(const name of ['PHASE2_MAINNET_ASSOCIATION_SET_MIRROR_URL','PHASE2_MAINNET_PUBLISHER_STATUS_MIRROR_URL']){
    if(env[name]===undefined)continue;
    need(publicMirrorURL(env[name]),'MAINNET_CONTAINER_MIRROR_URL_INVALID');result[name]=env[name];
  }
  return result;
}
// Points receipts are opt-in; the API server re-checks both values and requires signing.
export function mainnetContainerPointsEnvironment(env={}){
  if(env.PHASE2_MAINNET_POINTS_SEASON===undefined){need(env.PHASE2_MAINNET_POINTS_URL===undefined,'MAINNET_POINTS_SEASON_REQUIRED');return {};}
  need(/^[a-z0-9][a-z0-9_-]{0,63}$/.test(env.PHASE2_MAINNET_POINTS_SEASON),'MAINNET_POINTS_SEASON_INVALID');
  need(env.PHASE2_MAINNET_POINTS_URL===undefined||/^https:\/\/[^\s/?#]+$/.test(env.PHASE2_MAINNET_POINTS_URL),'MAINNET_POINTS_URL_INVALID');
  return {PHASE2_MAINNET_POINTS_SEASON:env.PHASE2_MAINNET_POINTS_SEASON,...(env.PHASE2_MAINNET_POINTS_URL===undefined?{}:{PHASE2_MAINNET_POINTS_URL:env.PHASE2_MAINNET_POINTS_URL})};
}
export function mainnetContainerIndexerEnvironment(env={}){
  need(env.PHASE2_ASP_PONDER_URL===undefined||env.PHASE2_ASP_PONDER_URL==='http://indexer:44663/','MAINNET_CONTAINER_INDEXER_URL_INVALID');
  need(env.PHASE2_ASP_PONDER_MODE===undefined||env.PHASE2_ASP_PONDER_MODE==='logs','MAINNET_PONDER_LOGS_ONLY_REQUIRED');
  need(env.PHASE2_ASP_PONDER_FALLBACK===undefined||env.PHASE2_ASP_PONDER_FALLBACK==='rpc','MAINNET_CONTAINER_INDEXER_FALLBACK_INVALID');
  return env.PHASE2_ASP_PONDER_URL?{PHASE2_ASP_PONDER_URL:env.PHASE2_ASP_PONDER_URL,PHASE2_ASP_PONDER_MODE:'logs',PHASE2_ASP_PONDER_FALLBACK:'rpc'}:{};
}
function mainnetOperatorLogClient(rpcClient,profiles,baseURL){
  const byAddress=new Map();
  for(const profile of profiles){
    const source=createPhase2PonderClient({client:rpcClient,profile,baseURL,mode:'logs',fallbackToRpc:true});
    byAddress.set(profile.pool.address.toLowerCase(),source);
    // The shared registry uses one wrapper, so an unavailable indexer produces
    // one bounded attempt before RPC fallback rather than nine nested attempts.
    if(!byAddress.has(profile.registry.address.toLowerCase()))byAddress.set(profile.registry.address.toLowerCase(),source);
  }
  const wrapped=Object.create(rpcClient);
  wrapped.getLogs=options=>(typeof options?.address==='string'?byAddress.get(options.address.toLowerCase()):null)?.getLogs(options)??rpcClient.getLogs(options);
  return wrapped;
}
function signerSettings(value){
  exact(value,['address','enabled','budgetWei','maxFeePerGasWei','reserveWei','maxGas'],'MAINNET_CONTAINER_SIGNER_CONFIG_INVALID');
  need(value.address===null||isAddress(value.address)&&!/^0x0{40}$/i.test(value.address),'MAINNET_CONTAINER_SIGNER_ADDRESS_INVALID');
  need(typeof value.enabled==='boolean'&&quantity(value.maxGas)&&BigInt(value.maxGas)<=5000000n,'MAINNET_CONTAINER_SIGNER_CONFIG_INVALID');
  need([value.budgetWei,value.maxFeePerGasWei,value.reserveWei].every(v=>v===null)
    ||quantity(value.budgetWei)&&quantity(value.maxFeePerGasWei)&&quantity(value.reserveWei,{zero:true}),'MAINNET_CONTAINER_EXPLICIT_BUDGET_REQUIRED');
  need(!value.enabled||value.address&&value.budgetWei!==null,'MAINNET_CONTAINER_EXPLICIT_BUDGET_REQUIRED');
}

/** Environment flags can enable only a role already explicitly enabled in the file. */
export function planMainnetRuntime(config,{role='api',poolId='eth',signingFlag='0'}={}){
  exact(config,['schema','chainId','rpcUrl','governanceSafe','profileFile','poolIds','relay','asp','publisher','network','serviceFeesFile','feeArtifactsFile'],'MAINNET_CONTAINER_CONFIG_INVALID');
  need(config.schema==='lincoln-mainnet-container/v1'&&config.chainId===4663&&config.rpcUrl===MAINNET_RPC,'MAINNET_CONTAINER_WRONG_NETWORK');
  need(sameAddress(config.governanceSafe,MAINNET_SAFE),'MAINNET_CONTAINER_SAFE_MISMATCH');
  need(fileName(config.profileFile),'MAINNET_CONTAINER_PROFILE_PATH_INVALID');
  need(Array.isArray(config.poolIds)&&config.poolIds.length>0&&config.poolIds.length<=32&&new Set(config.poolIds).size===config.poolIds.length
    &&config.poolIds.every(id=>typeof id==='string'&&/^[a-z][a-z0-9_-]{0,63}$/.test(id)),'MAINNET_CONTAINER_POOL_IDS_INVALID');
  need(['api','asp'].includes(role)&&['0','1'].includes(signingFlag),'MAINNET_CONTAINER_ROLE_OR_FLAG_INVALID');
  need(role!=='api'||config.poolIds.includes(poolId),'MAINNET_CONTAINER_POOL_NOT_CONFIGURED');
  signerSettings(config.relay);signerSettings(config.asp);
  // A shared hot address must have exactly one immutable fee policy across roles.
  if(config.relay.address&&sameAddress(config.relay.address,config.asp.address))
    need(['budgetWei','maxFeePerGasWei','reserveWei'].every(k=>config.relay[k]===config.asp[k]),'MAINNET_CONTAINER_SHARED_SIGNER_POLICY_MISMATCH');
  exact(config.publisher,['policy','originScreening','intervalSeconds','publication'],'MAINNET_CONTAINER_PUBLISHER_CONFIG_INVALID');
  need(config.publisher.policy==='all-current-notes'&&config.publisher.originScreening===false,'MAINNET_CONTAINER_UNSUPPORTED_ASP_POLICY');
  need(Number.isSafeInteger(config.publisher.intervalSeconds)&&config.publisher.intervalSeconds>=5&&config.publisher.intervalSeconds<=86400,'MAINNET_CONTAINER_PUBLISHER_CONFIG_INVALID');
  exact(config.publisher.publication,Object.keys(DEFAULT_ASP_OPERATOR_POLICY),'MAINNET_CONTAINER_PUBLISHER_POLICY_INVALID');
  const policy=config.publisher.publication;
  need(Object.values(policy).every(Number.isSafeInteger)&&policy.lifetimeSeconds>0&&policy.lifetimeSeconds<=30*86400&&policy.renewalWindowSeconds>0
    &&policy.renewalWindowSeconds<policy.lifetimeSeconds&&policy.minPublishIntervalSeconds>0&&policy.minPublishIntervalSeconds<policy.lifetimeSeconds
    &&policy.confirmations>=0&&policy.confirmations<=1024&&policy.maxCommitments>0&&policy.maxCommitments<=2**20,'MAINNET_CONTAINER_PUBLISHER_POLICY_INVALID');
  exact(config.network,['allowedHosts','allowedOrigins'],'MAINNET_CONTAINER_NETWORK_CONFIG_INVALID');
  need(['allowedHosts','allowedOrigins'].every(k=>Array.isArray(config.network[k])&&config.network[k].every(v=>typeof v==='string'&&!v.includes(','))),'MAINNET_CONTAINER_NETWORK_CONFIG_INVALID');
  createNetworkPolicy({PHASE1_ALLOWED_HOSTS:config.network.allowedHosts.length?config.network.allowedHosts.join(','):undefined,PHASE1_ALLOWED_ORIGINS:config.network.allowedOrigins.length?config.network.allowedOrigins.join(','):undefined});
  mainnetServiceFeeFile(config,role==='api'?poolId:config.poolIds[0]);
  need(config.feeArtifactsFile===null||fileName(config.feeArtifactsFile),'MAINNET_CONTAINER_FEE_PATH_INVALID');
  const settings=config[role==='api'?'relay':'asp'],signingEnabled=signingFlag==='1';
  need(!signingEnabled||settings.enabled&&settings.address&&settings.budgetWei!==null,'MAINNET_CONTAINER_SIGNING_NOT_AUTHORIZED');
  return {schema:'lincoln-mainnet-container-plan/v1',chainId:4663,role,poolId:role==='api'?poolId:null,root:MAINNET_CONTAINER_ROOT,
    profileFile:`${MAINNET_CONFIG}/${config.profileFile}`,stateDirectory:role==='api'?`${MAINNET_STATE}/api/${poolId}`:`${MAINNET_STATE}/asp/operator`,
    // All pools and ASP share this mount. The signer appends the address key.
    signerDirectoryRoot:`${MAINNET_STATE}/signers`,associationDirectory:`${MAINNET_STATE}/asp/public`,
    signingEnabled,address:settings.address,budgetWei:settings.budgetWei,maxFeePerGasWei:settings.maxFeePerGasWei,reserveWei:settings.reserveWei,maxGas:settings.maxGas,
    keystoreFile:signingEnabled?`/run/secrets/mainnet-${role==='api'?'relay':'provider'}.keystore.json`:null,
    passwordFile:signingEnabled?`/run/secrets/mainnet-${role==='api'?'relay':'provider'}.password`:null,
    productionVerificationRequired:true,automaticResend:false,transactionsBroadcast:0};
}

async function regularJSON(filename){
  const handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await handle.stat();need(stat.isFile()&&stat.size<=8*1024*1024&&await fs.realpath(filename)===filename,'MAINNET_CONTAINER_REGULAR_CONFIG_REQUIRED');return JSON.parse(await handle.readFile('utf8'));}
  finally{await handle.close();}
}
export function validateMainnetProfiles(deployed,config){
  need(deployed&&Object.getPrototypeOf(deployed.profiles)===Object.prototype,'MAINNET_CONTAINER_DEPLOYED_PROFILES_REQUIRED');
  const profiles=config.poolIds.map(id=>{
    const profile=deployed.profiles[id];normalizeProfile(profile);
    need(profile.schema===PRODUCTION_PROFILE_SCHEMA&&profile.chain.id===4663&&profile.chain.rpcUrl===MAINNET_RPC,'MAINNET_CONTAINER_PRODUCTION_PROFILE_REQUIRED');
    need(config.asp.address&&sameAddress(profile.registry.provider,config.asp.address),'MAINNET_CONTAINER_PROVIDER_PROFILE_MISMATCH');
    // A deployment without an assigned relayer can be inspected before choosing
    // a hot wallet. It must carry no relay signing permission or ledger policy.
    // planMainnetRuntime also rejects a signing flag for this configuration.
    if(profile.relayer===null)need(config.relay.address===null&&config.relay.enabled===false
      &&['budgetWei','maxFeePerGasWei','reserveWei'].every(k=>config.relay[k]===null),'MAINNET_CONTAINER_UNASSIGNED_RELAY_READ_ONLY_REQUIRED');
    else need(config.relay.address&&sameAddress(profile.relayer,config.relay.address),'MAINNET_CONTAINER_RELAY_PROFILE_MISMATCH');
    return profile;
  });
  const first=profiles[0];
  need(profiles.every(p=>p.genesisHash===first.genesisHash&&p.artifactSHA256===first.artifactSHA256
    &&sameAddress(p.registry.address,first.registry.address)&&p.registry.runtimeCodeHash===first.registry.runtimeCodeHash
    &&String(p.registry.startBlock)===String(first.registry.startBlock)),'MAINNET_CONTAINER_SHARED_RELEASE_MISMATCH');
  return profiles;
}

// Recheck exact registry state while createMainnetSigner holds the address lock.
export async function assertMainnetPublicationExpectation({client,profile,registryABI,policy}){
  need(policy?.previousPolicy&&/^(0|[1-9][0-9]*)$/.test(policy.expectedEpoch??'')&&/^(0|[1-9][0-9]*)$/.test(policy.validUntil??''),'MAINNET_CONTAINER_ASP_EXPECTATION_REQUIRED');
  const [latest,cidDigest,provider,block]=await Promise.all([
    client.readContract({address:profile.registry.address,abi:registryABI,functionName:'latestPolicy',blockTag:'latest'}),
    client.readContract({address:profile.registry.address,abi:registryABI,functionName:'cidDigest',blockTag:'latest'}),
    client.readContract({address:profile.registry.address,abi:registryABI,functionName:'PROVIDER',blockTag:'latest'}),client.getBlock({blockTag:'latest'})]);
  const prior=policy.previousPolicy;
  need(String(latest[0])===prior.root&&String(latest[1])===prior.epoch&&String(latest[2])===prior.validUntil&&sameAddress(cidDigest,prior.cidDigest)
    &&sameAddress(provider,profile.registry.provider)&&BigInt(policy.expectedEpoch)===BigInt(latest[1])+1n,'MAINNET_CONTAINER_ASP_REGISTRY_CHANGED');
  need(BigInt(policy.validUntil)>block.timestamp&&BigInt(policy.validUntil)<=block.timestamp+30n*86400n,'MAINNET_CONTAINER_ASP_PUBLICATION_EXPIRED');
}

export function mainnetPublisherSigner({client,profile,artifacts,plan,signerFactory=createMainnetSigner}){
  need(plan.signingEnabled&&sameAddress(plan.address,profile.registry.provider),'MAINNET_CONTAINER_PROVIDER_PROFILE_MISMATCH');
  const policies=new Map(),abi=artifacts.Phase2ASPRegistry.abi;
  const base=signerFactory({client,root:MAINNET_CONTAINER_ROOT,address:plan.address,keystoreFile:plan.keystoreFile,passwordFile:plan.passwordFile,
    budgetWei:plan.budgetWei,maxFeePerGasWei:plan.maxFeePerGasWei,reserveWei:plan.reserveWei,expectedGenesisHash:profile.genesisHash,
    beforeBroadcast:async entry=>{
      need(entry.chainId===4663&&sameAddress(entry.to,profile.registry.address)&&quantity(entry.gas)&&BigInt(entry.gas)<=BigInt(plan.maxGas),'MAINNET_CONTAINER_PROVIDER_GAS_OR_TARGET_MISMATCH');
      return assertMainnetPublicationExpectation({client,profile,registryABI:abi,policy:policies.get(entry.id)});
    }});
  return {...base,async prepare(intent){
    need(/^asp-[a-f0-9]{64}$/.test(intent?.id??'')&&intent.chainId===4663&&sameAddress(intent.from,plan.address)
      &&sameAddress(intent.to,profile.registry.address)&&intent.value==='0','MAINNET_CONTAINER_PROVIDER_REGISTRY_ONLY');
    const decoded=decodeFunctionData({abi,data:intent.data});
    need(decoded.functionName==='updateRoot'&&encodeFunctionData({abi,...decoded}).toLowerCase()===intent.data.toLowerCase()
      &&String(decoded.args[2])===intent.aspPolicy?.validUntil,'MAINNET_CONTAINER_PROVIDER_REGISTRY_ONLY');
    await assertMainnetPublicationExpectation({client,profile,registryABI:abi,policy:intent.aspPolicy});
    const estimate=await client.estimateGas({account:plan.address,to:intent.to,data:intent.data,value:0n}),gas=estimate*12n/10n+10000n;
    need(gas>0n&&gas<=BigInt(plan.maxGas),'MAINNET_CONTAINER_PROVIDER_GAS_LIMIT');
    policies.set(intent.id,structuredClone(intent.aspPolicy));
    const reservation=await base.prepare({...intent,gas:String(gas)});
    need(quantity(reservation.gas)&&BigInt(reservation.gas)<=BigInt(plan.maxGas),'MAINNET_CONTAINER_PROVIDER_GAS_LIMIT');
    return reservation;
  }};
}

function mainnetAPIEnvironment(config,plan,{poolId,apiPort,rpcEnv,indexerEnv}){
  const runtimeEnv={PHASE2_MAINNET_ROOT:MAINNET_CONTAINER_ROOT,PHASE2_MAINNET_PROFILE_PATH:plan.profileFile,PHASE2_MAINNET_POOL_ID:poolId,
    PHASE2_MAINNET_HOST:'0.0.0.0',PHASE2_MAINNET_PORT:String(apiPort),PHASE2_MAINNET_STATE_DIR:plan.stateDirectory,
    PHASE2_MAINNET_SIGNING_ENABLED:plan.signingEnabled?'1':'0',PHASE2_MAINNET_MAX_GAS:plan.maxGas,
    PHASE2_MAINNET_ALLOWED_HOSTS:config.network.allowedHosts.length?config.network.allowedHosts.join(','):undefined,PHASE2_MAINNET_ALLOWED_ORIGINS:config.network.allowedOrigins.length?config.network.allowedOrigins.join(','):undefined,
    PHASE2_MAINNET_ASSOCIATION_SET_FILE:`${plan.associationDirectory}/current.json`,PHASE2_MAINNET_PUBLISHER_STATUS_FILE:`${plan.associationDirectory}/publisher-heartbeat.json`,
    PHASE2_MAINNET_MIN_PUBLISH_INTERVAL_SECONDS:String(config.publisher.publication.minPublishIntervalSeconds),...rpcEnv,...indexerEnv,...mainnetContainerMirrorEnvironment(process.env),...mainnetContainerPointsEnvironment(process.env)};
  if(plan.budgetWei!==null)Object.assign(runtimeEnv,{PHASE2_MAINNET_GAS_BUDGET_WEI:plan.budgetWei,PHASE2_MAINNET_MAX_FEE_PER_GAS_WEI:plan.maxFeePerGasWei,PHASE2_MAINNET_RESERVE_WEI:plan.reserveWei});
  if(plan.signingEnabled)Object.assign(runtimeEnv,{PHASE2_MAINNET_KEYSTORE_FILE:plan.keystoreFile,PHASE2_MAINNET_PASSWORD_FILE:plan.passwordFile});
  const serviceFeesFile=mainnetServiceFeeFile(config,poolId);
  if(serviceFeesFile)runtimeEnv.PHASE2_MAINNET_SERVICE_FEES_FILE=`${MAINNET_CONFIG}/${serviceFeesFile}`;
  if(config.feeArtifactsFile)runtimeEnv.PHASE2_MAINNET_FEE_ARTIFACTS_PATH=`${MAINNET_CONFIG}/${config.feeArtifactsFile}`;
  return runtimeEnv;
}

/** Public inputs only. Never opens a client, business store, listener or wallet.
 * There is no persistent "verified" flag: activation re-reads the same inputs.
 */
export async function prepareMainnetContainer({role='apis',poolId='eth',env=process.env,apiPort=8797,preparationScope}={}){
  if(preparationScope===undefined)return withMainnetRuntimePreparation(scope=>prepareMainnetContainer({role,poolId,env,apiPort,preparationScope:scope}));
  const config=await regularJSON(`${MAINNET_CONFIG}/runtime.json`),rpcEnv=mainnetContainerRPCEnvironment(env),indexerEnv=mainnetContainerIndexerEnvironment(env);
  need(['apis','api','asp'].includes(role),'MAINNET_CONTAINER_ROLE_OR_FLAG_INVALID');
  const ids=role==='api'?[poolId]:config.poolIds;
  const plans=ids.map(id=>planMainnetRuntime(config,{role:role==='asp'?'asp':'api',poolId:id,signingFlag:env.LINCOLN_MAINNET_SIGNING_ENABLED??'0'}));
  const deployed=await regularJSON(plans[0].profileFile),profiles=validateMainnetProfiles(deployed,config);
  const units=[];
  if(role==='asp')for(const profile of profiles)await loadProductionRelease({rootDirectory:MAINNET_CONTAINER_ROOT,profile});
  else for(const [index,id]of ids.entries()){
    const runtimeEnv=mainnetAPIEnvironment(config,plans[index],{poolId:id,apiPort:apiPort+index,rpcEnv,indexerEnv});
    units.push({plan:plans[index],runtimeEnv,ticket:await prepareMainnetASPRuntime(runtimeEnv,{preparationScope})});
  }
  return {config,plans,units,configurationSHA256:(await readMainnetConfigurationDigest(MAINNET_CONFIG)).configurationSHA256};
}

const EXCLUSIVE_GATED_API_STARTUP=Symbol('exclusive-gated-api-startup');
async function activatePreparedAPIs(prepared,{role,apiPort,startupAuthority}={}){
  const runtimes=[];
  // This private capability is supplied only after the root-controlled handoff
  // grant, stopped-writer quiescence check and unique runtime writer lease. A
  // normal boot/environment flag cannot enable startup reconciliation reuse.
  const executorGroup=createMainnetAPIExecutorGroup({startupMemo:startupAuthority===EXCLUSIVE_GATED_API_STARTUP});
  try{
    // All profiles were independently pinned before this gate. Reuse the same
    // validated read-only transport so bounded canonical-header reads can be
    // shared across pool wrappers; signer stores and pool identities stay local.
    need(prepared.units.length>0,'MAINNET_CONTAINER_API_UNITS_REQUIRED');
    const client=await createMainnetRuntimeClient({env:prepared.units[0].runtimeEnv});
    for(const unit of prepared.units){
      const service=await startMainnetASPRuntime(unit.runtimeEnv,{preparedRuntime:unit.ticket,client,executorGroup});
      runtimes.push({plan:unit.plan,service,close:()=>service.close()});
    }
    if(role==='api')return runtimes[0];
    return {plan:{...prepared.plans[0],role:'apis',poolId:null,poolIds:[...prepared.config.poolIds],listeners:prepared.config.poolIds.map((id,index)=>({poolId:id,port:apiPort+index}))},runtimes,
      async close(){const closed=await Promise.allSettled(runtimes.map(runtime=>runtime.close()));need(closed.every(result=>result.status==='fulfilled'),'MAINNET_CONTAINER_GROUP_CLOSE_FAILED');}};
  }catch(error){await Promise.allSettled(runtimes.map(runtime=>runtime.close()));throw error;}
  finally{finishMainnetAPIExecutorGroup(executorGroup);}
}

export async function startMainnetContainer({role='api',poolId='eth',env=process.env,signal,onResult=summary=>console.log(JSON.stringify(summary)),apiPort=8797,activationHandled=false}={}){
  need(env.LINCOLN_MAINNET_ACTIVATION_REQUIRED===undefined||['0','1'].includes(env.LINCOLN_MAINNET_ACTIVATION_REQUIRED),'MAINNET_ACTIVATION_FLAG_INVALID');
  if(env.LINCOLN_MAINNET_ACTIVATION_REQUIRED==='1'&&!activationHandled){
    const before=await readMainnetConfigurationDigest(MAINNET_CONFIG);
    need(/^[a-f0-9]{64}$/.test(env.LINCOLN_MAINNET_RELEASE_SHA256??''),'MAINNET_ACTIVATION_RELEASE_REQUIRED');
    const control=await readMainnetActivationRequest({role,configurationSHA256:before.configurationSHA256});
    need(control.request.releaseSHA256===env.LINCOLN_MAINNET_RELEASE_SHA256,'MAINNET_ACTIVATION_RELEASE_MISMATCH');
    const prepared=await prepareMainnetContainer({role,poolId,env,apiPort});
    need(prepared.configurationSHA256===before.configurationSHA256,'MAINNET_ACTIVATION_CONFIG_CHANGED');
    // A distinct empty transaction waits for the root gate. No warm ticket or
    // public-file memo crosses this boundary. Only gate-time fresh tickets are
    // consumed before this callback closes and invalidates its authority.
    return withMainnetRuntimePreparation(async preparationScope=>{
      let current;
      const activation=await waitForMainnetActivation({...control,signal,onPrepared:value=>onResult({service:'lincoln-mainnet-candidate',...value,signingEnabled:false,businessStoresOpened:false,walletsRead:false}),
        verifyInputs:async()=>{
          current=await prepareMainnetContainer({role,poolId,env,apiPort,preparationScope});
          need(current.configurationSHA256===before.configurationSHA256,'MAINNET_ACTIVATION_CONFIG_CHANGED');
          await assertMainnetRoleQuiescent({role,stateDirectory:MAINNET_STATE,poolIds:role==='api'?[poolId]:current.config.poolIds,address:current.plans[0].address,
            initialPoolIds:control.request.appendMigration?.initializePoolIds??[]});
        }});
      const lease=await acquireMainnetWriterLease({role,stateDirectory:MAINNET_STATE,preparedSHA256:activation.preparedSHA256});
      try{
        const runtime=role==='asp'?await startMainnetContainer({role,poolId,env,signal,onResult,apiPort,activationHandled:true}):await activatePreparedAPIs(current,{role,apiPort,startupAuthority:EXCLUSIVE_GATED_API_STARTUP});
        let closePromise;
        const close=()=>closePromise??=(async()=>{try{await runtime.close();}finally{await lease.close();}})();
        return {...runtime,close,...(runtime.run?{async run(){try{return await runtime.run();}finally{await close();}}}:{})};
      }catch(error){await lease.close();throw error;}
    });
  }

  // Fixed mount locations prevent environment overrides from reusing testnet data.
  const config=await regularJSON(`${MAINNET_CONFIG}/runtime.json`);
  if(role==='apis'){
    need(Number.isSafeInteger(apiPort)&&apiPort>=1024&&apiPort+config.poolIds.length-1<=65535,'MAINNET_CONTAINER_API_PORT_INVALID');
    return withMainnetRuntimePreparation(async preparationScope=>{
      const prepared=await prepareMainnetContainer({role,poolId,env,apiPort,preparationScope});
      return activatePreparedAPIs(prepared,{role,apiPort});
    });
  }
  const plan=planMainnetRuntime(config,{role,poolId,signingFlag:env.LINCOLN_MAINNET_SIGNING_ENABLED??'0'});
  const deployed=await regularJSON(plan.profileFile),profiles=validateMainnetProfiles(deployed,config);
  const rpcEnv=mainnetContainerRPCEnvironment(env),indexerEnv=mainnetContainerIndexerEnvironment(env);
  if(role==='api'){
    const runtimeEnv=mainnetAPIEnvironment(config,plan,{poolId,apiPort,rpcEnv,indexerEnv});
    const service=await startMainnetASPRuntime(runtimeEnv);
    return {plan,close:()=>service.close(),service};
  }
  // Full verification finishes before constructing the operator or signer.
  // Check every profile in full, but avoid retaining two copies of large proving
  // parameters while verifying the second pool. The process-local verifier cache
  // remains content-bound; this does not persist or bypass a verification result.
  let artifacts;
  for(const profile of profiles){
    const release=await loadProductionRelease({rootDirectory:MAINNET_CONTAINER_ROOT,profile});
    artifacts??=release.artifacts;
  }
  const rpcClient=await createMainnetRuntimeClient({env:rpcEnv,expectedGenesisHash:profiles[0].genesisHash});
  // Wrap only known pool/registry log ranges. Receipt, state and signer reads
  // retain independent RPC validation; temporary indexer lag falls back to RPC.
  const client=indexerEnv.PHASE2_ASP_PONDER_URL?mainnetOperatorLogClient(rpcClient,profiles,indexerEnv.PHASE2_ASP_PONDER_URL):rpcClient;
  let operator,signer;
  try{
    operator=await createASPOperator({profiles,requiredPools:profiles.map(p=>p.pool.address),artifacts,client,directory:plan.stateDirectory,policy:config.publisher.publication});
    if(plan.signingEnabled)signer=mainnetPublisherSigner({client,profile:profiles[0],artifacts,plan});
    // Same fixed secret mount as canonical HTTP; URL remains closure-private.
    // Plans/telemetry/config never serialize the credential-bearing endpoint.
    const eventSource=createASPEventSource({rpcURL:(await resolveMainnetRPC({env:rpcEnv})).url,profiles});
    const publisher=createASPPublisher({operator,signer,eventSource,signingEnabled:plan.signingEnabled,outputDirectory:plan.associationDirectory,activeFile:'current.json',
      intervalSeconds:config.publisher.intervalSeconds,minPublishIntervalSeconds:config.publisher.publication.minPublishIntervalSeconds,
      identity:{chainId:4663,registry:profiles[0].registry.address},heartbeatEnabled:true,onResult});
    return {plan,publisher,async run(){try{return await publisher.run({signal});}finally{await signer?.close?.();await operator.close();await rpcClient.close?.();}},
      async close(){await publisher.stop();await signer?.close?.();await operator.close();await rpcClient.close?.();}};
  }catch(error){await signer?.close?.();await operator?.close();await rpcClient.close?.();throw error;}
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [role='plan',poolId='eth',...extra]=process.argv.slice(2),aborter=new AbortController();
  for(const s of ['SIGINT','SIGTERM'])process.once(s,()=>aborter.abort());
  try{
    need(extra.length===0,'MAINNET_CONTAINER_ARGUMENTS_INVALID');
    if(role==='plan')console.log(JSON.stringify(planMainnetRuntime(await regularJSON(poolId==='eth'?`${MAINNET_CONFIG}/runtime.json`:path.resolve(poolId))),null,2));
    else{
      const runtime=await startMainnetContainer({role,poolId,signal:aborter.signal});
      console.log(JSON.stringify({service:`lincoln-mainnet-${role}`,chainId:4663,signingEnabled:runtime.plan.signingEnabled,readOnly:!runtime.plan.signingEnabled,
        ...(runtime.plan.listeners?{listeners:runtime.plan.listeners}:{}),releaseVerified:true,productionReady:false}));
      if(role==='asp')await runtime.run();else if(aborter.signal.aborted)await runtime.close();else aborter.signal.addEventListener('abort',()=>runtime.close().catch(()=>{process.exitCode=1;}),{once:true});
    }
  }catch(error){const code=error.code??error.message;console.error(JSON.stringify({error:/^[A-Z][A-Z0-9_]{1,100}$/.test(code)?code:'MAINNET_CONTAINER_STARTUP_FAILED',automaticResend:false}));process.exitCode=1;}
}
