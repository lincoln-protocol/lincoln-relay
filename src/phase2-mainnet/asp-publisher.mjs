// SPDX-License-Identifier: Apache-2.0
// Small single-writer ASP scheduler. Signing is an explicitly injected adapter.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { BlockNotFoundError, TransactionNotFoundError, TransactionReceiptNotFoundError } from 'viem';
import {publisherHeartbeat} from '../phase2-asp/publisher-status.mjs';
import {ASP_PUBLICATION_EVENT_FILE} from './asp-event-source.mjs';
import {acceptedAssociationPolicy} from '../phase2-asp/association-policy.mjs';

const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { code }); };
const clone = value => structuredClone(value);
const digest = value => typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value);
const SIGNER_BUSY_CODES=new Set(['DEPLOYMENT_OR_SPENDING_LOCKED_NO_AUTOMATIC_STALE_LOCK_REMOVAL','SPENDING_LEDGER_LOCKED','SHARED_TESTNET_BUDGET_LOCKED']);
function signerBusy(error){
  for(let depth=0,cause=error;cause&&depth<5;depth++,cause=cause.cause)
    if(SIGNER_BUSY_CODES.has(cause.code??cause.message))return true;
  return false;
}
function retryableTransport(error) {
  for (let depth = 0, cause = error; cause && depth < 5; depth++, cause = cause.cause) {
    // Load-balanced RPC nodes can briefly disagree about a numbered snapshot
    // block/transaction/receipt. Retry the next full reconciliation tick; a
    // durably signed hash still forbids another signature or broadcast.
    if (cause instanceof BlockNotFoundError || cause instanceof TransactionNotFoundError || cause instanceof TransactionReceiptNotFoundError) return true;
    if (/^(HttpRequestError|TimeoutError|SocketError|FetchError)$/.test(cause.name ?? '')
      || /^(ECONNRESET|ETIMEDOUT|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|UND_ERR_CONNECT_TIMEOUT|MAINNET_RECEIPT_LOOKUP_FAILED)$/.test(cause.code ?? '')) return true;
  }
  return false;
}

async function readJSON(filename) {
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { const st = await handle.stat(); check(st.isFile() && st.size <= 32 * 1024 * 1024, 'INVALID_ASP_PUBLICATION_FILE'); return JSON.parse(await handle.readFile('utf8')); }
  finally { await handle.close(); }
}
async function atomicJSON(filename, value) {
  try { check((await fs.lstat(filename)).isFile() && await fs.realpath(filename) === filename, 'INVALID_ASP_PUBLICATION_FILE'); }
  catch (e) { if (e.code !== 'ENOENT') throw e; }
  const temporary = path.join(path.dirname(filename), `.asp-${randomBytes(12).toString('hex')}.tmp`);
  let handle;
  try {
    handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    await handle.writeFile(JSON.stringify(value, null, 2) + '\n'); await handle.sync(); await handle.close(); handle = null;
    await fs.rename(temporary, filename);
    const directory = await fs.open(path.dirname(filename), constants.O_RDONLY | constants.O_DIRECTORY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally { await handle?.close(); await fs.unlink(temporary).catch(e => { if (e.code !== 'ENOENT') throw e; }); }
}

async function publicationDirectory(directory) {
  directory = path.resolve(directory); await fs.mkdir(directory, { recursive: true, mode: 0o755 });
  check(await fs.realpath(directory) === directory && (await fs.lstat(directory)).isDirectory(), 'INVALID_ASP_PUBLICATION_DIRECTORY');
  return directory;
}
/** The immutable per-digest document. Written before a broadcast so mirrors can
 * copy the proposal before its root is live; identical bytes are never rewritten. */
export async function writeAssociationSetDocument({ associationSet, directory }) {
  check(digest(associationSet?.digest) && Array.isArray(associationSet.leaves), 'INVALID_ASP_PUBLICATION_RESULT');
  directory = await publicationDirectory(directory);
  const setFile = path.join(directory, `association-set-${associationSet.digest.slice(2).toLowerCase()}.json`);
  let existing;
  try { existing = await readJSON(setFile); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (existing) {
    check(existing.root === associationSet.root && existing.digest === associationSet.digest && existing.chainId === associationSet.chainId && existing.registry === associationSet.registry && JSON.stringify(existing.leaves) === JSON.stringify(associationSet.leaves), 'ASP_IMMUTABLE_SET_MISMATCH');
  } else await atomicJSON(setFile, associationSet);
  return setFile;
}
/** Only the operator's pinned, canonical registry snapshot may activate a set. */
export async function writeASPPublication({ result, directory, activeFile = 'active-association-set.json' }) {
  check(result?.schema === 'phase2-asp-operator-result/v1' && digest(result.associationSet?.digest), 'INVALID_ASP_PUBLICATION_RESULT');
  check(typeof activeFile === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]*\.json$/.test(activeFile), 'INVALID_ASP_ACTIVE_FILENAME');
  directory = await publicationDirectory(directory);
  const setFile = await writeAssociationSetDocument({ associationSet: result.associationSet, directory });
  const activePath = path.join(directory, activeFile), active = result.activeAssociationSet;
  if (active) {
    const activePolicy=acceptedAssociationPolicy(result.currentPolicy,active,result.chainTimestamp);
    check(activePolicy&&active.registry===result.associationSet.registry&&active.chainId===result.associationSet.chainId,
      'ASP_ACTIVE_SET_NOT_CHAIN_CONFIRMED');
    if(result.activePolicy)check(JSON.stringify(activePolicy)===JSON.stringify(result.activePolicy),'ASP_ACTIVE_SET_POLICY_MISMATCH');
    // Unlike association-set-* (which may be a pending proposal), this archive
    // is created only for an already confirmed, accepted active publication.
    const confirmedPath=path.join(directory,`confirmed-association-set-${active.digest.slice(2).toLowerCase()}.json`);
    let confirmed;try{confirmed=await readJSON(confirmedPath);}catch(error){if(error.code!=='ENOENT')throw error;}
    if(confirmed)check(confirmed.root===active.root&&confirmed.digest===active.digest&&confirmed.chainId===active.chainId
      &&confirmed.registry===active.registry&&JSON.stringify(confirmed.leaves)===JSON.stringify(active.leaves),'ASP_CONFIRMED_ARCHIVE_MISMATCH');
    else await atomicJSON(confirmedPath,active);
    await atomicJSON(activePath, active);
    // Written only AFTER the confirmed active set is readable. APIs independently
    // match current.json and their canonical pool snapshot before emitting SSE.
    if (activePolicy.epoch===result.currentPolicy.epoch&&!result.currentPolicy.expired && typeof result.lastPublicationTimestamp === 'string'
      && /^(0|[1-9][0-9]{0,77})$/.test(result.lastPublicationTimestamp)) {
      check(Array.isArray(active.pools) && active.pools.length > 0 && active.pools.length <= 32, 'ASP_EVENT_ROSTER_INVALID');
      await atomicJSON(path.join(directory, ASP_PUBLICATION_EVENT_FILE), {
        schema:'phase2-asp-confirmed-publication/v1',chainId:active.chainId,registry:active.registry,
        epoch:activePolicy.epoch,root:active.root,validUntil:activePolicy.validUntil,
        cidDigest:active.digest,lastPublicationTimestamp:result.lastPublicationTimestamp,activeFile,
        pools:active.pools.map(({pool,scope})=>({pool,scope}))
      });
    } else if(activePolicy.epoch===result.currentPolicy.epoch)await removePublicationEvent(directory);
  } else {
    await removePublicationEvent(directory);
    // Retain historical data, never its authority. APIs bind it to their current
    // canonical acceptedPolicy and reject expired/revoked/rotated epochs.
  }
  await atomicJSON(path.join(directory, 'publisher-status.json'), result);
  return { associationSet: setFile, activeAssociationSet: active ? activePath : null };
}

async function removePublicationEvent(directory) {
  const filename=path.join(directory,ASP_PUBLICATION_EVENT_FILE);
  try { const st=await fs.lstat(filename);check(st.isFile()&&!st.isSymbolicLink(),'INVALID_ASP_PUBLICATION_FILE');await fs.unlink(filename); }
  catch(error){if(error.code!=='ENOENT')throw error;}
}

async function deactivatePublication({ directory, activeFile = 'active-association-set.json' }) {
  check(/^[a-zA-Z0-9][a-zA-Z0-9._-]*\.json$/.test(activeFile), 'INVALID_ASP_ACTIVE_FILENAME');
  directory = path.resolve(directory);
  try { check(await fs.realpath(directory) === directory, 'INVALID_ASP_PUBLICATION_DIRECTORY'); }
  catch (e) { if (e.code === 'ENOENT') return; throw e; }
  await removePublicationEvent(directory);
  const filename = path.join(directory, activeFile);
  try { const st = await fs.lstat(filename); check(st.isFile() && !st.isSymbolicLink(), 'INVALID_ASP_PUBLICATION_FILE'); await fs.unlink(filename); }
  catch (e) { if (e.code !== 'ENOENT') throw e; }
}

/** No timer, wallet, or network is opened merely by importing this module. */
export function createASPPublisher({ operator, signer = null, signingEnabled = false, outputDirectory, activeFile, mirrors = [], intervalSeconds = 60,
  eventIdleIntervalSeconds = 30, minPublishIntervalSeconds = 900, identity = null, heartbeatEnabled = signingEnabled, now = Date.now, eventSource = null, onResult = async () => {} }) {
  check(operator && ['prepare', 'status', 'sendPrepared', 'recordHash'].every(k => typeof operator[k] === 'function'), 'ASP_OPERATOR_REQUIRED');
  check(typeof signingEnabled === 'boolean' && Number.isSafeInteger(intervalSeconds) && intervalSeconds >= 5 && intervalSeconds <= 86400, 'INVALID_ASP_PUBLISHER_SETTINGS');
  check(Number.isSafeInteger(eventIdleIntervalSeconds) && eventIdleIntervalSeconds >= 5 && eventIdleIntervalSeconds <= 3600, 'INVALID_ASP_PUBLISHER_SETTINGS');
  check(!signingEnabled || signer && ['prepare', 'broadcast', 'recoverHash', 'reconcile', 'cancelPrepared'].every(k => typeof signer[k] === 'function'), 'EXPLICIT_ASP_SIGNER_REQUIRED');
  check(Array.isArray(mirrors) && mirrors.length <= 4 && mirrors.every(m => typeof m?.directory === 'string'), 'INVALID_ASP_PUBLICATION_MIRRORS');
  check(Number.isSafeInteger(minPublishIntervalSeconds)&&minPublishIntervalSeconds>0&&minPublishIntervalSeconds<=30*86400&&typeof heartbeatEnabled==='boolean'&&typeof now==='function','INVALID_ASP_PUBLISHER_SETTINGS');
  check(eventSource===null||typeof eventSource.start==='function'&&typeof eventSource.close==='function','INVALID_ASP_EVENT_SOURCE');
  const heartbeatIntervalSeconds=Math.min(15,Math.max(1,Math.floor(intervalSeconds/2)));
  // The sender ledger is audited in full on the first tick, after any failed
  // tick, and at least hourly; other ticks follow only its live entries.
  const FULL_SENDER_RECONCILE_MS=3600000;let lastFullSenderReconcile=null;
  let publicIdentity=identity,observation={status:'unknown',reason:'ASP_PUBLISHER_STARTING'},heartbeatTail=Promise.resolve(),heartbeatBusy=false,enteredBroadcast=false;
  if(identity)publisherHeartbeat({...identity,...observation,checkedAt:new Date(now()).toISOString(),pollIntervalSeconds:intervalSeconds,heartbeatIntervalSeconds,minPublishIntervalSeconds});
  async function heartbeat(){
    if(!heartbeatEnabled||!publicIdentity)return;
    const record=publisherHeartbeat({...publicIdentity,...observation,checkedAt:new Date(now()).toISOString(),pollIntervalSeconds:intervalSeconds,heartbeatIntervalSeconds,minPublishIntervalSeconds});
    const run=heartbeatTail.then(async()=>{
      for(const directory of [...new Set([outputDirectory,...mirrors.map(m=>m.directory)].filter(Boolean))]){
        const resolved=path.resolve(directory);await fs.mkdir(resolved,{recursive:true,mode:0o755});
        check(await fs.realpath(resolved)===resolved&&(await fs.lstat(resolved)).isDirectory(),'INVALID_ASP_PUBLICATION_DIRECTORY');
        await atomicJSON(path.join(resolved,'publisher-heartbeat.json'),record);
      }
    });
    heartbeatTail=run.catch(()=>{});
    // Telemetry failure cannot change approval or transaction recovery. If the
    // file cannot be refreshed, readers age it out instead of trusting running.
    await run.catch(()=>{});
  }
  async function observe(status,reason){observation={status,reason};await heartbeat();}
  function resultObservation(result){
    if(!signingEnabled)return {status:'paused',reason:'ASP_PUBLISHER_STATUS_ONLY'};
    if(result?.summary?.decision==='awaiting-confirmations')return {status:'running',reason:'ASP_PUBLISHER_AWAITING_CONFIRMATIONS'};
    const jobs=result?.result?.jobs??[];
    if(result?.result?.knownSignedHash||jobs.some(job=>job.state==='broadcast-unknown'&&!job.unsignedCancellation))return {status:'blocked',reason:'ASP_PUBLISHER_BROADCAST_UNKNOWN'};
    if(jobs.some(job=>['prepared','submitted'].includes(job.state)))return {status:'blocked',reason:'ASP_PUBLISHER_ROOT_PENDING'};
    return {status:'running',reason:'ASP_PUBLISHER_RUNNING'};
  }
  async function observedTick(){
    enteredBroadcast=false;
    if(observation.status==='unknown'||observation.status==='paused')await observe(signingEnabled?'running':'paused',signingEnabled?'ASP_PUBLISHER_STARTING':'ASP_PUBLISHER_STATUS_ONLY');
    try{
      const result=await tick();
      if(result.result?.associationSet){
        const found={chainId:result.result.associationSet.chainId,registry:result.result.associationSet.registry};
        if(publicIdentity)check(publicIdentity.chainId===found.chainId&&publicIdentity.registry.toLowerCase()===found.registry.toLowerCase(),'ASP_PUBLISHER_HEARTBEAT_IDENTITY_MISMATCH');
        publicIdentity=found;
      }
      const status=resultObservation(result);await observe(status.status,status.reason);return result;
    }catch(error){
      const code=error.code??error.message;
      const budget=['ASP_PUBLISHER_BUDGET_EXHAUSTED','GAS_BUDGET_EXHAUSTED','MAINNET_SIGNER_BUDGET_EXCEEDED','TESTNET_GAS_BUDGET_EXCEEDED'].includes(code);
      await observe(budget?'paused':'blocked',budget?'ASP_PUBLISHER_BUDGET_EXHAUSTED':signerBusy(error)?'ASP_PUBLISHER_SIGNER_BUSY':enteredBroadcast?'ASP_PUBLISHER_BROADCAST_UNKNOWN':retryableTransport(error)?'ASP_PUBLISHER_RPC_UNAVAILABLE':'ASP_PUBLISHER_ERROR');
      lastFullSenderReconcile=null;
      throw error;
    }
  }
  let tail = Promise.resolve();
  const serial = fn => { const value = tail.then(fn); tail = value.catch(() => {}); return value; };
  async function releaseUnsigned(job, { terminalOnly = false } = {}) {
    if (typeof signer?.unsignedEvidence !== 'function' || typeof operator.cancelUnsigned !== 'function' || job.transactionHash) return false;
    const id = `asp-${job.id}`;
    let evidence = await signer.unsignedEvidence(id);
    if(!evidence&&!terminalOnly&&typeof signer.cancelUnsubmitted==='function'){
      // The sender must prove absence under its canonical lock and persist an
      // exact-intent tombstone. A missing step alone is never release evidence.
      await signer.cancelUnsubmitted(id,job.plan?.transaction);
      evidence=await signer.unsignedEvidence(id);
    }
    if (!evidence || terminalOnly && !['cancelled', 'not-submitted'].includes(evidence.status)) return false;
    const tx = job.plan?.transaction;
    check(tx && evidence.unsigned === true && evidence.id === id && evidence.chainId === tx.chainId
      && evidence.from?.toLowerCase() === tx.from.toLowerCase() && evidence.to?.toLowerCase() === tx.to.toLowerCase()
      && evidence.data?.toLowerCase() === tx.data.toLowerCase() && evidence.value === '0'
      && !Object.hasOwn(evidence, 'hash') && !Object.hasOwn(evidence, 'transactionHash') && !Object.hasOwn(evidence, 'rawTransaction'), 'ASP_UNSIGNED_CANCELLATION_EVIDENCE_INVALID');
    if (evidence.status === 'prepared') {
      // Persist cancellation in the canonical sender before releasing the
      // operator job. A later sender cannot sign a cancelled reservation.
      await signer.cancelPrepared(id);
      evidence = await signer.unsignedEvidence(id);
    }
    if (!evidence || !['cancelled', 'not-submitted'].includes(evidence.status)) return false;
    await operator.cancelUnsigned(job.id, evidence); return true;
  }
  async function tick() {
    let broadcasts = 0;
    try {
    if (signingEnabled) {
      const full=lastFullSenderReconcile===null||now()-lastFullSenderReconcile>=FULL_SENDER_RECONCILE_MS;
      await signer.reconcile(...(full?[]:[{activeOnly:true}]));
      if(full)lastFullSenderReconcile=now();
    }
    let result = await operator[signingEnabled ? 'prepare' : 'status']();
    if (signingEnabled) {
      let released = false;
      for (const job of result.jobs.filter(j => ['prepared', 'broadcast-unknown', 'superseded'].includes(j.state) && !j.transactionHash && !j.unsignedCancellation))
        // A crash can leave the operator's old prepared state on disk after its
        // sender reservation was cancelled. Recover that terminal evidence, but
        // never cancel a still-valid prepared reservation merely to prepare again.
        released = await releaseUnsigned(job, { terminalOnly: job.state === 'prepared' }) || released;
      if (released) result = await operator.prepare();
    }
    if (signingEnabled && result.plan) {
      const id = `asp-${result.plan.id}`, job = result.jobs.find(j => j.id === result.plan.id);
      check(job, 'ASP_PUBLICATION_JOB_MISSING');
      const knownHash = await signer.recoverHash(id);
      if (knownHash && ['prepared', 'broadcast-unknown', 'submitted'].includes(job.state) && !job.transactionHash) {
        try { await operator.recordHash(result.plan.id, knownHash); result = await operator.status(); }
        catch (error) {
          if (!/TransactionReceiptNotFound|TransactionNotFound/.test(error.name ?? '')) throw error;
          // A signed hash is durable before RPC submission. Missing propagation
          // is not permission to send it again or to reserve a different nonce.
          result = { ...result, reason: 'Known signed hash is not observable yet; no automatic resend.', knownSignedHash: knownHash };
        }
      } else if (!knownHash && job.state === 'prepared') {
        const tx = result.plan.transaction;
        const reservation = await signer.prepare({ id, to: tx.to, data: tx.data, value: tx.value, chainId: tx.chainId, from: tx.from,
          aspPolicy: { previousPolicy: result.plan.previousPolicy, expectedEpoch: result.plan.expectedEpoch, validUntil: result.plan.validUntil } });
        // Publish the proposal document first: a mirror can copy it before the
        // root is live, and readers only accept it once the chain confirms it.
        for (const directory of [outputDirectory, ...mirrors.map(m => m.directory)].filter(Boolean)) await writeAssociationSetDocument({ associationSet: result.associationSet, directory });
        let enteredSend = false, sent;
        try {
          sent = await operator.sendPrepared(result.plan.id, async () => { enteredSend = true; enteredBroadcast = true; const hash = await signer.broadcast(reservation); broadcasts++; return hash; });
        } catch (e) {
          // If snapshot validation rejected the plan before entering the callback,
          // its unsigned nonce/fee reservation is safe to cancel. Otherwise the
          // sender's journal decides whether the outcome is unknown.
          if (!enteredSend) {
            await signer.cancelPrepared(id);
            // New notes may supersede a prepared operator job during the second
            // canonical snapshot inside sendPrepared(). Only a successfully
            // cancelled, never-entered sender reservation may retry preparation.
            // No signed/unknown broadcast or unrelated validation error qualifies.
            if (['ASP_JOB_NOT_SENDABLE', 'ASP_PLAN_STALE'].includes(e.code)) {
              const summary = { schema: 'phase2-asp-publisher-tick/v1', signingEnabled,
                decision: 'retrying-stale-plan', reason: e.code, unsignedReservationCancelled: true,
                transactionsBroadcast: 0, automaticResend: false, activeAssociationSetRetained: true,
                originScreening: false, productionReady: false };
              await onResult(clone(summary)); return { summary, result: null };
            }
          }
          throw e;
        }
        // The operator reports the recorded hash from the snapshot it just
        // validated; only a sender without that result needs another snapshot.
        result = sent?.result?.schema === 'phase2-asp-operator-result/v1' ? sent.result : await operator.status();
      }
    }
    const files = outputDirectory ? await writeASPPublication({ result, directory: outputDirectory, activeFile }) : null;
    for (const mirror of mirrors) await writeASPPublication({ result, directory: mirror.directory, activeFile: mirror.activeFile });
    const summary = { schema: 'phase2-asp-publisher-tick/v1', signingEnabled, transactionsBroadcast: broadcasts,
      decision: result.decision, reason: result.reason, chainId: result.associationSet.chainId,
      registry: result.associationSet.registry, root: result.currentPolicy.root, epoch: result.currentPolicy.epoch,
      validUntil: result.currentPolicy.validUntil, expired: result.currentPolicy.expired, lastPublicationTimestamp: result.lastPublicationTimestamp ?? null,
      activeAssociationSet: files?.activeAssociationSet ?? null, files,
      jobs: result.jobs.map(({ id, state, transactionHash }) => ({ id, state, transactionHash })),
      eventSource:eventSource?.status?.()??null, originScreening: false, productionReady: false, testOnly: result.testOnly };
    await onResult(clone(summary)); return { summary, result };
    } catch (error) {
      if (!['ASP_REGISTRY_AHEAD_OF_SNAPSHOT', 'SNAPSHOT_REORGANIZED'].includes(error.code)) throw error;
      // A freshly mined publication may lead the confirmation-delayed index.
      // Keep the last CONFIRMED document. The API independently revalidates its
      // exact epoch/root/digest against acceptedPolicy at every fresh snapshot;
      // this does not activate the newly broadcast proposal or bypass revocation.
      const summary = { schema: 'phase2-asp-publisher-tick/v1', signingEnabled, transactionsBroadcast: broadcasts,
        decision: 'awaiting-confirmations', reason: error.code, activeAssociationSetRetained:true, originScreening: false,
        productionReady: false, automaticResend: false };
      await onResult(clone(summary)); return { summary, result: null };
    }
  }
  return {
    tick: () => serial(observedTick),
    async stop({reason='ASP_PUBLISHER_STOPPED'}={}){
      check(['ASP_PUBLISHER_STOPPED','ASP_PUBLISHER_ONCE_COMPLETE','ASP_PUBLISHER_ITERATION_LIMIT'].includes(reason),'INVALID_ASP_PUBLISHER_STOP_REASON');
      eventSource?.close();
      await tail;
      // Stopping does not resolve a pending/unknown publication. Retain its
      // last-known blocked reason, with freshness aging normally after exit.
      if(observation.status==='blocked')await heartbeat();else await observe('paused',reason);
      await heartbeatTail;
    },
    async run({ signal, maxIterations = Infinity } = {}) {
      check(maxIterations === Infinity || Number.isSafeInteger(maxIterations) && maxIterations > 0, 'INVALID_ASP_ITERATION_LIMIT');
      let iterations = 0, last = null,failed=false,pendingWake=false,waiting=null,lastStarted=0;
      const wake=()=>{pendingWake=true;waiting?.();};
      function waitFor(ms,interruptible=true){
        if(signal?.aborted||interruptible&&pendingWake)return Promise.resolve();
        return new Promise(resolve=>{
          let timer;const done=()=>{clearTimeout(timer);signal?.removeEventListener('abort',done);if(waiting===done)waiting=null;resolve();};
          timer=setTimeout(done,ms);signal?.addEventListener('abort',done,{once:true});if(interruptible)waiting=done;
        });
      }
      await observe(signingEnabled?'running':'paused',signingEnabled?'ASP_PUBLISHER_STARTING':'ASP_PUBLISHER_STATUS_ONLY');
      const timer=setInterval(()=>{
        if(heartbeatBusy)return;heartbeatBusy=true;
        heartbeat().finally(()=>{heartbeatBusy=false;});
      },heartbeatIntervalSeconds*1000);timer.unref();
      try{
      eventSource?.start(wake);
      while (!signal?.aborted && iterations < maxIterations) {
        // A burst of logs or connection events becomes one follow-up, never concurrent or an
        // unbounded queue of prepare/sign/reconcile calls. Minimum publication
        // cadence remains enforced by the canonical operator, not these hints.
        if(lastStarted)await waitFor(Math.max(0,lastStarted+1000-now()),false);
        if(signal?.aborted)break;pendingWake=false;lastStarted=now();
        try { last = await serial(observedTick); }
        catch (error) {
          const busy=signerBusy(error);
          if (!busy&&!retryableTransport(error)) throw error;
          // Retry polling, never an unknown transaction. Both journals remain
          // authoritative and are reconciled at the beginning of the next tick.
          const summary = { schema: 'phase2-asp-publisher-tick/v1', signingEnabled,
            decision:busy?'retrying-signer':'retrying-rpc',error:busy?'ASP_PUBLISHER_SIGNER_BUSY':'ASP_PUBLISHER_RPC_UNAVAILABLE',
            transactionsBroadcast: null, automaticResend: false, productionReady: false };
          last = { summary, result: null }; await onResult(clone(summary));
        }
        iterations++;
        if (iterations < maxIterations && !signal?.aborted) {
          // With a live commitment-log subscription deposits and connection
          // transitions wake this loop, so the canonical poll only bounds the
          // age of an idle snapshot: every tick is a full roster sync. While
          // the subscription is connecting or retrying, event mode
          // keeps its bounded five-second canonical fallback even if a legacy
          // configuration used a much slower polling interval.
          const subscribed=eventSource?.status?.()?.status==='subscribed';
          let waitMs=eventSource?(subscribed?eventIdleIntervalSeconds*1000:Math.min(intervalSeconds*1000,5000)):intervalSeconds*1000;
          if(last?.summary?.decision==='awaiting-confirmations'||last?.result?.jobs?.some(j=>['prepared','submitted'].includes(j.state)))waitMs=Math.min(waitMs,1000);
          if(last?.result?.decision==='deferred'&&last.result.lastPublicationTimestamp!==null&&last.result.lastPublicationTimestamp!==undefined){
            const remaining=Number(BigInt(last.result.lastPublicationTimestamp)+BigInt(minPublishIntervalSeconds)-BigInt(last.result.chainTimestamp));
            waitMs=Math.min(waitMs,Math.max(250,remaining*1000));
          }
          await waitFor(waitMs);
        }
      }
      return { iterations, last };
      }catch(error){failed=true;throw error;}
      finally{
        eventSource?.close();waiting?.();
        clearInterval(timer);
        if(!failed){
          if(observation.status==='blocked')await heartbeat();
          else await observe('paused',signal?.aborted?'ASP_PUBLISHER_STOPPED':'ASP_PUBLISHER_ITERATION_LIMIT');
        }
        await heartbeatTail;
      }
    }
  };
}
