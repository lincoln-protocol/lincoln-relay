// SPDX-License-Identifier: Apache-2.0
// The relay's signing address carries one transaction at a time: the signer
// refuses a new reservation while any entry is live. Submissions already run
// one after another; this makes the one at the head of the line wait for the
// previous transaction to settle, for a bounded time, instead of cancelling
// the job and sending the client away. Nothing is signed or sent here; the
// settle step only reads receipts.
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
export const RELAY_SIGNER_BUSY='MAINNET_ACCOUNT_PENDING_TRANSACTION';
export const RELAY_SIGNER_WAIT_MS=25000,RELAY_SIGNER_WAIT_INTERVAL_MS=1000;

export async function prepareWhenSignerFree({prepare,settle,waitMs=RELAY_SIGNER_WAIT_MS,intervalMs=RELAY_SIGNER_WAIT_INTERVAL_MS,
  sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),now=Date.now}={}){
  need(typeof prepare==='function'&&typeof settle==='function','RELAY_SIGNER_WAIT_INVALID');
  need(Number.isSafeInteger(waitMs)&&waitMs>=0&&waitMs<=120000&&Number.isSafeInteger(intervalMs)&&intervalMs>=100&&intervalMs<=10000,'RELAY_SIGNER_WAIT_INVALID');
  const began=now();let attempts=0,settles=0;
  for(;;){
    attempts++;
    try{return await prepare();}
    catch(error){
      if(error?.code!==RELAY_SIGNER_BUSY)throw error;
      const elapsed=now()-began;
      if(elapsed>=waitMs)throw Object.assign(error,{retryAfterSeconds:3,waitedMs:elapsed,attempts,settles});
      await sleep(Math.min(intervalMs,waitMs-elapsed));
      // A receipt read that fails is not a verdict: the next prepare() asks the
      // ledger again, and the deadline still bounds the whole wait.
      try{await settle();settles++;}catch{}
    }
  }
}
