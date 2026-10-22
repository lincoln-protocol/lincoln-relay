// SPDX-License-Identifier: Apache-2.0
// Relay-side receipt issuance helpers. The relay already knows the public fee
// it was paid; a receipt only attaches the user's chosen claim address to it.
import {decodeEventLog,parseAbi} from 'viem';
import {signFeeReceipt} from './receipts.mjs';

// Kept local (not imported from indexer.mjs) so the relay image ships only this
// file and receipts.mjs.
const FEE_EVENTS=parseAbi([
  'event PublicFlow(address indexed processor, address indexed recipient, address indexed feeRecipient, uint256 publicIn, uint256 publicOut, uint256 fee)',
  'event HolderExited(address indexed processor, address indexed recipient, uint256 indexed commitment, uint256 nullifier, uint256 value, uint256 fee, address feeRecipient)',
  'event ServiceFeePaid(address indexed treasury, address indexed token, uint256 grossAmountOut, uint256 serviceFee, uint256 netAmountOut)',
]);

const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const ADDRESS=/^0x[0-9a-fA-F]{40}$/,ZERO='0x0000000000000000000000000000000000000000';
export const POINTS_STATUSES=['pending','issued','delivered','no-fee','conflict','sign-failed'];

/** Optional `points` member of a relay job request. First submission wins. */
export function normalizePointsRequest(input){
  need(input&&Object.getPrototypeOf(input)===Object.prototype&&Object.keys(input).every(k=>['claimant','referrer'].includes(k)),'INVALID_POINTS_REQUEST');
  need(ADDRESS.test(input.claimant??'')&&(input.referrer===undefined||ADDRESS.test(input.referrer)),'INVALID_POINTS_REQUEST');
  const claimant=input.claimant.toLowerCase(),referrer=(input.referrer??ZERO).toLowerCase();
  need(claimant!==ZERO&&claimant!==referrer,'INVALID_POINTS_REQUEST');
  return {claimant,referrer};
}

/** Service option. signer: {address, signTypedData} bound to the relay key. */
export function normalizePointsIssuer(input,{relayer}){
  need(input&&Object.getPrototypeOf(input)===Object.prototype&&Object.keys(input).every(k=>['season','signer','forwardUrl'].includes(k)),'INVALID_POINTS_ISSUER');
  need(typeof input.season==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(input.season),'INVALID_POINTS_ISSUER');
  need(input.signer&&ADDRESS.test(input.signer.address??'')&&input.signer.address.toLowerCase()===String(relayer).toLowerCase()&&typeof input.signer.signTypedData==='function','INVALID_POINTS_ISSUER');
  const forwardUrl=input.forwardUrl??null;need(forwardUrl===null||typeof forwardUrl==='string'&&/^https?:\/\/[^\s/?#]+$/.test(forwardUrl),'INVALID_POINTS_ISSUER');
  const signer=input.signer;
  return Object.freeze({season:input.season,forwardUrl,signerAddress:signer.address.toLowerCase(),sign:fields=>signFeeReceipt({account:signer,...fields})});
}

/** Locate the one public fee log of a confirmed relay transaction.
 * Pool fees: the log's processor is this relay and the payee is one of
 * feeRecipients (the relay passes only the treasury Safe: a fee a relay keeps
 * earns no points). Swap fees come from the adapter.
 * Returns null when the job paid no official service fee (ragequit, zero fee, kept fee).
 */
export function findRelayFeeLog(logs,{kind,pool,adapter=null,processor,feeRecipients=[processor]}){
  const payees=new Set(feeRecipients.map(a=>String(a).toLowerCase()));
  need(Array.isArray(logs),'INVALID_RECEIPT_LOGS');
  const decoded=[];
  for(const log of logs){
    let event;try{event=decodeEventLog({abi:FEE_EVENTS,topics:log.topics,data:log.data,strict:true});}catch{continue;}
    decoded.push({address:String(log.address).toLowerCase(),logIndex:String(log.logIndex),event});
  }
  if(kind==='swap'&&adapter){
    const hit=decoded.find(d=>d.address===adapter.toLowerCase()&&d.event.eventName==='ServiceFeePaid'&&BigInt(d.event.args.serviceFee)>0n);
    if(hit)return {logIndex:hit.logIndex,kind:'swap',fee:String(hit.event.args.serviceFee),asset:hit.event.args.token.toLowerCase()};
  }
  if(kind==='ragequit')return null;
  const hit=decoded.find(d=>d.address===pool.toLowerCase()&&['PublicFlow','HolderExited'].includes(d.event.eventName)&&BigInt(d.event.args.fee)>0n
    &&d.event.args.processor.toLowerCase()===processor.toLowerCase()&&payees.has(d.event.args.feeRecipient.toLowerCase()));
  if(!hit)return null;
  const a=hit.event.args,feeKind=hit.event.eventName==='HolderExited'?'holder-exit':BigInt(a.publicOut)===BigInt(a.fee)?'private-transfer':'withdrawal';
  return {logIndex:hit.logIndex,kind:feeKind,fee:String(a.fee)};
}
