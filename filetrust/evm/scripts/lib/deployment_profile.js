// Who the protocol is handed to, decided before the first deployment transaction.
//
// FILETRUST_DEPLOY_PROFILE=local (the default) is a developer chain. What is left unset
// falls back to a safe local value: the treasury is the deployment's own timelock, the
// deployer proposes, and there is no separate canceller. The treasury is never the
// deployer's wallet in either profile.
//
// FILETRUST_DEPLOY_PROFILE=mainnet takes no defaults. The treasury, the proposer (a
// multisig) and an independent canceller must be named, none of them may be the
// deployer, the canceller may not be the proposer, and the delay may not be shorter than
// the protocol default. A mainnet configuration that is incomplete or unsafe stops the
// deployment before anything is sent.

export const PROFILES=['local','mainnet'];
export const DEFAULT_DELAY_SECONDS=172800n; // 48 hours
const TIMELOCK_FLOOR_SECONDS=3600n; // FileTrustTimelock refuses less
const ZERO='0x0000000000000000000000000000000000000000';

export function resolveGovernance(env,{deployer}) {
  const profile=(env.FILETRUST_DEPLOY_PROFILE||'local').trim().toLowerCase();
  if(!PROFILES.includes(profile))
    throw new Error(`FILETRUST_DEPLOY_PROFILE must be ${PROFILES.join(' or ')}, not "${env.FILETRUST_DEPLOY_PROFILE}"`);
  const mainnet=profile==='mainnet';
  const problems=[];
  const address=name=>{
    const value=env[name]?.trim();
    if(!value)return null;
    if(!/^0x[0-9a-fA-F]{40}$/.test(value) || value.toLowerCase()===ZERO){
      problems.push(`${name} is not a valid non-zero address: ${value}`);
      return null;
    }
    return value;
  };
  const same=(a,b)=>Boolean(a && b && a.toLowerCase()===b.toLowerCase());

  const treasury=address('FILETRUST_TREASURY_ADDRESS');
  const proposer=address('GOVERNANCE_PROPOSER_ADDRESS');
  const canceller=address('GOVERNANCE_CANCELLER_ADDRESS');
  const executor=address('GOVERNANCE_EXECUTOR_ADDRESS'); // unset: anyone may execute a ready operation
  let delay=DEFAULT_DELAY_SECONDS;
  const rawDelay=env.GOVERNANCE_DELAY_SECONDS?.trim();
  if(rawDelay){
    if(/^[0-9]+$/.test(rawDelay))delay=BigInt(rawDelay);
    else problems.push(`GOVERNANCE_DELAY_SECONDS is not a whole number of seconds: ${rawDelay}`);
  }
  if(delay<TIMELOCK_FLOOR_SECONDS)problems.push(`GOVERNANCE_DELAY_SECONDS must be at least ${TIMELOCK_FLOOR_SECONDS}`);

  if(same(treasury,deployer))
    problems.push('FILETRUST_TREASURY_ADDRESS must not be the deployer wallet'+(mainnet?'':': leave it unset to use the timelock'));
  if(mainnet){
    if(!treasury)problems.push('FILETRUST_TREASURY_ADDRESS is required: the protocol treasury contract');
    if(!proposer)problems.push('GOVERNANCE_PROPOSER_ADDRESS is required: the multisig that proposes changes');
    if(!canceller)problems.push('GOVERNANCE_CANCELLER_ADDRESS is required: an independent account that can cancel a proposal');
    for(const [name,value] of [['GOVERNANCE_PROPOSER_ADDRESS',proposer],['GOVERNANCE_CANCELLER_ADDRESS',canceller],
      ['GOVERNANCE_EXECUTOR_ADDRESS',executor]])
      if(same(value,deployer))problems.push(`${name} must not be the deployer`);
    if(same(canceller,proposer))problems.push('GOVERNANCE_CANCELLER_ADDRESS must be independent of the proposer');
    if(same(treasury,proposer) || same(treasury,canceller))
      problems.push('FILETRUST_TREASURY_ADDRESS must not be a governance account');
    if(delay<DEFAULT_DELAY_SECONDS)problems.push(`GOVERNANCE_DELAY_SECONDS must be at least ${DEFAULT_DELAY_SECONDS} on mainnet`);
  }
  if(problems.length)throw new Error(`Unsafe ${profile} deployment configuration:\n  - ${problems.join('\n  - ')}`);
  return {profile,mainnet,treasury,delay,
    proposers:[proposer??deployer],executors:[executor??ZERO],cancellers:canceller?[canceller]:[]};
}

/// The on-chain half of the mainnet checks: the treasury and the proposer must already be
/// contracts (a treasury contract, a multisig) on the target chain.
export async function requireGovernanceContracts(provider,governance) {
  if(!governance.mainnet)return;
  for(const [name,value] of [['FILETRUST_TREASURY_ADDRESS',governance.treasury],
    ['GOVERNANCE_PROPOSER_ADDRESS',governance.proposers[0]]])
    if((await provider.getCode(value))==='0x')
      throw new Error(`Unsafe mainnet deployment configuration: ${name} ${value} has no contract code`);
}
