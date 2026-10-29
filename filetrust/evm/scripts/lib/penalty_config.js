// Penalty amounts a deployment sets, checked before the first deployment transaction.
//
// MISSED_EPOCH_PENALTY_WEI (GuardianShareProof) and VERIFIED_DKG_COMPLAINT_SLASH_WEI
// (ReputationManager) are taken from a Guardian's stake. Each is a whole number of aftu
// (1 FTU = 10^18 aftu), and neither may be above 1% of MIN_GUARDIAN_STAKE. The VaultKeeper
// wrong-proof slash rates WRONG_PROOF_SLASH_BPS and WRONG_PROOF_SUSPEND_SLASH_BPS
// (StorageProofSC) are whole basis points, at most 5,000 (half the stake), the suspension
// rate not below the slash rate. The contracts refuse anything else, so a deployment
// configured outside these limits stops here instead of half-way.

export const PENALTY_CEILING_BPS=100n;
export const MAX_WRONG_PROOF_SLASH_BPS=5000n;
export const DEFAULT_MISSED_EPOCH_PENALTY_WEI=1000000000000000n; // 0.001 FTU
export const DEFAULT_VERIFIED_DKG_COMPLAINT_SLASH_WEI=1000000000000000n; // 0.001 FTU
export const DEFAULT_WRONG_PROOF_SLASH_BPS=50n; // 0.5%
export const DEFAULT_WRONG_PROOF_SUSPEND_SLASH_BPS=200n; // 2%

/// The most either Guardian penalty may be: 1% of the minimum stake Guardians are admitted with.
export function penaltyCeilingWei(minGuardianStake) {
  return BigInt(minGuardianStake)*PENALTY_CEILING_BPS/10000n;
}

export function resolvePenalties(env,{minGuardianStake}) {
  const ceilingWei=penaltyCeilingWei(minGuardianStake);
  const problems=[];
  const whole=(name,fallback,unit)=>{
    const value=env[name]?.trim();
    if(!value)return fallback;
    if(!/^[0-9]+$/.test(value)){
      problems.push(`${name} must be a whole number of ${unit}, not "${value}"`);
      return null;
    }
    return BigInt(value);
  };
  const missedEpochPenaltyWei=whole('MISSED_EPOCH_PENALTY_WEI',DEFAULT_MISSED_EPOCH_PENALTY_WEI,'aftu');
  const verifiedDkgComplaintSlashWei=whole('VERIFIED_DKG_COMPLAINT_SLASH_WEI',DEFAULT_VERIFIED_DKG_COMPLAINT_SLASH_WEI,'aftu');
  for(const [name,value] of [['MISSED_EPOCH_PENALTY_WEI',missedEpochPenaltyWei],
    ['VERIFIED_DKG_COMPLAINT_SLASH_WEI',verifiedDkgComplaintSlashWei]]) {
    if(value!==null && value>ceilingWei)
      problems.push(`${name} is ${value} aftu, above the ceiling of ${ceilingWei} aftu (1% of MIN_GUARDIAN_STAKE)`);
  }
  const slashBps=whole('WRONG_PROOF_SLASH_BPS',DEFAULT_WRONG_PROOF_SLASH_BPS,'basis points');
  const suspendSlashBps=whole('WRONG_PROOF_SUSPEND_SLASH_BPS',DEFAULT_WRONG_PROOF_SUSPEND_SLASH_BPS,'basis points');
  for(const [name,value] of [['WRONG_PROOF_SLASH_BPS',slashBps],['WRONG_PROOF_SUSPEND_SLASH_BPS',suspendSlashBps]]) {
    if(value!==null && value>MAX_WRONG_PROOF_SLASH_BPS)
      problems.push(`${name} is ${value}, above ${MAX_WRONG_PROOF_SLASH_BPS} basis points (half the stake)`);
  }
  if(slashBps!==null && suspendSlashBps!==null && suspendSlashBps<slashBps)
    problems.push(`WRONG_PROOF_SUSPEND_SLASH_BPS (${suspendSlashBps}) must not be below WRONG_PROOF_SLASH_BPS (${slashBps})`);
  if(problems.length)
    throw new Error(`Unsafe penalty configuration:\n  - ${problems.join('\n  - ')}`);
  return {
    missedEpochPenaltyWei,verifiedDkgComplaintSlashWei,ceilingWei,
    wrongProofSlashBps:Number(slashBps),wrongProofSuspendSlashBps:Number(suspendSlashBps),
  };
}
