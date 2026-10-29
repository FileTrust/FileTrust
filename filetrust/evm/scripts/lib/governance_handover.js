// Handing the deployed protocol contracts to the FileTrust timelock.
//
// The OpenZeppelin-owned contracts change owner in two steps (Ownable2Step): a transfer
// only names the timelock as the pending owner, and the timelock completes it by running
// acceptOwnership as one of its own operations -- proposed, delayed, then executed by
// anyone. Until then the deployer still owns those contracts. The custom-owned contracts
// change owner in one step. Both kinds are verified here, so a deployment can never
// believe a hand-over happened that did not.

export const HANDOVER_SALT_LABEL='filetrust-governance-handover-v1';

export function isTwoStep(contract) {
  try {return contract.interface.getFunction('acceptOwnership')!==null;} catch {return false;}
}

const same=(a,b)=>a.toLowerCase()===b.toLowerCase();

/// Transfers each [label, contract] to the timelock. Returns the two-step ones, which
/// still wait for the timelock to accept.
export async function startHandover(contracts,timelockAddress) {
  const pending=[];
  for(const [label,contract] of contracts){
    if(!contract)throw new Error(`${label} governance target is unavailable`);
    await (await contract.transferOwnership(timelockAddress)).wait();
    if(isTwoStep(contract)){
      if(!same(await contract.pendingOwner(),timelockAddress))throw new Error(`${label} did not name the timelock as pending owner`);
      pending.push([label,contract]);
    } else if(!same(await contract.owner(),timelockAddress)){
      throw new Error(`${label} ownership transfer verification failed`);
    }
  }
  return pending;
}

/// The one timelock batch that accepts ownership of every pending contract.
export async function acceptanceBatch(ethers,pending) {
  const targets=await Promise.all(pending.map(([,contract])=>contract.getAddress()));
  return {
    labels:pending.map(([label])=>label),
    targets,
    values:targets.map(()=>'0'),
    payloads:pending.map(([,contract])=>contract.interface.encodeFunctionData('acceptOwnership')),
    predecessor:ethers.ZeroHash,
    salt:ethers.id(HANDOVER_SALT_LABEL),
  };
}

export function operationId(timelock,batch) {
  return timelock.hashOperationBatch(batch.targets,batch.values,batch.payloads,batch.predecessor,batch.salt);
}

export async function scheduleAcceptance(timelock,batch,delay) {
  await (await timelock.scheduleBatch(batch.targets,batch.values,batch.payloads,batch.predecessor,batch.salt,delay)).wait();
}

export async function executeAcceptance(timelock,batch) {
  await (await timelock.executeBatch(batch.targets,batch.values,batch.payloads,batch.predecessor,batch.salt)).wait();
}

/// Throws unless the timelock owns every contract and none still has a pending owner.
export async function verifyOwnedBy(contracts,timelockAddress) {
  for(const [label,contract] of contracts){
    if(!same(await contract.owner(),timelockAddress))throw new Error(`${label} is not owned by the timelock`);
    if(isTwoStep(contract) && !same(await contract.pendingOwner(),'0x0000000000000000000000000000000000000000'))
      throw new Error(`${label} still has a pending owner`);
  }
}
