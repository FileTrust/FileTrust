// Recovery-v1 wiring for a NEW deployment. Existing policies and contract
// histories are never imported or repointed by this helper.
export function requireRecoveryDeployment(mode) {
  if(mode!=='1')throw new Error('This branch deploys DKG recovery-v1. Review the versioned deployment and explicitly set FILETRUST_DKG_ATTEMPT_PROTOCOL=1; do not update a legacy deployment in place.');
}

export async function deployDkgRecovery({ethers,acl,coordinator,staking,reputation}) {
  const aclAddress=await acl.getAddress(),coordinatorAddress=await coordinator.getAddress(),stakingAddress=await staking.getAddress();
  if((await coordinator.acl()).toLowerCase()!==aclAddress.toLowerCase())throw new Error('DKG recovery ACL mismatch');
  if(await coordinator.attemptController()!==ethers.ZeroAddress)throw new Error('DKG recovery is already configured; refuse replacement');
  const manager=await ethers.getContractAt('ZkDkgDisputeManager',await coordinator.disputeManager());
  if((await manager.acl()).toLowerCase()!==aclAddress.toLowerCase())throw new Error('DKG recovery evidence ACL mismatch');
  await (await manager.setDkg(coordinatorAddress)).wait();
  await (await manager.setZkDkgCoordinatorV2(coordinatorAddress)).wait();
  const controller=await ethers.deployContract('DkgAttemptController',[coordinatorAddress,aclAddress,stakingAddress]);
  await controller.waitForDeployment();
  const controllerAddress=await controller.getAddress();
  const registry=await ethers.deployContract('DkgAttemptRegistry',[controllerAddress]);
  await registry.waitForDeployment();
  const escrow=await ethers.deployContract('DkgAttemptEscrow',[controllerAddress,stakingAddress]);
  await escrow.waitForDeployment();
  await (await controller.configure(await registry.getAddress(),await escrow.getAddress())).wait();
  await (await staking.setDkgAttemptEscrow(await escrow.getAddress())).wait();
  await (await coordinator.setAttemptController(controllerAddress)).wait();
  await (await reputation.setProtocolContract(controllerAddress,true)).wait();
  const commitments=await ethers.getContractAt('DkgCommitmentBook',await controller.commitments());
  if((await registry.coordinator()).toLowerCase()!==controllerAddress.toLowerCase() ||
     (await escrow.staking()).toLowerCase()!==stakingAddress.toLowerCase() ||
     (await staking.dkgAttemptEscrow()).toLowerCase()!==(await escrow.getAddress()).toLowerCase() ||
     (await commitments.controller()).toLowerCase()!==controllerAddress.toLowerCase() ||
     (await manager.dkg()).toLowerCase()!==coordinatorAddress.toLowerCase() ||
     (await manager.zkDkgCoordinatorV2()).toLowerCase()!==coordinatorAddress.toLowerCase())
    throw new Error('Incomplete DKG recovery wiring');
  return {controller,registry,escrow,commitments,addresses:{DkgAttemptController:controllerAddress,
    DkgAttemptRegistry:await registry.getAddress(),DkgAttemptEscrow:await escrow.getAddress(),
    DkgCommitmentBook:await commitments.getAddress()}};
}
