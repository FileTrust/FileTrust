// Read back the initialized modern protocol before publishing its deployment records.
import fs from 'node:fs';
import path from 'node:path';
import { REGISTERED_CONTRACTS, findArtifact } from './phase2_infrastructure.js';

export function requireCanonicalDeploymentArtifacts(workspace, canonicalWorkspace) {
  if (fs.realpathSync(workspace) !== fs.realpathSync(canonicalWorkspace)) {
    throw new Error('Run the canonical deployment from its filetrust/evm workspace');
  }
  for (const name of new Set(Object.values(REGISTERED_CONTRACTS))) {
    const artifact = findArtifact(path.join(workspace, 'artifacts', 'contracts'), name);
    const build = JSON.parse(fs.readFileSync(path.join(workspace, 'artifacts', 'build-info', `${artifact.buildInfoId}.json`)));
    if (build.input.sources[artifact.inputSourceName]?.content !==
        fs.readFileSync(path.join(workspace, artifact.sourceName), 'utf8')) {
      throw new Error(`Stale deployment artifact: ${name}; compile the canonical EVM sources`);
    }
  }
}

export const DEPLOYMENT_BINDINGS = {
  AccessControlFT: { guardianRegistry: 'GuardianRegistry', rewardManager: 'RewardManager', telgV2: 'TElGv2', dkgV2: 'ZkDkgCoordinatorV2' },
  DataVault: { acl: 'AccessControlFT', rewardManager: 'RewardManager', dkgV2: 'ZkDkgCoordinatorV2' },
  TElGv2: { acl: 'AccessControlFT', dataVault: 'DataVault', coordinator: 'ZkDkgCoordinatorV2', disputeManager: 'ZkDkgDisputeManager', reputationManager: 'ReputationManager', rewardManager: 'RewardManager', stakingManager: 'StakingManager', guardianShareProof: 'GuardianShareProof', guardianWorkReward: 'GuardianWorkReward', v2PrePartialVerifier: 'PrePartialVerifierRouter' },
  GuardianShareProof: { acl: 'AccessControlFT', coordinatorV2: 'ZkDkgCoordinatorV2', reputationManager: 'ReputationManager', rewardManager: 'RewardManager', stakingManager: 'StakingManager', sharePossessionVerifier: 'SharePossessionVerifierRouter' },
  RewardManager: { acl: 'AccessControlFT', dataVault: 'DataVault', guardianRegistry: 'GuardianRegistry' },
  ReputationManager: { stakingManager: 'StakingManager' },
  StakingManager: { guardianRegistry: 'GuardianRegistry', vaultKeeperRegistry: 'VaultKeeperRegistry', guardianShareProof: 'GuardianShareProof', dkgAttemptEscrow: 'DkgAttemptEscrow' },
  VKEscrow: { fileRegistration: 'FileRegistrationSC', fileRegistrationForDeletion: 'FileRegistrationSC', rewardManager: 'RewardManager', disputeContract: 'StorageReceiptDispute', registrationTimeoutResolver: 'StorageRegistrationTimeout' },
  FileRegistrationSC: { trustedStorageProofSC: 'StorageProofSC', vaultKeeperRegistry: 'VaultKeeperRegistry', capacityProof: 'CapacityProofSC', partitionSnapshotProof: 'PartitionSnapshotProofSC', deletionRelease: 'DeletionReleaseSC', registrationTimeoutResolver: 'StorageRegistrationTimeout' },
  StorageProofSC: { vaultKeeperRegistry: 'VaultKeeperRegistry', partitionSnapshotProof: 'PartitionSnapshotProofSC', capacityProof: 'CapacityProofSC', fileRegistration: 'FileRegistrationSC', deletionRelease: 'DeletionReleaseSC', reputationManager: 'ReputationManager', rewardManager: 'RewardManager', stakingManager: 'StakingManager', partitionVerifier: 'PartitionVerifierRouter' },
  CapacityProofSC: { vaultKeeperRegistry: 'VaultKeeperRegistry', storageProof: 'StorageProofSC', partitionSnapshotProof: 'PartitionSnapshotProofSC', certificationContract: 'CapacityCertificationSC', campaignCoordinator: 'CapacityIncrementalBatchSC', fileRegistration: 'FileRegistrationSC' },
  CapacityCertificationSC: { capacityProofSC: 'CapacityProofSC', rewardManager: 'RewardManager' },
  CapacityIncrementalBatchSC: { capacityProof: 'CapacityProofSC', certification: 'CapacityCertificationSC', snapshotProof: 'PartitionSnapshotProofSC', vaultKeeperRegistry: 'VaultKeeperRegistry' },
  PartitionSnapshotProofSC: { storageProof: 'StorageProofSC', capacityProof: 'CapacityProofSC', incrementalBatch: 'CapacityIncrementalBatchSC', certificationHasher: 'CapacityCertificationSC', vaultKeeperRegistry: 'VaultKeeperRegistry', deletionRelease: 'DeletionReleaseSC', partitionVerifier: 'PartitionVerifierRouter' },
  DeletionReleaseSC: { fileRegistration: 'FileRegistrationSC', snapshotProof: 'PartitionSnapshotProofSC', storageProof: 'StorageProofSC' },
  StorageRegistrationTimeout: { vkEscrow: 'VKEscrow', fileRegistration: 'FileRegistrationSC' },
};

export async function validateDeploymentBindings(ethers, deployed) {
  const { contracts, governance } = deployed;
  const instances = {};
  for (const [name, artifact] of Object.entries(REGISTERED_CONTRACTS)) {
    const address = contracts[name];
    if (!ethers.isAddress(address || '') || address === ethers.ZeroAddress) {
      throw new Error(`Deployment incomplete: ${name} missing`);
    }
    const code = await ethers.provider.getCode(address);
    if (code === '0x' || (code.length - 2) / 2 > 24576) {
      throw new Error(`Deployment invalid runtime: ${name}`);
    }
    instances[name] = await ethers.getContractAt(artifact, address);
  }
  for (const [name, edges] of Object.entries(DEPLOYMENT_BINDINGS)) {
    for (const [getter, target] of Object.entries(edges)) {
      const actual = await instances[name][getter]();
      if (actual.toLowerCase() !== contracts[target].toLowerCase()) {
        throw new Error(`Deployment binding mismatch: ${name}.${getter} != ${target}`);
      }
    }
  }
  const { StakingManager: staking, RewardManager: rewards, ReputationManager: reputation } = instances;
  if (!await staking.slashersBound() || !await rewards.rewardersBound()) {
    throw new Error('Deployment permissions were not finalized');
  }
  for (const address of governance.slashers) {
    if (!await staking.authorizedSlashers(address)) throw new Error(`Missing slasher ${address}`);
  }
  for (const address of governance.rewarders) {
    if (!await rewards.authorizedRewarders(address)) throw new Error(`Missing rewarder ${address}`);
  }
  for (const name of ['GuardianShareProof', 'TElGv2', 'StorageProofSC', 'StorageReceiptDispute']) {
    if (!await reputation.authorizedProtocols(contracts[name])) throw new Error(`Missing reputation producer ${name}`);
  }
  return { contracts: Object.keys(instances).length,
    bindings: Object.values(DEPLOYMENT_BINDINGS).reduce((n, edges) => n + Object.keys(edges).length, 0) };
}
