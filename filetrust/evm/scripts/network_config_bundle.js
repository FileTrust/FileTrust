// Pack everything the network config service publishes into one file.
//
// The service hands out the deployed addresses and about twenty-five contract
// ABIs. On this machine those ABIs are a 47 MB Hardhat tree; the service does
// not run here, and copying a tree between machines is how you end up serving
// yesterday's ABI next to today's address without anyone noticing.
//
// So the deploy writes them together, once, as its last step. One file to
// copy, and either it is there or it is not.
//
// The list below must match what network_config_server.py asks for. A name
// here that the tree does not have is reported rather than skipped: a bundle
// that is quietly short is worse than one that says what is missing, because
// the service refuses to start on a short bundle and that refusal is the
// thing keeping a half-deployed network off the air.

import fs from "node:fs";
import path from "node:path";

export const REQUIRED = [
  ["AccessControlFT.json", "AccessControlFT.sol/AccessControlFT.json"],
  ["DataVault.json", "DataVault.sol/DataVault.json"],
  ["GuardianRegistry.json", "GuardianRegistry.sol/GuardianRegistry.json"],
  ["VaultKeeperRegistry.json", "VaultKeeperRegistry.sol/VaultKeeperRegistry.json"],
  ["TElGv2.json", "TElGv2.sol/TElGv2.json"],
  ["ZkDkgCoordinatorV2.json", "ZkDkgCoordinatorV2.sol/ZkDkgCoordinatorV2.json"],
  ["GuardianShareProof.json", "GuardianShareProof.sol/GuardianShareProof.json"],
  ["ZkDkgDisputeManager.json", "ZkDkgDisputeManager.sol/ZkDkgDisputeManager.json"],
  ["ReputationManager.json", "ReputationManager.sol/ReputationManager.json"],
  ["StakingManager.json", "StakingManager.sol/StakingManager.json"],
  ["RewardManager.json", "RewardManager.sol/RewardManager.json"],
  ["FileRegistrationSC.json", "FileRegistrationSC.sol/FileRegistrationSC.json"],
  ["VKEscrow.json", "VKEscrow.sol/VKEscrow.json"],
  ["CapacityProofSC.json", "CapacityProofSC.sol/CapacityProofSC.json"],
  ["CapacityCertificationSC.json", "CapacityCertificationSC.sol/CapacityCertificationSC.json"],
  ["CapacityIncrementalBatchSC.json", "CapacityIncrementalBatchSC.sol/CapacityIncrementalBatchSC.json"],
  ["PartitionSnapshotProofSC.json", "PartitionSnapshotProofSC.sol/PartitionSnapshotProofSC.json"],
  ["StorageProofSC.json", "StorageProofSC.sol/StorageProofSC.json"],
  ["StorageReceiptDispute.json", "StorageReceiptDispute.sol/StorageReceiptDispute.json"],
  ["StorageRegistrationTimeout.json", "StorageRegistrationTimeout.sol/StorageRegistrationTimeout.json"],
  ["DeletionReleaseSC.json", "DeletionReleaseSC.sol/DeletionReleaseSC.json"],
  ["ShareVerifier.json", "zkdkg/ShareVerifier.sol/ShareVerifier.json"],
  ["V2PrePartialVerifier.json", "zkdkg/V2PrePartialVerifier.sol/V2PrePartialVerifier.json"],
  ["SharePossessionVerifier.json", "zkdkg/SharePossessionVerifier.sol/SharePossessionVerifier.json"],
  ["GnarkStorageProofVerifierAdapter.json", "GnarkStorageProofVerifierAdapter.sol/GnarkStorageProofVerifierAdapter.json"],
  // The generated source exports `contract Verifier`; published under a
  // unique filename so it cannot collide with the partition verifier.
  ["StorageProofGnarkVerifier.json", "StorageProofGnarkVerifier.sol/Verifier.json"],
  ["GnarkPartitionProofVerifierAdapter132.json", "GnarkPartitionProofVerifierAdapter132.sol/GnarkPartitionProofVerifierAdapter132.json"],
  // Discovery reads every keeper and guardian through this one.
  ["NetworkDirectoryReader.json", "NetworkDirectoryReader.sol/NetworkDirectoryReader.json"],
  // Phase 2: the versioned address registry, and the router every consumer binds instead
  // of a verifier (one ABI for the three routers).
  ["FileTrustAddressRegistry.json", "governance/FileTrustAddressRegistry.sol/FileTrustAddressRegistry.json"],
  ["FileTrustVerifierRouter.json", "FileTrustVerifierRouter.sol/FileTrustVerifierRouter.json"],
];

// Verifier.json exists in more than one folder; the 512 profile is the one in
// use, and the plain one is the fallback for an older deploy.
const VERIFIER_CANDIDATES = [
  "PartitionStorageProofGnarkVerifier512.sol/Verifier.json",
  "PartitionStorageProofGnarkVerifier.sol/Verifier.json",
];

// Named here too, because the service names them: it refuses to start
// without these ABIs, so a bundle is only finished when it has them.
export const ALSO_REQUIRED = ["Verifier.json"];
export const RECOVERY_REQUIRED = ['DkgAttemptController','DkgAttemptRegistry','DkgAttemptEscrow','DkgCommitmentBook']
  .map(name=>[name+'.json',name+'.sol/'+name+'.json']);

export function readArtifact(contractsRoot, relative) {
  const file = path.join(contractsRoot, relative);
  if (!fs.existsSync(file)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(data.abi) ? data : null;
  } catch (error) {
    return null;
  }
}

/**
 * Write the bundle beside the addresses file.
 *
 * @param {string} blockchainDir folder holding deployed_addresses.json and artifacts/
 * @param {object} deployed      the addresses object the deploy just built
 * @returns {{path: string, present: number, required: number, missing: string[]}}
 */
export function explorerFiles(blockchainDir) {
  const files = {};
  const contractsRoot = path.join(blockchainDir, "artifacts", "contracts");
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) { visit(file); continue; }
      if (!entry.name.endsWith(".json") || entry.name.endsWith(".dbg.json")) continue;
      const artifact = JSON.parse(fs.readFileSync(file, "utf8"));
      if (!Array.isArray(artifact.abi)) continue;
      files[path.relative(blockchainDir, file).split(path.sep).join("/")] = artifact;
      const source = artifact.sourceName;
      if (source && source.startsWith("contracts/") && !source.split("/").includes("..")) {
        const sourceFile = path.join(blockchainDir, source);
        if (fs.existsSync(sourceFile)) files[source] = fs.readFileSync(sourceFile, "utf8");
      }
      if (artifact.buildInfoId && /^[A-Za-z0-9_-]+$/.test(artifact.buildInfoId)) {
        const relative = `artifacts/build-info/${artifact.buildInfoId}.json`;
        const buildFile = path.join(blockchainDir, relative);
        if (!files[relative] && fs.existsSync(buildFile)) {
          const info = JSON.parse(fs.readFileSync(buildFile, "utf8"));
          // The details page needs compiler settings, not the entire compiler
          // output (tens of MB, duplicated alongside the individual artifacts).
          files[relative] = {
            compilerType: info.compilerType, solcVersion: info.solcVersion,
            solcLongVersion: info.solcLongVersion,
            input: { language: info.input?.language, settings: info.input?.settings },
          };
        }
      }
    }
  };
  if (fs.existsSync(contractsRoot)) visit(contractsRoot);
  return files;
}

export function writeNetworkConfigBundle(blockchainDir, deployed, { chainType = "cosmos", outputDir = blockchainDir } = {}) {
  const contractsRoot = path.join(blockchainDir, "artifacts", "contracts");
  const artifactFiles = {};

  const required=deployed.capabilities?.dkgAttemptProtocol===1 ? [...REQUIRED,...RECOVERY_REQUIRED] : REQUIRED;
  for (const [name, relative] of required) {
    const artifact = readArtifact(contractsRoot, relative);
    if (artifact) artifactFiles[name] = artifact;
  }
  for (const relative of VERIFIER_CANDIDATES) {
    const artifact = readArtifact(contractsRoot, relative);
    if (artifact) {
      artifactFiles["Verifier.json"] = artifact;
      break;
    }
  }

  // Three of them are also published under the contract name, which is how
  // the older clients ask for them.
  const artifacts = {};
  for (const name of ["VaultKeeperRegistry", "GuardianRegistry", "GuardianShareProof"]) {
    const artifact = artifactFiles[`${name}.json`];
    if (artifact) artifacts[name] = artifact;
  }

  const requiredNames = required.map(([name]) => name).concat(ALSO_REQUIRED);
  const missing = requiredNames.filter((name) => !(name in artifactFiles));

  const bundle = {
    bundle_version: 2,
    chain_type: chainType,
    generated_at: new Date().toISOString(),
    deployed_addresses: deployed,
    artifacts,
    artifact_files: artifactFiles,
    // Served separately, so ordinary clients still download only their ABIs.
    // An Explorer can now install away from the validator's checkout.
    explorer_files: explorerFiles(blockchainDir),
    // What this bundle set out to carry. The service compares against this,
    // so a bundle written while a contract was missing still reports it as
    // missing instead of looking complete because nothing asked for it.
    required_artifact_files: requiredNames,
  };

  const target = path.join(outputDir, "network_config_bundle.json");
  fs.writeFileSync(target, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  return {
    path: target,
    present: requiredNames.length - missing.length,
    required: requiredNames.length,
    missing,
  };
}
