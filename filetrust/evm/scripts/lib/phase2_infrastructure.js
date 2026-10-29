// Phase 2 upgrade infrastructure for a fresh deployment.
//
// One FileTrustVerifierRouter per active circuit, which the consumers bind once instead of
// the verifier itself, so a key can later be replaced with a bounded transition window
// (the timelock rotates the router). And the FileTrustAddressRegistry, holding every
// deployed contract as version 1 of its name, with its runtime code hash and ABI hash.
// Both are handed to the timelock with the other governed contracts.
import fs from "node:fs";
import path from "node:path";

const DAY = 86400;

// The verify function each consumer calls, and the longest transition window governance
// may give the previous key. Windows are for honest work in flight: a storage round or a
// share-possession epoch, a short-lived PRE request.
export const VERIFIER_ROUTERS = {
  partition: {
    name: "PartitionVerifierRouter",
    fn: "function verifyProof(bytes,uint256[]) view returns (bool)",
    env: "FILETRUST_PARTITION_ROUTER_MAX_WINDOW_SECONDS",
    maxWindow: 30 * DAY,
  },
  sharePossession: {
    name: "SharePossessionVerifierRouter",
    fn: "function verifyTx(((uint256,uint256),(uint256[2],uint256[2]),(uint256,uint256)),uint256[8]) view returns (bool)",
    env: "FILETRUST_SHARE_POSSESSION_ROUTER_MAX_WINDOW_SECONDS",
    maxWindow: 30 * DAY,
  },
  prePartial: {
    name: "PrePartialVerifierRouter",
    fn: "function verifyTx(((uint256,uint256),(uint256[2],uint256[2]),(uint256,uint256)),uint256[12]) view returns (bool)",
    env: "FILETRUST_PRE_PARTIAL_ROUTER_MAX_WINDOW_SECONDS",
    maxWindow: 7 * DAY,
  },
};

export function routerSelector(ethers, kind) {
  return new ethers.Interface([VERIFIER_ROUTERS[kind].fn]).fragments[0].selector;
}

export function routerMaxWindow(kind) {
  const spec = VERIFIER_ROUTERS[kind];
  const value = BigInt(process.env[spec.env] || spec.maxWindow);
  if (value <= 0n || value > 365n * BigInt(DAY)) throw new Error(`${spec.env} must be between 1 second and 365 days`);
  return value;
}

/// Throw unless `consumer.getter()` names `router`: a consumer binds its verifier once.
export async function requireBoundRouter(consumer, getter, router, label) {
  const bound = String(await consumer[getter]());
  if (bound.toLowerCase() !== String(router).toLowerCase()) {
    throw new Error(`${label}.${getter} reads ${bound}, not its router ${router}`);
  }
}

/// Deploy the router for `kind` in front of `verifierAddress` and return its address.
export async function deployVerifierRouter(ethers, kind, verifierAddress) {
  const spec = VERIFIER_ROUTERS[kind];
  const router = await ethers.deployContract(
    "FileTrustVerifierRouter", [verifierAddress, routerSelector(ethers, kind), routerMaxWindow(kind)],
  );
  await router.waitForDeployment();
  const address = await router.getAddress();
  if ((await router.currentVerifier()).toLowerCase() !== verifierAddress.toLowerCase()) {
    throw new Error(`${spec.name} does not name ${verifierAddress} as its verifier`);
  }
  console.log(`${spec.name} deployed to: ${address} (verifier ${verifierAddress})`);
  return address;
}

// The contracts the registry records, as named in deployed_addresses.json, with the
// artifact each one is built from when the two names differ.
export const REGISTERED_CONTRACTS = {
  FileTrustTimelock: "FileTrustTimelock",
  FileTrustAddressRegistry: "FileTrustAddressRegistry",
  GuardianRegistry: "GuardianRegistry",
  VaultKeeperRegistry: "VaultKeeperRegistry",
  NetworkDirectoryReader: "NetworkDirectoryReader",
  AccessControlFT: "AccessControlFT",
  DataVault: "DataVault",
  TElGv2: "TElGv2",
  ZkDkgCoordinatorV2: "ZkDkgCoordinatorV2",
  ZkDkgDisputeManager: "ZkDkgDisputeManager",
  GuardianShareProof: "GuardianShareProof",
  ReputationManager: "ReputationManager",
  StakingManager: "StakingManager",
  RewardManager: "RewardManager",
  GuardianWorkReward: "GuardianWorkReward",
  VKEscrow: "VKEscrow",
  FileRegistrationSC: "FileRegistrationSC",
  StorageProofSC: "StorageProofSC",
  PartitionSnapshotProofSC: "PartitionSnapshotProofSC",
  CapacityProofSC: "CapacityProofSC",
  CapacityCertificationSC: "CapacityCertificationSC",
  CapacityIncrementalBatchSC: "CapacityIncrementalBatchSC",
  StorageReceiptDispute: "StorageReceiptDispute",
  StorageRegistrationTimeout: "StorageRegistrationTimeout",
  DeletionReleaseSC: "DeletionReleaseSC",
  DkgAttemptController: "DkgAttemptController",
  DkgAttemptRegistry: "DkgAttemptRegistry",
  DkgAttemptEscrow: "DkgAttemptEscrow",
  DkgCommitmentBook: "DkgCommitmentBook",
  PartitionVerifierRouter: "FileTrustVerifierRouter",
  SharePossessionVerifierRouter: "FileTrustVerifierRouter",
  PrePartialVerifierRouter: "FileTrustVerifierRouter",
};

export function findArtifact(artifactsRoot, contractName) {
  const stack = [artifactsRoot];
  while (stack.length) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(file);
      else if (entry.name === `${contractName}.json` && dir.endsWith(".sol")) {
        return JSON.parse(fs.readFileSync(file, "utf8"));
      }
    }
  }
  throw new Error(`artifact for ${contractName} not found under ${artifactsRoot}`);
}

/// The ABI hash the deployment manifest records: keccak256 of the ABI JSON. A commitment
/// to a file, not a proof that the ABI is right.
export function abiHashOf(ethers, abi) {
  return ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(abi)));
}

/// Record every deployed contract in `contracts` that the registry names as version 1.
/// Returns the entries written.
export async function registerDeployment(ethers, registry, contracts, artifactsRoot) {
  const entries = [];
  for (const [name, artifactName] of Object.entries(REGISTERED_CONTRACTS)) {
    const address = contracts[name];
    if (typeof address !== "string" || !ethers.isAddress(address) || address === ethers.ZeroAddress) continue;
    const code = await ethers.provider.getCode(address);
    if (code === "0x") throw new Error(`${name} has no code at ${address}`);
    const codeHash = ethers.keccak256(code);
    const abiHash = abiHashOf(ethers, findArtifact(artifactsRoot, artifactName).abi);
    const key = ethers.encodeBytes32String(name);
    await (await registry.register(key, 1, address, codeHash, abiHash)).wait();
    const recorded = await registry.entry(key, 1);
    if (recorded.addr.toLowerCase() !== address.toLowerCase() || recorded.codeHash !== codeHash || recorded.abiHash !== abiHash) {
      throw new Error(`FileTrustAddressRegistry did not record ${name} as written`);
    }
    entries.push({ name, version: 1, address, codeHash, abiHash });
  }
  return entries;
}
