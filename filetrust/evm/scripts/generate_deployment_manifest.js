// A.0 deployment manifest generator.
//
// Produces a versioned, tamper-evident manifest that VK and DO startup verify. It binds a
// running stack to the exact contracts it was built for: chain id, per-contract addresses,
// runtime code hashes (keccak256 of on-chain deployed bytecode), ABI hashes (keccak256 of
// the canonical ABI JSON), the deployer, and the wiring relationships (which contract each
// consumer points at). A mismatch on any of these at startup means the process is talking
// to the wrong or a partially-migrated stack and must refuse to run.
//
// Usage:
//   npx hardhat run scripts/generate_deployment_manifest.js
// Writes the deployment manifest into this workspace or FILETRUST_DEPLOY_OUTPUT_DIR.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { network } from "hardhat";
import { resolveRepoRoot } from "./lib/repo_paths.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const blockchainDir = path.join(here, "..");
const repoRoot = resolveRepoRoot(blockchainDir);
const outputDir = process.env.FILETRUST_DEPLOY_OUTPUT_DIR || blockchainDir;
const addressesPath = path.join(outputDir, "deployed_addresses.json");
const artifactsRoot = path.join(blockchainDir, "artifacts", "contracts");

// The contracts a running stack must pin. Wiring edges are (consumer -> getter -> target).
const MANIFEST_CONTRACTS = [
  "PartitionSnapshotProofSC",
  "StorageProofSC",
  "CapacityProofSC",
  "CapacityCertificationSC",
  "CapacityIncrementalBatchSC",
  "FileRegistrationSC",
  "DeletionReleaseSC",
  "VaultKeeperRegistry",
];

function findArtifact(name) {
  // artifacts/contracts/<File>.sol/<name>.json — locate by contract name.
  const entries = fs.readdirSync(artifactsRoot, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const candidate = path.join(artifactsRoot, e.name, `${name}.json`);
    if (fs.existsSync(candidate)) return JSON.parse(fs.readFileSync(candidate, "utf8"));
  }
  throw new Error(`artifact for ${name} not found under ${artifactsRoot}`);
}

// Index the deploy transaction log (real receipts) by contract address so the manifest
// records deploymentBlock/deploymentTransactionHash from actual deployment receipts, not
// inferred. Env DEPLOY_TX_LOG overrides the default path.
function indexDeployLog() {
  const candidates = [
    process.env.DEPLOY_TX_LOG,
    // Matches the reports/blockchain2 subdirectory deploy_filetrust.js writes to, so
    // read deployment records from the same directory as the deploy script.
    path.join(repoRoot, "reports", "deployment", "transaction_logs", "deploy_filetrust_transactions.jsonl"),
  ].filter(Boolean);
  const byAddr = new Map();
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue;
    for (const line of fs.readFileSync(p, "utf8").split("\n")) {
      const s = line.trim();
      if (!s) continue;
      let rec;
      try { rec = JSON.parse(s); } catch { continue; }
      if (rec.transaction_kind !== "contract_deployment") continue;
      const addr = String(rec.contract_address || "").toLowerCase();
      if (!addr) continue;
      byAddr.set(addr, { txHash: rec.transaction_hash || "", block: rec.block_number || "" });
    }
    if (byAddr.size) break;
  }
  return byAddr;
}

async function main() {
  const connection = await network.getOrCreate();
  const { ethers } = connection;
  // Manifest generation is read-only. Without an explicit provider the Hardhat
  // helper requests eth_accounts, which a locked Cosmos RPC correctly refuses.
  // Explicit `from` also avoids Hardhat's HTTP automatic-sender middleware,
  // which otherwise calls eth_accounts even for a provider-only eth_call.
  const reader = { provider: ethers.provider,
    call: request => ethers.provider.call({ ...request, from: ethers.ZeroAddress }) };
  const readContract = (name, address) => ethers.getContractAt(name, address, reader);
  const net = await ethers.provider.getNetwork();
  const deployed = JSON.parse(fs.readFileSync(addressesPath, "utf8"));
  const contracts = deployed.contracts || deployed;
  const deployLog = indexDeployLog();
  const addressesJson = fs.readFileSync(addressesPath, "utf8");
  const contractInterfaceVersion = String(process.env.CONTRACT_INTERFACE_VERSION || "a0.1");

  const manifest = {
    version: 1,
    schema: "filetrust-deployment-manifest/1",
    manifestKind: "filetrust-deployment-manifest",
    chainId: net.chainId.toString(),
    generatedAt: new Date().toISOString(),
    deployer: deployed.deployer || "",
    deployedAddressesHash: ethers.keccak256(ethers.toUtf8Bytes(addressesJson)),
    contractInterfaceVersion,
    contracts: {},
    wiring: {},
  };

  for (const name of MANIFEST_CONTRACTS) {
    const address = contracts[name];
    if (!address) throw new Error(`${name} missing from deployed_addresses.json`);
    const code = await ethers.provider.getCode(address);
    if (code === "0x") throw new Error(`${name} has no code at ${address}`);
    const artifact = findArtifact(name);
    const dl = deployLog.get(String(address).toLowerCase());
    if (!dl || !dl.txHash || !dl.block) {
      throw new Error(`${name}: deployment receipt (tx hash + block) not found in deploy log for ${address}; refusing to infer`);
    }
    manifest.contracts[name] = {
      contractAddress: address,
      address, // back-compat alias
      runtimeCodeHash: ethers.keccak256(code),
      codeHash: ethers.keccak256(code), // back-compat alias
      abiHash: ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(artifact.abi))),
      contractVersion: contractInterfaceVersion,
      deploymentBlock: dl.block,
      deploymentTransactionHash: dl.txHash,
    };
  }

  // Wiring: verify each consumer points at the manifest's snapshot/capacity/storage.
  const snapshotAddr = manifest.contracts.PartitionSnapshotProofSC.address;
  const capacityAddr = manifest.contracts.CapacityProofSC.address;
  const storageAddr = manifest.contracts.StorageProofSC.address;
  const certificationAddr = manifest.contracts.CapacityCertificationSC.address;
  const fileRegistrationAddr = manifest.contracts.FileRegistrationSC.address;
  const deletionReleaseAddr = manifest.contracts.DeletionReleaseSC.address;

  const storage = await readContract("StorageProofSC", storageAddr);
  const capacity = await readContract("CapacityProofSC", capacityAddr);
  const snapshot = await readContract("PartitionSnapshotProofSC", snapshotAddr);
  const certification = await readContract(
    "CapacityCertificationSC", certificationAddr,
  );
  const incrementalAddr = manifest.contracts.CapacityIncrementalBatchSC.address;
  const incremental = await readContract(
    "CapacityIncrementalBatchSC", incrementalAddr,
  );
  const fileRegistration = await readContract(
    "FileRegistrationSC", fileRegistrationAddr,
  );
  const deletionRelease = await readContract(
    "DeletionReleaseSC", deletionReleaseAddr,
  );

  manifest.wiring = {
    "StorageProofSC.partitionSnapshotProof": await storage.partitionSnapshotProof(),
    "StorageProofSC.capacityProof": await storage.capacityProof(),
    "CapacityProofSC.partitionSnapshotProof": await capacity.partitionSnapshotProof(),
    "CapacityProofSC.storageProof": await capacity.storageProof(),
    "PartitionSnapshotProofSC.storageProof": await snapshot.storageProof(),
    "PartitionSnapshotProofSC.capacityProof": await snapshot.capacityProof(),
    // G.1A: the certification authority edge must be reciprocal in BOTH directions, or the
    // stack is talking to a certification ring that will reject every write.
    "CapacityProofSC.certificationContract": await capacity.certificationContract(),
    "CapacityCertificationSC.capacityProofSC": await certification.capacityProofSC(),
    // G.2A: exact incremental membership is only enforceable when the snapshot contract and
    // the batch contract are reciprocally bound, and the batch contract reads the same
    // CapacityProofSC the rest of the stack uses.
    "PartitionSnapshotProofSC.incrementalBatch": await snapshot.incrementalBatch(),
    "CapacityIncrementalBatchSC.snapshotProof": await incremental.snapshotProof(),
    "CapacityIncrementalBatchSC.capacityProof": await incremental.capacityProof(),
    "CapacityIncrementalBatchSC.certification": await incremental.certification(),
    "CapacityProofSC.campaignCoordinator": await capacity.campaignCoordinator(),
    "FileRegistrationSC.deletionRelease": await fileRegistration.deletionRelease(),
    "PartitionSnapshotProofSC.deletionRelease": await snapshot.deletionRelease(),
    "StorageProofSC.deletionRelease": await storage.deletionRelease(),
    "DeletionReleaseSC.fileRegistration": await deletionRelease.fileRegistration(),
    "DeletionReleaseSC.snapshotProof": await deletionRelease.snapshotProof(),
    "DeletionReleaseSC.storageProof": await deletionRelease.storageProof(),
  };
  // Fail closed if any wiring edge does not point at the manifest's own addresses.
  const mustEqual = [
    ["StorageProofSC.partitionSnapshotProof", snapshotAddr],
    ["CapacityProofSC.partitionSnapshotProof", snapshotAddr],
    ["PartitionSnapshotProofSC.storageProof", storageAddr],
    ["PartitionSnapshotProofSC.capacityProof", capacityAddr],
    ["CapacityProofSC.storageProof", storageAddr],
    ["StorageProofSC.capacityProof", capacityAddr],
    ["CapacityProofSC.certificationContract", certificationAddr],
    ["CapacityCertificationSC.capacityProofSC", capacityAddr],
    ["PartitionSnapshotProofSC.incrementalBatch", incrementalAddr],
    ["CapacityIncrementalBatchSC.snapshotProof", snapshotAddr],
    ["CapacityIncrementalBatchSC.capacityProof", capacityAddr],
    ["CapacityIncrementalBatchSC.certification", certificationAddr],
    ["CapacityProofSC.campaignCoordinator", incrementalAddr],
    ["FileRegistrationSC.deletionRelease", deletionReleaseAddr],
    ["PartitionSnapshotProofSC.deletionRelease", deletionReleaseAddr],
    ["StorageProofSC.deletionRelease", deletionReleaseAddr],
    ["DeletionReleaseSC.fileRegistration", fileRegistrationAddr],
    ["DeletionReleaseSC.snapshotProof", snapshotAddr],
    ["DeletionReleaseSC.storageProof", storageAddr],
  ];
  for (const [edge, want] of mustEqual) {
    const got = manifest.wiring[edge];
    if (String(got).toLowerCase() !== String(want).toLowerCase()) {
      throw new Error(`wiring mismatch ${edge}: on-chain ${got}, expected ${want}`);
    }
  }

  // Ring geometry is immutable per deployment; pinning it lets a consumer detect a
  // silently redeployed certification contract with different slot/ring parameters.
  // G.4B-LV0: pin the deployed proof profile. A VK whose local proof profile disagrees with
  // the deployed StorageProof configuration computes different committedBytes for the same
  // sectors, which silently blocks capacity bootstrap. Pinning it lets the VK fail fast.
  const storageProfile = await readContract("StorageProofSC", storageAddr);
  manifest.proofProfile = {
    zkBlockSizeBytes: (await storageProfile.zkBlockSizeBytes()).toString(),
    partitionCircuitSectors: (await storageProfile.partitionCircuitSectors()).toString(),
    partitionCircuitChallenges: (await storageProfile.partitionCircuitChallenges()).toString(),
    // zkTreeDepth is a deployment parameter the contract does not publish; it is pinned from
    // the deployed-addresses record written by the deploy script.
    zkTreeDepth: String((deployed.env || {}).STORAGEPROOF_ZK_TREE_DEPTH || ""),
  };

  // G.2B: pin the permanent authority-id domain constants and the enforced membership bound,
  // so a stack cannot silently run against a contract with a different namespace or limit.
  manifest.proofAuthorityDomains = {
    deletionFlag: (1n << 63n).toString(),
    incrementalFlag: (1n << 62n).toString(),
    fullIdLimit: (1n << 62n).toString(),
    maxIncrementalBatchMembers:
      (await incremental.MAX_INCREMENTAL_BATCH_MEMBERS()).toString(),
  };

  manifest.certificationRing = {
    slotSeconds: (await certification.slotSeconds()).toString(),
    ringSize: (await certification.ringSize()).toString(),
    certificationMaxProofAgeSeconds:
      (await certification.certificationMaxProofAgeSeconds()).toString(),
  };

  const out = JSON.stringify(manifest, null, 2);
  fs.writeFileSync(path.join(outputDir, "deployment_manifest.json"), out, "utf8");
  console.log(`deployment manifest written (chainId ${manifest.chainId}, ${MANIFEST_CONTRACTS.length} contracts)`);
  return manifest;
}

export const manifest = main();
manifest.catch((err) => { console.error(String(err && err.stack ? err.stack : err)); process.exitCode = 1; });
