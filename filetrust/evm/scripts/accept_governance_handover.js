// scripts/accept_governance_handover.js
//
// Completes the hand-over of the protocol contracts to the FileTrust timelock.
//
// deploy_filetrust.js transfers the OpenZeppelin-owned contracts in two steps: it names
// the timelock as their pending owner and writes the one acceptOwnership batch the
// timelock must run to reports/deployment/governance_handover.json. In the local profile
// the deployer proposes and has already scheduled it; on mainnet the proposer multisig
// schedules exactly that batch. Once the timelock delay has passed, anyone may run this
// script: it executes the batch and then checks that the timelock owns every contract and
// none still has a pending owner.
//
//   npx hardhat run scripts/accept_governance_handover.js --network filetrustLocal
//
// FILETRUST_HANDOVER_FILE names another batch file.
import fs from "node:fs";
import path from "node:path";
import { network } from "hardhat";
import { resolveRepoRoot } from "./lib/repo_paths.js";
import { executeAcceptance, verifyOwnedBy } from "./lib/governance_handover.js";
import { configureDeploymentSigner } from "./lib/deployment_signer.js";

const OWNED_ABI = [
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function acceptOwnership()",
];

async function main() {
  const { ethers } = await network.getOrCreate();
  if (!process.env.FILETRUST_DEPLOY_KEY_FILE) throw new Error("Set FILETRUST_DEPLOY_KEY_FILE for the ownership acceptance signer");
  configureDeploymentSigner(ethers, process.env.FILETRUST_DEPLOY_KEY_FILE, process.env.FILETRUST_FIXED_GAS_PRICE_WEI || "1000000");
  const file = process.env.FILETRUST_HANDOVER_FILE
    || path.join(resolveRepoRoot(process.cwd()), "reports", "deployment", "governance_handover.json");
  const batch = JSON.parse(fs.readFileSync(file, "utf8"));
  const timelock = await ethers.getContractAt("FileTrustTimelock", batch.timelock);
  const id = await timelock.hashOperationBatch(batch.targets, batch.values, batch.payloads, batch.predecessor, batch.salt);
  if (id !== batch.operationId) throw new Error(`${file} does not describe operation ${batch.operationId}`);

  if (await timelock.isOperationDone(id)) {
    console.log(`Ownership acceptance ${id} was already executed`);
  } else if (await timelock.isOperationReady(id)) {
    await executeAcceptance(timelock, batch);
    console.log(`Executed ownership acceptance ${id}`);
  } else {
    const readyAt = await timelock.getTimestamp(id);
    throw new Error(readyAt === 0n
      ? `Ownership acceptance ${id} is not scheduled: the proposer must schedule this batch first`
      : `Ownership acceptance ${id} is not ready until ${readyAt}`);
  }

  const contracts = batch.targets.map((target, i) => [batch.labels[i], new ethers.Contract(target, OWNED_ABI, ethers.provider)]);
  await verifyOwnedBy(contracts, batch.timelock);
  console.log(`The timelock owns ${batch.labels.join(", ")}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
