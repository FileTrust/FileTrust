// scripts/deploy_filetrust.js
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from 'node:url';
import { network } from "hardhat";
import { resolveRepoRoot } from "./lib/repo_paths.js";
import { writeNetworkConfigBundle } from "./network_config_bundle.js";
import { deployDkgRecovery, requireRecoveryDeployment } from './lib/dkg_recovery.js';
import { deploymentBudget,guardSignedDeploymentBroadcast } from './lib/deployment_budget.js';
import { configureDeploymentSigner } from './lib/deployment_signer.js';
import { requireGovernanceContracts, resolveGovernance } from './lib/deployment_profile.js';
import { resolvePenalties } from './lib/penalty_config.js';
import { acceptanceBatch, operationId, scheduleAcceptance, startHandover } from './lib/governance_handover.js';
import { deployVerifierRouter, registerDeployment, requireBoundRouter } from './lib/phase2_infrastructure.js';
import { requireCanonicalDeploymentArtifacts, validateDeploymentBindings } from './lib/deployment_bindings.js';

function stringifyJsonLine(value) {
  return JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? v.toString() : v));
}

function nowIsoLocal() {
  const d = new Date();
  const pad = (n) => String(Math.trunc(Math.abs(n))).padStart(2, "0");
  const offsetMin = -d.getTimezoneOffset();
  const sign = offsetMin >= 0 ? "+" : "-";
  const hh = pad(offsetMin / 60);
  const mm = pad(offsetMin % 60);
  const y = d.getFullYear();
  const mo = pad(d.getMonth() + 1);
  const da = pad(d.getDate());
  const h = pad(d.getHours());
  const mi = pad(d.getMinutes());
  const s = pad(d.getSeconds());
  return `${y}-${mo}-${da}T${h}:${mi}:${s}${sign}${hh}:${mm}`;
}

function enableMeaningfulDeployLabels() {
  const colors = {
    reset: "\x1b[0m",
    DEPLOY: "\x1b[32m",
    WIRE: "\x1b[36m",
    SKIP: "\x1b[33m",
    OK: "\x1b[32m",
    INFO: "\x1b[34m",
    CONFIG: "\x1b[35m",
    WARN: "\x1b[33m",
    ERR: "\x1b[31m",
  };
  const originalLog = console.log.bind(console);
  const originalWarn = console.warn.bind(console);
  const originalError = console.error.bind(console);
  const label = (name, value) => {
    const tag = `[${name}]`;
    if (!process.stdout.isTTY || process.env.NO_COLOR) return `${tag} ${value}`;
    return `${colors[name] || ""}${tag}${colors.reset} ${value}`;
  };

  console.log = (...args) => {
    const line = args.map(String).join(" ");
    if (line.includes("deployed to:") || line.includes("deployed as")) {
      originalLog(label("DEPLOY", args[0]), ...args.slice(1));
    } else if (line.includes(" set to:") || line.includes("authorized ") || line.includes("funded:")) {
      originalLog(label("WIRE", args[0]), ...args.slice(1));
    } else if (line.includes("skipped") || line.includes("not funded") || line.includes("not set")) {
      originalLog(label("SKIP", args[0]), ...args.slice(1));
    } else if (line.includes("Deployment completed successfully")) {
      originalLog(label("OK", args[0]), ...args.slice(1));
    } else if (line.includes("Config values:") || line.includes("Deployed addresses saved to:")) {
      originalLog(label("INFO", args[0]), ...args.slice(1));
    } else if (line.startsWith("  ") || line.includes("_ADDRESS") || line.includes("_WEI")) {
      originalLog(label("CONFIG", args[0]), ...args.slice(1));
    } else {
      originalLog(...args);
    }
  };

  console.warn = (...args) => originalWarn(label("WARN", args[0]), ...args.slice(1));
  console.error = (...args) => originalError(label("ERR", args[0]), ...args.slice(1));
}

function resolveNetworkName(connection) {
  const argIndex = process.argv.indexOf("--network");
  if (argIndex >= 0 && process.argv[argIndex + 1]) return process.argv[argIndex + 1];
  return connection?.networkName || process.env.HARDHAT_NETWORK || "hardhat";
}

function envBool(name, defaultValue = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return defaultValue;
  return ["1", "true", "yes", "on"].includes(String(raw).trim().toLowerCase());
}

function partitionVerifierContractForBlockSize(zkBlockSizeBytes) {
  if (zkBlockSizeBytes === 512) {
    return "contracts/PartitionStorageProofGnarkVerifier512.sol:Verifier";
  }
  return "contracts/PartitionStorageProofGnarkVerifier.sol:Verifier";
}

function partitionMsmLibraryForBlockSize(zkBlockSizeBytes) {
  if (zkBlockSizeBytes === 512) return "PublicInputMSMLib512";
  return "PublicInputMSMLib";
}

function createDeployTransactionLogger({ ethers, networkName, deployerAddress, logPath, budget }) {
  const addressBook = new Map();
  const txMetadata = new Map();
  const submittedTxs = new Map();
  const loggedHashes = new Set();
  let chainId = "";

  function rememberContract(address, contractName, contract) {
    if (!address) return;
    const key = String(address).toLowerCase();
    const selectors = new Map();
    for (const fragment of contract?.interface?.fragments || []) {
      if (fragment.type === "function") {
        selectors.set(fragment.selector, fragment.name);
      }
    }
    addressBook.set(key, { contractName, selectors });
  }

  function decodeCall(tx) {
    const to = tx?.to ? String(tx.to).toLowerCase() : "";
    const known = to ? addressBook.get(to) : null;
    const selector = tx?.data && tx.data !== "0x" ? tx.data.slice(0, 10) : "";
    return {
      contract_name: known?.contractName || "",
      function_name: selector ? (known?.selectors?.get(selector) || selector) : "",
    };
  }

  function normalizeSubmittedTx(hash, tx) {
    return {
      hash,
      from: tx?.from || deployerAddress,
      to: tx?.to || "",
      data: tx?.data || "0x",
      value: tx?.value || "0",
      gasPrice: tx?.gasPrice || "0",
    };
  }

  async function record(tx, receipt, extra = {}) {
    const hash = tx?.hash || receipt?.hash || receipt?.transactionHash || "";
    if (!hash || loggedHashes.has(hash)) return;
    loggedHashes.add(hash);

    if (!chainId) {
      const chain = await ethers.provider.getNetwork();
      chainId = chain.chainId.toString();
    }

    const meta = txMetadata.get(hash) || {};
    const decoded = decodeCall(tx);
    const gasUsed = BigInt(receipt?.gasUsed || 0);
    const effectiveGasPrice = BigInt(receipt?.gasPrice || receipt?.effectiveGasPrice || tx?.gasPrice || 0);
    const txGasPrice = BigInt(tx?.gasPrice || effectiveGasPrice || 0);
    const totalCostWei = gasUsed * effectiveGasPrice;
    const valueWei = BigInt(tx?.value || 0);
    const contractAddress = receipt?.contractAddress || extra.contractAddress || "";
    const kind = meta.transaction_kind || (contractAddress ? "contract_deployment" : "contract_call");
    const contractName = meta.contract_name || extra.contractName || decoded.contract_name;
    const functionName = meta.function_name || decoded.function_name;

    const line = {
      tag: meta.tag || (contractName && functionName ? `deploy:${contractName}.${functionName}` : `deploy:${kind}`),
      facility: "deploy",
      source: "deploy_filetrust.js",
      transaction_kind: kind,
      network: networkName,
      chain_id: chainId,
      timestamp: nowIsoLocal(),
      actor_address: tx?.from || deployerAddress,
      contract_name: contractName || "",
      function_name: functionName || "",
      contract_address: contractAddress || "",
      to_address: tx?.to || "",
      value_wei: valueWei.toString(),
      transaction_hash: hash,
      block_number: receipt?.blockNumber?.toString?.() || "",
      status: receipt?.status?.toString?.() || "",
      gas_used: gasUsed.toString(),
      gas_price_wei: txGasPrice.toString(),
      effective_gas_price_wei: effectiveGasPrice.toString(),
      total_cost_wei: totalCostWei.toString(),
      total_cost_eth: ethers.formatEther(totalCostWei),
    };
    fs.appendFileSync(logPath, `${stringifyJsonLine(line)}\n`, "utf8");
  }

  function patchTransactionResponse(tx) {
    if (!tx || typeof tx.wait !== "function" || tx.__fileTrustTxLoggerPatched) return tx;
    const originalWait = tx.wait.bind(tx);
    tx.wait = async (...args) => {
      const receipt = await originalWait(...args);
      await record(tx, receipt);
      return receipt;
    };
    Object.defineProperty(tx, "__fileTrustTxLoggerPatched", { value: true });
    return tx;
  }

  async function patchSigner(signer) {
    if (!signer || typeof signer.sendTransaction !== "function" || signer.__fileTrustTxLoggerPatched) return signer;
    const originalSendTransaction = signer.sendTransaction.bind(signer);
    signer.sendTransaction = async (...args) => patchTransactionResponse(await originalSendTransaction(...args));
    Object.defineProperty(signer, "__fileTrustTxLoggerPatched", { value: true });
    return signer;
  }

  function patchProvider(provider) {
    if (!provider || provider.__fileTrustTxLoggerPatched) return;
    const rememberSigned=raw=>{
      const signed=ethers.Transaction.from(raw);
      submittedTxs.set(signed.hash,normalizeSubmittedTx(signed.hash,signed));
    };
    guardSignedDeploymentBroadcast(provider,budget,rememberSigned);

    if (typeof provider.send === "function") {
      const originalSend = provider.send.bind(provider);
      provider.send = async (method, params = []) => {
        if(method==='eth_sendTransaction' && params[0]) {
          // Hardhat's RPC adapter can normally fill these fields downstream.
          // Resolve them before reserving the maximum debit, then broadcast
          // the exact bounded fields instead of relying on hidden defaults.
          const tx={...params[0]};
          if(tx.gasPrice===undefined && tx.maxFeePerGas===undefined)
            tx.gasPrice='0x'+BigInt(process.env.FILETRUST_FIXED_GAS_PRICE_WEI || '1000000').toString(16);
          if(tx.gas===undefined) {
            const estimate=BigInt(await originalSend('eth_estimateGas',[tx]));
            const margin=(estimate*6n+4n)/5n;
            tx.gas='0x'+(margin>16777216n?16777216n:margin).toString(16);
          }
          params=[tx,...params.slice(1)];
        }
        budget.reserveRpc(method,params);
        if(method==='eth_sendRawTransaction')rememberSigned(params[0]);
        const result = await originalSend(method, params);
        if (method === "eth_sendTransaction" && result && params?.[0]) {
          submittedTxs.set(String(result), normalizeSubmittedTx(String(result), params[0]));
        }
        return result;
      };
    }

    if (typeof provider.getTransactionReceipt === "function") {
      const originalGetTransactionReceipt = provider.getTransactionReceipt.bind(provider);
      provider.getTransactionReceipt = async (hash) => {
        const receipt = await originalGetTransactionReceipt(hash);
        if (receipt) {
          const tx = submittedTxs.get(String(hash));
          if (tx) await record(tx, receipt);
        }
        return receipt;
      };
    }

    Object.defineProperty(provider, "__fileTrustTxLoggerPatched", { value: true });
  }

  const originalDeployContract = ethers.deployContract.bind(ethers);
  ethers.deployContract = async (contractName, args = [], options = undefined) => {
    const contract = await originalDeployContract(contractName, args, options);
    const deploymentTx = contract.deploymentTransaction?.();
    if (deploymentTx?.hash) {
      txMetadata.set(deploymentTx.hash, {
        tag: `deploy:${contractName}`,
        transaction_kind: "contract_deployment",
        contract_name: contractName,
        function_name: "constructor",
      });
      patchTransactionResponse(deploymentTx);
    }
    const originalWaitForDeployment = contract.waitForDeployment.bind(contract);
    contract.waitForDeployment = async (...waitArgs) => {
      const deployedContract = await originalWaitForDeployment(...waitArgs);
      const address = await contract.getAddress();
      rememberContract(address, contractName, contract);
      if (deploymentTx?.hash) {
        const receipt = await ethers.provider.getTransactionReceipt(deploymentTx.hash);
        if (receipt) await record(deploymentTx, receipt, { contractName, contractAddress: address });
      }
      return deployedContract;
    };
    return contract;
  };

  const originalGetContractAt = ethers.getContractAt.bind(ethers);
  ethers.getContractAt = async (contractName, address, ...args) => {
    const contract = await originalGetContractAt(contractName, address, ...args);
    rememberContract(address, contractName, contract);
    return contract;
  };

  patchProvider(ethers.provider);

  return { patchSigner, rememberContract, logPath };
}

function candidateStorageProofVerifierNames() {
  const raw = process.env.STORAGE_PROOF_GENERATED_VERIFIER_CONTRACT || "";
  const names = [];
  for (const item of raw.split(",")) {
    const name = item.trim();
    if (name && !names.includes(name)) names.push(name);
  }
  // The checked-in gnark source exports the generic Solidity name `Verifier`.
  // Always try its fully-qualified artifact first: a bare `Verifier` becomes
  // ambiguous as soon as the partition verifiers are compiled beside it.
  for (const name of [
    "contracts/StorageProofGnarkVerifier.sol:Verifier",
    "StorageProofGnarkVerifier",
    "Groth16Verifier",
    "Verifier",
  ]) {
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

async function tryDeployFirstAvailable(ethers, names, label, args = []) {
  const errors = [];
  for (const name of names) {
    try {
      const contract = await ethers.deployContract(name, args);
      await contract.waitForDeployment();
      const address = await contract.getAddress();
      console.log(`${label} deployed as ${name} to:`, address);
      return { address, contractName: name };
    } catch (e) {
      errors.push(`${name}: ${e.message || e}`);
    }
  }
  console.warn(`${label} deployment failed for all candidate contract names:`);
  for (const err of errors) console.warn("  -", err);
  return { address: null, contractName: "" };
}

function parseSupportedZkDkgParticipantCounts() {
  const raw = process.env.ZKDKG_SUPPORTED_N || "3,5,7,10,15,20";
  const values = [];
  for (const item of raw.split(",")) {
    const n = Number.parseInt(item.trim(), 10);
    if (!Number.isInteger(n) || n < 1 || n > 20) continue;
    if (!values.includes(n)) values.push(n);
  }
  return values.length ? values : [3, 5, 7, 10, 15, 20];
}

function defaultThresholdForParticipantCount(n) {
  return Math.floor(n / 2) + 1;
}

function shippedZkDkgCommitteeProfiles(participantCounts) {
  const allowed = new Set(participantCounts);
  const profiles = [];
  const contractsRoot = path.join(process.cwd(), "contracts");
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(fullPath);
        continue;
      }
      const match = /^ShareVerifierN(\d+)T(\d+)\.sol$/.exec(entry.name);
      if (!match) continue;
      const n = Number.parseInt(match[1], 10);
      const t = Number.parseInt(match[2], 10);
      if (allowed.has(n) && t >= 2 && t <= n) profiles.push({ n, t });
    }
  };
  visit(contractsRoot);
  profiles.sort((a, b) => a.n - b.n || a.t - b.t);
  return profiles;
}

function parseSupportedZkDkgCommitteeProfiles(participantCounts) {
  // Default only to verifiers actually shipped in this release. Operators may
  // explicitly request "all" after supplying every missing generated verifier
  // or provide an exact profile list with externally deployed addresses.
  const raw = process.env.ZKDKG_SUPPORTED_PROFILES || "shipped";
  const profiles = [];
  const addProfile = (n, t) => {
    if (!Number.isInteger(n) || !Number.isInteger(t) || n < 1 || n > 20 || t < 2 || t > n) return;
    if (!profiles.some((profile) => profile.n === n && profile.t === t)) profiles.push({ n, t });
  };
  if (["shipped", "bundled", "default"].includes(raw.trim().toLowerCase())) {
    for (const profile of shippedZkDkgCommitteeProfiles(participantCounts)) {
      addProfile(profile.n, profile.t);
    }
  } else if (["all", "full", "*"].includes(raw.trim().toLowerCase())) {
    for (const n of participantCounts) {
      for (let t = 2; t <= n; t++) addProfile(n, t);
    }
  } else if (raw.trim()) {
    for (const item of raw.split(",")) {
      const [left, right] = item.split(/[:/]/).map((part) => part?.trim());
      addProfile(Number.parseInt(left, 10), Number.parseInt(right, 10));
    }
  }
  if (!profiles.length) throw new Error("No supported zkDKG committee verifier profiles were configured");
  return profiles;
}

function parseAddressMap(raw) {
  const out = {};
  for (const item of String(raw || "").split(",")) {
    const [left, right] = item.split(/[:=]/).map((part) => part?.trim());
    const n = Number.parseInt(left, 10);
    if (Number.isInteger(n) && right) out[n] = right;
  }
  return out;
}

function parseCommitteeAddressMap(raw) {
  const out = {};
  for (const item of String(raw || "").split(",")) {
    const [profilePart, addressPart] = item.split("=").map((part) => part?.trim());
    if (!profilePart || !addressPart) continue;
    const [nPart, tPart] = profilePart.split(/[:/]/).map((part) => part?.trim());
    const n = Number.parseInt(nPart, 10);
    const t = Number.parseInt(tPart, 10);
    if (Number.isInteger(n) && Number.isInteger(t)) out[`${n}:${t}`] = addressPart;
  }
  return out;
}

function verifierAddressFromEnv(n) {
  const map = parseAddressMap(process.env.ZKDKG_SHARE_VERIFIER_ADDRESSES || "");
  return (
    process.env[`ZKDKG_SHARE_VERIFIER_ADDRESS_N${n}`]
    || process.env[`ZKDKG_SHARE_VERIFIER_${n}_ADDRESS`]
    || map[n]
    || ""
  );
}

function committeeVerifierAddressFromEnv(n, t) {
  const map = parseCommitteeAddressMap(process.env.ZKDKG_SHARE_VERIFIER_PROFILE_ADDRESSES || "");
  return (
    process.env[`ZKDKG_SHARE_VERIFIER_ADDRESS_N${n}_T${t}`]
    || process.env[`ZKDKG_SHARE_VERIFIER_${n}_${t}_ADDRESS`]
    || map[`${n}:${t}`]
    || ""
  );
}

async function main() {
  requireRecoveryDeployment(process.env.FILETRUST_DKG_ATTEMPT_PROTOCOL);
  requireCanonicalDeploymentArtifacts(process.cwd(), fileURLToPath(new URL('..', import.meta.url)));
  enableMeaningfulDeployLabels();

  const connection = await network.getOrCreate();
  const { ethers } = connection;
  if(process.env.FILETRUST_DEPLOY_KEY_FILE)
    configureDeploymentSigner(ethers,process.env.FILETRUST_DEPLOY_KEY_FILE,process.env.FILETRUST_FIXED_GAS_PRICE_WEI || '1000000');
  const networkName = resolveNetworkName(connection);
  const signers = await ethers.getSigners();
  const [deployer] = signers;
  const deployerAddress = await deployer.getAddress();
  // Who the protocol is handed to, and where slashed stake goes, is settled before the first
  // transaction: an incomplete or unsafe mainnet configuration stops here (Phase 1B F11).
  const governance = resolveGovernance(process.env, { deployer: deployerAddress });
  await requireGovernanceContracts(ethers.provider, governance);
  console.log(`Deployment profile: ${governance.profile}`);
  // MIN_GUARDIAN_STAKE — minimum native token (FTU) a Guardian, and through
  // StakingManager a Vault Keeper, must stake to register (default 1 FTU).
  // Guardians and VKs read this minimum from the chain and stake at least it.
  const minGuardianStake = ethers.parseEther(process.env.MIN_GUARDIAN_STAKE || "1");
  // Guardian penalties, in aftu (1 FTU = 10^18 aftu), each at most 1% of MIN_GUARDIAN_STAKE,
  // checked here, before the first transaction (Phase 1C):
  // MISSED_EPOCH_PENALTY_WEI         — slashed per missed share-proof epoch (default 0.001 FTU):
  //                                    10% to an independent reporter, 90% to the treasury.
  // VERIFIED_DKG_COMPLAINT_SLASH_WEI — fined per verified DKG complaint (default 0.001 FTU), to the
  //                                    treasury, counted toward the same complaint's penalty points.
  // The wrong-proof slash rates (WRONG_PROOF_SLASH_BPS, WRONG_PROOF_SUSPEND_SLASH_BPS, below) are
  // checked here too: at most 5,000 basis points each, the suspension rate not below the slash rate.
  const {
    missedEpochPenaltyWei, verifiedDkgComplaintSlashWei, wrongProofSlashBps, wrongProofSuspendSlashBps,
  } = resolvePenalties(process.env, { minGuardianStake });
  const blockchainDir = process.cwd();
  const repoRoot = resolveRepoRoot(blockchainDir);
  // Keep deployment records separate from the source tree.
  const reportsDir = path.join(repoRoot, "reports", "deployment");
  const transactionLogsDir = path.join(reportsDir, "transaction_logs");
  fs.mkdirSync(transactionLogsDir, { recursive: true });
  const budget=deploymentBudget({maximumWei:process.env.FILETRUST_DEPLOY_MAX_DEBIT_WEI,
    address:deployerAddress,chainId:(await ethers.provider.getNetwork()).chainId,
    journal:path.join(transactionLogsDir,'deployment_budget.jsonl')});
  const deployTransactionLogPath = path.join(transactionLogsDir, "deploy_filetrust_transactions.jsonl");
  fs.writeFileSync(deployTransactionLogPath, "", "utf8");
  const deployTxLogger = createDeployTransactionLogger({
    ethers,
    networkName,
    deployerAddress,
    budget,
    logPath: deployTransactionLogPath,
  });
  await Promise.all(signers.map((signer) => deployTxLogger.patchSigner(signer)));

  // Join reward: how much each new Guardian receives on first registration.
  // GUARDIAN_JOIN_REWARD_WEI      — reward per Guardian join (default 0.005 ETH)
  // GUARDIAN_JOIN_REWARD_POOL_WEI — FTU seeded into pool at deploy (default 2 FTU = 400 joins)
  const joinRewardWei = BigInt(process.env.GUARDIAN_JOIN_REWARD_WEI || "5000000000000000"); // 0.005 ETH
  const joinRewardPoolWei = BigInt(process.env.GUARDIAN_JOIN_REWARD_POOL_WEI || "2000000000000000000"); // 2 FTU

  // Proof reward: how much each Guardian receives per valid daily share proof.
  // GUARDIAN_PROOF_REWARD_WEI      — reward per valid proof (default 0.001 ETH)
  // GUARDIAN_PROOF_REWARD_POOL_WEI — FTU seeded into pool at deploy (default 2 FTU = 2000 proofs)
  const proofRewardWei = BigInt(process.env.GUARDIAN_PROOF_REWARD_WEI || "1000000000000000"); // 0.001 ETH
  const proofRewardPoolWei = BigInt(process.env.GUARDIAN_PROOF_REWARD_POOL_WEI || "2000000000000000000"); // 2 FTU

  // Reporter / economic config (MISSED_EPOCH_PENALTY_WEI is read above, with the other penalty).
  // REPORTER_BATCH_SIZE           — max Guardians processed per batch report transaction (default 500, tune to block gas limit).
  // SU_TO_WEI_RATE                — storage-unit to wei conversion rate used for gas reimbursements (default 1e12 wei/SU).
  // FILETRUST_FIXED_GAS_PRICE_WEI — fixed gas price (wei) used when estimating reimbursement costs (default 1,000,000 wei).
  const reporterBatchSize = BigInt(process.env.REPORTER_BATCH_SIZE || "500");
  const admissionReporterAddress = process.env.ADMISSION_REPORTER_ADDRESS
    || process.env.REPORTER_ADDRESS
    || "0x1cbd3b2770909d4e10f157cabc84c7264073c9ec";
  const suToWeiRate = BigInt(process.env.SU_TO_WEI_RATE || "1000000000000");
  const fixedGasPriceWei = BigInt(process.env.FILETRUST_FIXED_GAS_PRICE_WEI || "1000000");
  // VK_PIECE_TX_COST_GAS — gas a VK spends on one piece's own transactions, store plus
  // delete, paid back to it in full when the data owner deletes early (VKEscrow
  // deletionTxCostEstimate). Without it an early deletion pays the VK only the time it
  // stored, which for a small piece is less than the transactions the piece cost it.
  // Default: the fair average measured on a live run (132 stores, 33 deletes):
  // 4,476,524 gas = fixed store 673,000 + fixed delete 709,912 + 2 x 1,546,806 average
  // data-partition update and proof work per store or delete. Rounded up.
  // VKs also never quote a price below this, so the escrow can always pay it.
  const vkPieceTxCostGas = BigInt(process.env.VK_PIECE_TX_COST_GAS || "4500000");

  // VK reward pools (early-stage incentives). Set a value to 0 to switch one off.
  // VK_JOIN_REWARD_WEI       — FTU paid to each VK on first registration (default 0.005)
  // VK_JOIN_REWARD_POOL_WEI  — FTU seeded into join pool at deploy (default 2 = 400 joins)
  // VK_PROOF_REWARD_WEI      — FTU paid to VK per successful storage proof (default 0.001)
  // VK_PROOF_REWARD_POOL_WEI — FTU seeded into proof pool at deploy (default 2 = 2000 proofs)
  // All five pools together: 10 FTU from the deployer.
  const vkJoinRewardWei      = BigInt(process.env.VK_JOIN_REWARD_WEI      || "5000000000000000");  // 0.005 ETH
  const vkJoinRewardPoolWei  = BigInt(process.env.VK_JOIN_REWARD_POOL_WEI  || "2000000000000000000"); // 2 FTU
  const vkProofRewardWei     = BigInt(process.env.VK_PROOF_REWARD_WEI     || "1000000000000000");  // 0.001 ETH
  const vkProofRewardPoolWei = BigInt(process.env.VK_PROOF_REWARD_POOL_WEI || "2000000000000000000"); // 2 FTU
  // VK_FILE_REWARD_WEI       — ETH paid per successfully completed file (claimEscrow)
  // VK_FILE_REWARD_POOL_WEI  — FTU seeded into file completion pool at deploy (default 2 = 1000 files)
  const vkFileRewardWei      = BigInt(process.env.VK_FILE_REWARD_WEI      || "2000000000000000");  // 0.002 ETH
  const vkFileRewardPoolWei  = BigInt(process.env.VK_FILE_REWARD_POOL_WEI  || "2000000000000000000"); // 2 FTU
  // VK capacity reward: paid once for the space a VK proves, per GB (1e9 bytes), up to a
  // limit per VK, inside the proof transactions it already sends. Zero rate or zero limit
  // switches it off. The rate and limit stay adjustable on RewardManager (through
  // governance after deploy).
  // VK_CAPACITY_REWARD_PER_GB_WEI — FTU per proven GB (default 0.001)
  // VK_CAPACITY_REWARD_CAP_WEI    — most one VK can receive (default 1 FTU = 1000 GB)
  // VK_CAPACITY_REWARD_POOL_WEI   — FTU seeded into the pool at deploy (default 2)
  const vkCapacityRewardPerGbWei = BigInt(process.env.VK_CAPACITY_REWARD_PER_GB_WEI || "1000000000000000");  // 0.001 FTU
  const vkCapacityRewardCapWei   = BigInt(process.env.VK_CAPACITY_REWARD_CAP_WEI    || "1000000000000000000"); // 1 FTU
  const vkCapacityRewardPoolWei  = BigInt(process.env.VK_CAPACITY_REWARD_POOL_WEI   || "2000000000000000000"); // 2 FTU
  // Guardian work reward (GuardianWorkReward contract): an early-network pool paid inside the
  // DKG and PRE transactions Guardians already send, on the same events that earn reputation.
  // One limit per Guardian covers all three. Zero switches a reward off. The amounts stay
  // adjustable on GuardianWorkReward (through governance after deploy).
  // GUARDIAN_DKG_REWARD_WEI        — each Guardian of a finished DKG (default 0.0005 FTU)
  // GUARDIAN_PRE_REWARD_WEI        — a Guardian whose PRE part was used (default 0.0005 FTU)
  // GUARDIAN_PRE_READY_REWARD_WEI  — a Guardian ready for a PRE that did not need it (default 0.0002 FTU)
  // GUARDIAN_WORK_REWARD_CAP_WEI   — most one Guardian can receive (default 1 FTU)
  // GUARDIAN_WORK_REWARD_POOL_WEI  — FTU seeded into the pool at deploy (default 2)
  const guardianDkgRewardWei      = BigInt(process.env.GUARDIAN_DKG_REWARD_WEI       || "500000000000000");     // 0.0005 FTU
  const guardianPreRewardWei      = BigInt(process.env.GUARDIAN_PRE_REWARD_WEI       || "500000000000000");     // 0.0005 FTU
  const guardianPreReadyRewardWei = BigInt(process.env.GUARDIAN_PRE_READY_REWARD_WEI || "200000000000000");     // 0.0002 FTU
  const guardianWorkRewardCapWei  = BigInt(process.env.GUARDIAN_WORK_REWARD_CAP_WEI  || "1000000000000000000"); // 1 FTU
  const guardianWorkRewardPoolWei = BigInt(process.env.GUARDIAN_WORK_REWARD_POOL_WEI || "2000000000000000000"); // 2 FTU
  // Wrong-proof escalation thresholds and slash sizes (all configurable via env vars):
  // WRONG_PROOF_REP_THRESHOLD     — consecutive wrong proofs before reputation penalty starts (default 3)
  // WRONG_PROOF_SLASH_THRESHOLD   — consecutive wrong proofs before small stake slash (default 6)
  // WRONG_PROOF_SUSPEND_THRESHOLD — consecutive wrong proofs before large slash + suspension (default 10)
  // WRONG_PROOF_SLASH_BPS         — basis points of stake slashed at slash level (default 50 = 0.5%; read above)
  // WRONG_PROOF_SUSPEND_SLASH_BPS — basis points of stake slashed at suspend level (default 200 = 2%; read above)
  // WRONG_PROOF_SUSPEND_SECONDS   — suspension duration in seconds (default 86400 = 24h)
  const wrongProofRepThreshold     = parseInt(process.env.WRONG_PROOF_REP_THRESHOLD     || "3");
  const wrongProofSlashThreshold   = parseInt(process.env.WRONG_PROOF_SLASH_THRESHOLD   || "6");
  const wrongProofSuspendThreshold = parseInt(process.env.WRONG_PROOF_SUSPEND_THRESHOLD || "10");
  const wrongProofSuspendSeconds   = parseInt(process.env.WRONG_PROOF_SUSPEND_SECONDS   || "86400");
  const storageRegistrationTimeoutSeconds = parseInt(
    process.env.STORAGE_REGISTRATION_TIMEOUT_SECONDS || "600",
  );
  if (!Number.isInteger(storageRegistrationTimeoutSeconds) || storageRegistrationTimeoutSeconds < 60) {
    throw new Error("STORAGE_REGISTRATION_TIMEOUT_SECONDS must be an integer >= 60");
  }
  const maxStorageRegistrationTimeoutSeconds = parseInt(
    process.env.MAX_STORAGE_REGISTRATION_TIMEOUT_SECONDS || "604800",
  );
  if (!Number.isInteger(maxStorageRegistrationTimeoutSeconds) ||
      maxStorageRegistrationTimeoutSeconds < 600 ||
      maxStorageRegistrationTimeoutSeconds > 30 * 86400) {
    throw new Error(
      "MAX_STORAGE_REGISTRATION_TIMEOUT_SECONDS must be between 600 and 2592000",
    );
  }
  const capacityMaxProofAgeSeconds = BigInt(
    process.env.CAPACITY_MAX_PROOF_AGE_SECONDS || "108000",
  );
  const capacityMaxManifestOverheadBytes = BigInt(
    process.env.CAPACITY_MAX_MANIFEST_OVERHEAD_BYTES || "18446744073709551615",
  );
  if (capacityMaxManifestOverheadBytes <= 0n ||
      capacityMaxManifestOverheadBytes > 18446744073709551615n) {
    throw new Error("CAPACITY_MAX_MANIFEST_OVERHEAD_BYTES must fit uint64 and be positive");
  }
  // Guardian DKG/PRE operation prices in storage units (SU), used for gas reimbursements.
  // DKG_MATERIAL_SU              — SU cost for a DKG material contribution (default 12000).
  // DKG_SHARE_KEY_SU             — SU cost for a DKG share-key submission (default 6325).
  // DKG_FINALIZATION_SU          — SU cost for DKG finalization (default 0 = free).
  // PRE_BATCH_PARTIAL_SU         — SU cost per partial PRE batch contribution (default 30542).
  // PRE_READY_NOT_USED_SU        — SU cost when a PRE-ready Guardian is not selected (default 20).
  // V2_DKG_BASE_SU               — base SU cost for a v2 DKG operation (default 100).
  // V2_PRE_BASE_SU               — base SU cost for a v2 PRE operation (default 50).
  // GAS_REIMBURSEMENT_BUFFER_BPS — buffer added on top of gas estimates in basis points (default 1000 = 10%).
  const rewardPrices = {
    dkgMaterialSu: BigInt(process.env.DKG_MATERIAL_SU || "12000"),
    dkgShareKeySu: BigInt(process.env.DKG_SHARE_KEY_SU || "6325"),
    dkgFinalizationSu: BigInt(process.env.DKG_FINALIZATION_SU || "0"),
    preBatchPartialSu: BigInt(process.env.PRE_BATCH_PARTIAL_SU || "30542"),
    preReadyNotUsedSu: BigInt(process.env.PRE_READY_NOT_USED_SU || "20"),
    v2DkgBaseSu: BigInt(process.env.V2_DKG_BASE_SU || "100"),
    v2PreBaseSu: BigInt(process.env.V2_PRE_BASE_SU || "50"),
    gasReimbursementBufferBps: BigInt(process.env.GAS_REIMBURSEMENT_BUFFER_BPS || "1000"),
  };
  // Gas overhead/estimate constants used for reimbursement calculations.
  // OVERHEAD_GAS_V2_DKG_MATERIAL     — fixed overhead gas for v2 DKG material tx (default 260000).
  // OVERHEAD_GAS_V2_DKG_SHARE_KEY    — fixed overhead gas for v2 DKG share-key tx (default 70000).
  // OVERHEAD_GAS_V2_PRE_BATCH_PARTIAL — fixed overhead gas for v2 PRE partial tx (default 120000).
  // ESTIMATED_GAS_V2_DKG_MATERIAL    — full estimated gas for v2 DKG material tx (default 520000).
  // ESTIMATED_GAS_V2_DKG_SHARE_KEY   — full estimated gas for v2 DKG share-key tx (default 190000).
  // ESTIMATED_GAS_V2_PRE_BATCH_PARTIAL — full estimated gas for v2 PRE partial tx (default 1250000).
  const rewardGasConfig = {
    overheadDkgMaterial: BigInt(process.env.OVERHEAD_GAS_V2_DKG_MATERIAL || "260000"),
    overheadDkgShareKey: BigInt(process.env.OVERHEAD_GAS_V2_DKG_SHARE_KEY || "70000"),
    overheadPreBatchPartial: BigInt(process.env.OVERHEAD_GAS_V2_PRE_BATCH_PARTIAL || "120000"),
    estimateDkgMaterial: BigInt(process.env.ESTIMATED_GAS_V2_DKG_MATERIAL || "520000"),
    estimateDkgShareKey: BigInt(process.env.ESTIMATED_GAS_V2_DKG_SHARE_KEY || "190000"),
    estimatePreBatchPartial: BigInt(process.env.ESTIMATED_GAS_V2_PRE_BATCH_PARTIAL || "1250000"),
  };
  // StorageProof circuit and timing parameters.
  // STORAGE_PROOF_GENERATED_VERIFIER_ADDRESS — address of an already-deployed gnark verifier (skip compile if set).
  // STORAGE_PROOF_VERIFIER_ADDRESS           — address of an already-deployed verifier adapter (skip deploy if set).
  // STORAGE_PROOF_PERIOD_SECONDS             — length of one proof period in seconds (default 86400 = 1 day).
  // STORAGE_PROOF_DEADLINE_SECONDS           — window after challenge open to submit proof (default 21600 s = 6 h).
  // STORAGE_PROOF_MAX_CHALLENGES             — max challenge indices per proof (default 4).
  const storageProofZkBlockSize = parseInt(process.env.STORAGEPROOF_ZK_BLOCK_SIZE || process.env.ZK_BLOCK_SIZE || "128");
  const storageProofZkTreeDepth = parseInt(process.env.STORAGEPROOF_ZK_TREE_DEPTH || process.env.ZK_TREE_DEPTH || "28");
  const storageProofConfig = {
    generatedVerifier: process.env.STORAGE_PROOF_GENERATED_VERIFIER_ADDRESS || "",
    existingVerifierAdapter: process.env.STORAGE_PROOF_VERIFIER_ADDRESS || "",
    periodSeconds: BigInt(process.env.STORAGE_PROOF_PERIOD_SECONDS || "86400"),
    deadlineSeconds: BigInt(process.env.STORAGE_PROOF_DEADLINE_SECONDS || "21600"),
    maxChallenges: BigInt(process.env.STORAGE_PROOF_MAX_CHALLENGES || "4"),
  };
  const shareProofConfig = {
    periodSeconds: BigInt(process.env.SHARE_PROOF_PERIOD_SECONDS || "86400"),
    graceSeconds: BigInt(process.env.SHARE_PROOF_GRACE_SECONDS || "3600"),
    slotSeconds: BigInt(process.env.SHARE_PROOF_SLOT_SECONDS || "300"),
    windowSeconds: BigInt(process.env.SHARE_PROOF_WINDOW_SECONDS || "300"),
    avgBlockSeconds: BigInt(process.env.SHARE_PROOF_AVG_BLOCK_SECONDS || "12"),
    enforceWindow: envBool("SHARE_PROOF_WINDOW_ENFORCED", true),
  };
  // ZKDKG_KEYGEN_DEADLINE_SECONDS — max allowed keygen window in ZkDkgCoordinatorV2.
  // This is set at deploy-time via setDkgKeyGenDeadline(uint64).
  const dkgKeyGenDeadlineSeconds = BigInt(process.env.ZKDKG_KEYGEN_DEADLINE_SECONDS || "900");
  const dkgDisputePeriodSeconds = BigInt(process.env.ZKDKG_DISPUTE_PERIOD_SECONDS || "3600");
  if(dkgDisputePeriodSeconds<=0n || dkgDisputePeriodSeconds>86400n)
    throw new Error('Choose a positive bounded ZKDKG_DISPUTE_PERIOD_SECONDS');

  // VK reputation parameters.
  // REP_INITIAL_REPUTATION  — starting reputation score for new guardians (default 1000).
  // REP_MAX_REPUTATION      — reputation score ceiling (default 10000).
  // REP_SERIOUS_THRESHOLD   — penalty-point total that triggers a stake slash (default 20).
  // REP_PROOF_SUCCESS_DELTA — reputation gained per successful partition proof (default 1).
  // REP_PENALTY_WARNING     — reputation lost on 1st valid dispute (default 50).
  // REP_PENALTY_MINOR       — reputation lost on 2nd–3rd valid dispute (default 100).
  // REP_PENALTY_MAJOR       — reputation lost on 4th–5th valid dispute (default 200).
  // REP_PENALTY_MALICIOUS   — reputation lost on 6th+ valid dispute (default 500).
  const repConfig = {
    initialReputation:      parseInt(process.env.REP_INITIAL_REPUTATION  || "1000"),
    maxReputation:          parseInt(process.env.REP_MAX_REPUTATION       || "10000"),
    seriousPenaltyThreshold: parseInt(process.env.REP_SERIOUS_THRESHOLD  || "20"),
    proofSuccessDelta:      parseInt(process.env.REP_PROOF_SUCCESS_DELTA  || "1"),
    penaltyWarning:         parseInt(process.env.REP_PENALTY_WARNING      || "50"),
    penaltyMinor:           parseInt(process.env.REP_PENALTY_MINOR        || "100"),
    penaltyMajor:           parseInt(process.env.REP_PENALTY_MAJOR        || "200"),
    penaltyMalicious:       parseInt(process.env.REP_PENALTY_MALICIOUS    || "500"),
  };

  // The timelock comes first. In the local profile it is also the protocol treasury, and
  // StakingManager needs a treasury contract at construction. Its proposer, executor and
  // independent canceller come from the deployment profile above.
  const timelock = await ethers.deployContract("FileTrustTimelock", [
    governance.delay,
    governance.proposers,
    governance.executors,
    governance.cancellers,
  ]);
  await timelock.waitForDeployment();
  const timelockAddress = await timelock.getAddress();
  console.log("FileTrustTimelock deployed to:", timelockAddress);
  const treasuryAddress = governance.treasury || timelockAddress;
  console.log("Protocol treasury:", treasuryAddress, governance.treasury ? "" : "(the timelock: local profile default)");

  const guardianRegistry = await ethers.deployContract("GuardianRegistry", [minGuardianStake]);
  await guardianRegistry.waitForDeployment();
  const guardianRegistryAddress = await guardianRegistry.getAddress();
  console.log("GuardianRegistry deployed to:", guardianRegistryAddress);

  const acl = await ethers.deployContract("AccessControlFT");
  await acl.waitForDeployment();
  const aclAddress = await acl.getAddress();
  console.log("AccessControlFT deployed to:", aclAddress);

  const dataVault = await ethers.deployContract("DataVault", [aclAddress]);
  await dataVault.waitForDeployment();
  const dvAddress = await dataVault.getAddress();
  console.log("DataVault deployed to:", dvAddress);

  const deployLegacy = process.env.DEPLOY_LEGACY === "1";
  let dkgAddress = null;
  if (deployLegacy) {
    try {
      const dkg = await ethers.deployContract("DKG", [aclAddress]);
      await dkg.waitForDeployment();
      dkgAddress = await dkg.getAddress();
      console.log("DKG deployed to:", dkgAddress);
    } catch (e) {
      console.warn("DKG deployment failed (skipping):", e.message || e);
    }
  } else {
    console.log("DKG legacy deployment skipped (active flow is ZKDKG_V2-only)");
  }

  const zkDkgSupportedParticipantCounts = parseSupportedZkDkgParticipantCounts();
  const zkDkgSupportedCommitteeProfiles = parseSupportedZkDkgCommitteeProfiles(zkDkgSupportedParticipantCounts);
  const zkDkgShareVerifierAddressesByN = {};
  const zkDkgShareVerifierAddressesByProfile = {};
  let zkDkgShareVerifierAddress = process.env.ZKDKG_SHARE_VERIFIER_ADDRESS || null;
  if (!zkDkgShareVerifierAddress) {
    try {
      const verifier = await ethers.deployContract("ShareVerifier");
      await verifier.waitForDeployment();
      zkDkgShareVerifierAddress = await verifier.getAddress();
      console.log("zkDKG ShareVerifier deployed to:", zkDkgShareVerifierAddress);
    } catch (e) {
      console.warn("zkDKG ShareVerifier deployment failed (skipping):", e.message || e);
    }
  } else {
    console.log("Using existing zkDKG ShareVerifier:", zkDkgShareVerifierAddress);
  }

  for (const profile of zkDkgSupportedCommitteeProfiles) {
    const { n, t } = profile;
    const key = `${n}:${t}`;
    const configured = committeeVerifierAddressFromEnv(n, t);
    if (configured) {
      zkDkgShareVerifierAddressesByProfile[key] = configured;
      console.log(`Using existing zkDKG ShareVerifier for N=${n}, T=${t}:`, configured);
      continue;
    }
    if (n === 5 && t === defaultThresholdForParticipantCount(5) && zkDkgShareVerifierAddress) {
      zkDkgShareVerifierAddressesByProfile[key] = zkDkgShareVerifierAddress;
      continue;
    }
    const deployed = await tryDeployFirstAvailable(
      ethers,
      [`ShareVerifierN${n}T${t}`, `ShareVerifier${n}T${t}`],
      `zkDKG ShareVerifier N=${n} T=${t}`,
    );
    if (deployed.address) {
      zkDkgShareVerifierAddressesByProfile[key] = deployed.address;
    }
  }

  for (const n of zkDkgSupportedParticipantCounts) {
    const configured = verifierAddressFromEnv(n);
    if (configured) {
      zkDkgShareVerifierAddressesByN[n] = configured;
      console.log(`Using existing zkDKG ShareVerifier for N=${n}:`, configured);
      continue;
    }
    if (n === 5 && zkDkgShareVerifierAddress) {
      zkDkgShareVerifierAddressesByN[n] = zkDkgShareVerifierAddress;
    }
  }
  const missingZkDkgProfiles = zkDkgSupportedCommitteeProfiles
    .map(({ n, t }) => `${n}:${t}`)
    .filter((profile) => !zkDkgShareVerifierAddressesByProfile[profile]);
  if (missingZkDkgProfiles.length > 0) {
    throw new Error(
      "Missing required threshold-specific zkDKG verifier coverage: " +
      `profiles=[${missingZkDkgProfiles.join(",")}]`,
    );
  }

  let v2PrePartialVerifierAddress = process.env.V2_PRE_PARTIAL_VERIFIER_ADDRESS || null;
  if (!v2PrePartialVerifierAddress) {
    try {
      const verifier = await ethers.deployContract("V2PrePartialVerifier");
      await verifier.waitForDeployment();
      v2PrePartialVerifierAddress = await verifier.getAddress();
      console.log("V2PrePartialVerifier deployed to:", v2PrePartialVerifierAddress);
    } catch (e) {
      console.warn("V2PrePartialVerifier deployment failed (skipping):", e.message || e);
    }
  } else {
    console.log("Using existing V2PrePartialVerifier:", v2PrePartialVerifierAddress);
  }

  let sharePossessionVerifierAddress = process.env.SHARE_POSSESSION_VERIFIER_ADDRESS || null;
  if (!sharePossessionVerifierAddress) {
    try {
      const verifier = await ethers.deployContract("SharePossessionVerifier");
      await verifier.waitForDeployment();
      sharePossessionVerifierAddress = await verifier.getAddress();
      console.log("SharePossessionVerifier deployed to:", sharePossessionVerifierAddress);
    } catch (e) {
      console.warn("SharePossessionVerifier deployment failed (skipping):", e.message || e);
    }
  } else {
    console.log("Using existing SharePossessionVerifier:", sharePossessionVerifierAddress);
  }

  // Phase 2: each consumer binds a FileTrustVerifierRouter once, never the verifier itself,
  // so a key is replaced through the timelock with a bounded transition window.
  let sharePossessionRouterAddress = "";
  let prePartialRouterAddress = "";
  let partitionRouterAddress = "";

  let zkDkgDisputeManagerAddress = null;
  const hasAnyZkDkgShareVerifier = Boolean(zkDkgShareVerifierAddress)
    || Object.keys(zkDkgShareVerifierAddressesByN).length > 0
    || Object.keys(zkDkgShareVerifierAddressesByProfile).length > 0;
  if (hasAnyZkDkgShareVerifier) {
    try {
      const manager = await ethers.deployContract(
        "ZkDkgDisputeManager",
        [aclAddress, dkgAddress || ethers.ZeroAddress, zkDkgShareVerifierAddress || ethers.ZeroAddress],
      );
      await manager.waitForDeployment();
      zkDkgDisputeManagerAddress = await manager.getAddress();
      console.log("ZkDkgDisputeManager deployed to:", zkDkgDisputeManagerAddress);
      for (const profile of zkDkgSupportedCommitteeProfiles) {
        const { n, t } = profile;
        const verifierAddress = zkDkgShareVerifierAddressesByProfile[`${n}:${t}`];
        if (!verifierAddress) {
          console.warn(`zkDKG ShareVerifier for N=${n}, T=${t} not registered; build/deploy ShareVerifierN${n}T${t} before using that committee profile disputes.`);
          continue;
        }
        await (await manager.setZkDkgShareVerifierForCommittee(n, t, verifierAddress)).wait();
        console.log(`ZkDkgDisputeManager ShareVerifier N=${n} T=${t} set to:`, verifierAddress);
      }
      for (const n of zkDkgSupportedParticipantCounts) {
        const verifierAddress = zkDkgShareVerifierAddressesByN[n];
        if (verifierAddress) {
          await (await manager.setZkDkgShareVerifierForParticipantCount(n, verifierAddress)).wait();
          console.log(`ZkDkgDisputeManager fallback ShareVerifier N=${n} set to:`, verifierAddress);
        }
      }
    } catch (e) {
      console.warn("ZkDkgDisputeManager deployment failed (skipping):", e.message || e);
    }
  }

  let zkDkgCoordinatorV2Address = null;
  if (zkDkgDisputeManagerAddress) {
    try {
      const coordinator = await ethers.deployContract(
        "ZkDkgCoordinatorV2",
        [aclAddress, zkDkgDisputeManagerAddress],
      );
      await coordinator.waitForDeployment();
      zkDkgCoordinatorV2Address = await coordinator.getAddress();
      console.log("ZkDkgCoordinatorV2 deployed to:", zkDkgCoordinatorV2Address);
    } catch (e) {
      console.warn("ZkDkgCoordinatorV2 deployment failed (skipping):", e.message || e);
    }
  }

  let guardianShareProofAddress = null;
  if (zkDkgCoordinatorV2Address) {
    try {
      const shareProof = await ethers.deployContract(
        "GuardianShareProof",
        [aclAddress, zkDkgCoordinatorV2Address],
      );
      await shareProof.waitForDeployment();
      guardianShareProofAddress = await shareProof.getAddress();
      console.log("GuardianShareProof deployed to:", guardianShareProofAddress);
    } catch (e) {
      console.warn("GuardianShareProof deployment failed (skipping):", e.message || e);
    }
  }

  let telgAddress = null;
  if (deployLegacy && dkgAddress) {
    try {
      const telg = await ethers.deployContract("TElG", [aclAddress, dvAddress, dkgAddress]);
      await telg.waitForDeployment();
      telgAddress = await telg.getAddress();
      console.log("TElG deployed to:", telgAddress);
    } catch (e) {
      console.warn("TElG deployment failed (skipping):", e.message || e);
    }
  } else {
    console.log("TElG legacy deployment skipped (active flow uses TElGv2)");
  }

  const reputationManager = await ethers.deployContract("ReputationManager");
  await reputationManager.waitForDeployment();
  const reputationManagerAddress = await reputationManager.getAddress();
  console.log("ReputationManager deployed to:", reputationManagerAddress);

  const stakingManager = await ethers.deployContract("StakingManager", [minGuardianStake, treasuryAddress]);
  await stakingManager.waitForDeployment();
  const stakingManagerAddress = await stakingManager.getAddress();
  console.log("StakingManager deployed to:", stakingManagerAddress);
  // Slashing and reward rights are bound once, after every protocol contract that needs
  // them exists; afterwards they can only be revoked (Phase 1B F4, F6). Only contracts
  // that actually call StakingManager or RewardManager are listed.
  const slashers = [];
  const rewarders = [];

  const rewardManager = await ethers.deployContract("RewardManager", [aclAddress, suToWeiRate]);
  await rewardManager.waitForDeployment();
  const rewardManagerAddress = await rewardManager.getAddress();
  console.log("RewardManager deployed to:", rewardManagerAddress);
  await (await rewardManager.setFixedGasPriceWei(fixedGasPriceWei)).wait();
  console.log("RewardManager.fixedGasPriceWei set to:", fixedGasPriceWei.toString());
  await (await rewardManager.setRewardGasConfig(
    rewardGasConfig.overheadDkgMaterial,
    rewardGasConfig.overheadDkgShareKey,
    rewardGasConfig.overheadPreBatchPartial,
    rewardGasConfig.estimateDkgMaterial,
    rewardGasConfig.estimateDkgShareKey,
    rewardGasConfig.estimatePreBatchPartial,
  )).wait();
  console.log("RewardManager reward gas config set");
  await (await rewardManager.setPrices(
    rewardPrices.dkgMaterialSu,
    rewardPrices.dkgShareKeySu,
    rewardPrices.dkgFinalizationSu,
    rewardPrices.preBatchPartialSu,
    rewardPrices.preReadyNotUsedSu,
    rewardPrices.v2DkgBaseSu,
    rewardPrices.v2PreBaseSu,
    rewardPrices.gasReimbursementBufferBps,
  )).wait();
  console.log("RewardManager service incentive prices set");

  await (await rewardManager.setJoinRewardWei(joinRewardWei)).wait();
  console.log("RewardManager.joinRewardWei set to:", joinRewardWei.toString(), "wei");
  if (joinRewardPoolWei > 0n) {
    await (await rewardManager.depositJoinRewardPool({ value: joinRewardPoolWei })).wait();
    console.log("RewardManager join reward pool funded:", joinRewardPoolWei.toString(), "wei");
  } else {
    console.log("RewardManager join reward pool not funded at deploy (set GUARDIAN_JOIN_REWARD_POOL_WEI to fund)");
  }

  await (await rewardManager.setProofRewardWei(proofRewardWei)).wait();
  console.log("RewardManager.proofRewardWei set to:", proofRewardWei.toString(), "wei");
  if (proofRewardPoolWei > 0n) {
    await (await rewardManager.depositProofRewardPool({ value: proofRewardPoolWei })).wait();
    console.log("RewardManager proof reward pool funded:", proofRewardPoolWei.toString(), "wei");
  } else {
    console.log("RewardManager proof reward pool not funded at deploy (set GUARDIAN_PROOF_REWARD_POOL_WEI to fund)");
  }

  await (await guardianRegistry.setStakingManager(stakingManagerAddress)).wait();
  console.log("GuardianRegistry.stakingManager set to:", stakingManagerAddress);

  await (await stakingManager.setGuardianRegistry(guardianRegistryAddress)).wait();
  console.log("StakingManager.guardianRegistry set to:", guardianRegistryAddress);

  await (await guardianRegistry.setReputationManager(reputationManagerAddress)).wait();
  console.log("GuardianRegistry.reputationManager set to:", reputationManagerAddress);

  await (await guardianRegistry.setRewardManager(rewardManagerAddress)).wait();
  console.log("GuardianRegistry.rewardManager set to:", rewardManagerAddress);
  rewarders.push(guardianRegistryAddress);

  await (await rewardManager.setGuardianRegistry(guardianRegistryAddress)).wait();
  console.log("RewardManager.guardianRegistry set to:", guardianRegistryAddress);

  await (await acl.setRewardManager(rewardManagerAddress)).wait();
  console.log("ACL.rewardManager set to:", rewardManagerAddress);

  await (await rewardManager.setDataVault(dvAddress)).wait();
  console.log("RewardManager.dataVault set to:", dvAddress);

  await (await dataVault.setRewardManager(rewardManagerAddress)).wait();
  console.log("DataVault.rewardManager set to:", rewardManagerAddress);

  if (dkgAddress) {
    await (await reputationManager.setProtocolContract(dkgAddress, true)).wait();
    console.log("ReputationManager authorized DKG contract:", dkgAddress);
  }

  let telgV2Address = null;

  if (zkDkgDisputeManagerAddress) {
    await (await reputationManager.setProtocolContract(zkDkgDisputeManagerAddress, true)).wait();
    console.log("ReputationManager authorized ZkDkgDisputeManager:", zkDkgDisputeManagerAddress);
  }

  if (zkDkgCoordinatorV2Address && zkDkgDisputeManagerAddress) {
    try {
      const telgV2 = await ethers.deployContract(
        "TElGv2",
        [aclAddress, dvAddress, zkDkgCoordinatorV2Address, zkDkgDisputeManagerAddress],
      );
      await telgV2.waitForDeployment();
      telgV2Address = await telgV2.getAddress();
      console.log("TElGv2 deployed to:", telgV2Address);
    } catch (e) {
      console.warn("TElGv2 deployment failed (skipping):", e.message || e);
    }
  }

  if (zkDkgCoordinatorV2Address) {
    await (await reputationManager.setProtocolContract(zkDkgCoordinatorV2Address, true)).wait();
    console.log("ReputationManager authorized ZkDkgCoordinatorV2:", zkDkgCoordinatorV2Address);
  }

  if (guardianShareProofAddress) {
    await (await reputationManager.setProtocolContract(guardianShareProofAddress, true)).wait();
    console.log("ReputationManager authorized GuardianShareProof:", guardianShareProofAddress);
    await (await stakingManager.setGuardianShareProof(guardianShareProofAddress)).wait();
    console.log("StakingManager.guardianShareProof set to:", guardianShareProofAddress);
    await (await guardianRegistry.setGuardianShareProof(guardianShareProofAddress)).wait();
    console.log("GuardianRegistry.guardianShareProof set to:", guardianShareProofAddress);
    const shareProof = await ethers.getContractAt("GuardianShareProof", guardianShareProofAddress);
    await (await shareProof.setReputationManager(reputationManagerAddress)).wait();
    console.log("GuardianShareProof.reputationManager set to:", reputationManagerAddress);
    await (await shareProof.setRewardManager(rewardManagerAddress)).wait();
    console.log("GuardianShareProof.rewardManager set to:", rewardManagerAddress);
    rewarders.push(guardianShareProofAddress);
    await (await shareProof.setStakingManager(stakingManagerAddress)).wait();
    console.log("GuardianShareProof.stakingManager set to:", stakingManagerAddress);
    slashers.push(guardianShareProofAddress);
    await (await shareProof.setMissedEpochPenaltyWei(missedEpochPenaltyWei)).wait();
    const setMissedEpochPenalty = await shareProof.missedEpochPenaltyWei();
    if (setMissedEpochPenalty !== missedEpochPenaltyWei)
      throw new Error(`GuardianShareProof.missedEpochPenaltyWei reads ${setMissedEpochPenalty}, not ${missedEpochPenaltyWei}`);
    console.log("GuardianShareProof.missedEpochPenaltyWei set to:", setMissedEpochPenalty.toString());
    await (await shareProof.setMaxReporterBatchSize(reporterBatchSize)).wait();
    console.log("GuardianShareProof.maxReporterBatchSize set to:", reporterBatchSize.toString());
    if (sharePossessionVerifierAddress) {
      sharePossessionRouterAddress = await deployVerifierRouter(ethers, "sharePossession", sharePossessionVerifierAddress);
      await (await shareProof.setSharePossessionVerifier(sharePossessionRouterAddress)).wait();
      await requireBoundRouter(shareProof, "sharePossessionVerifier", sharePossessionRouterAddress, "GuardianShareProof");
      console.log("GuardianShareProof.sharePossessionVerifier bound to its router:", sharePossessionRouterAddress);
    }
    await (await shareProof.setProofTiming(
      shareProofConfig.periodSeconds,
      shareProofConfig.graceSeconds,
    )).wait();
    console.log(
      "GuardianShareProof proof timing set:",
      `period=${shareProofConfig.periodSeconds}`,
      `grace=${shareProofConfig.graceSeconds}`,
    );
    await (await shareProof.setProofWindowConfig(
      shareProofConfig.slotSeconds,
      shareProofConfig.windowSeconds,
      shareProofConfig.avgBlockSeconds,
      shareProofConfig.enforceWindow,
    )).wait();
    console.log(
      "GuardianShareProof proof window set:",
      `slot=${shareProofConfig.slotSeconds}`,
      `window=${shareProofConfig.windowSeconds}`,
      `avgBlock=${shareProofConfig.avgBlockSeconds}`,
      `enforced=${shareProofConfig.enforceWindow}`,
    );
  }

  if (telgAddress) {
    await (await reputationManager.setProtocolContract(telgAddress, true)).wait();
    console.log("ReputationManager authorized TElG contract:", telgAddress);
  }

  if (telgV2Address) {
    await (await reputationManager.setProtocolContract(telgV2Address, true)).wait();
    console.log("ReputationManager authorized TElGv2 contract:", telgV2Address);
  }

  await (await reputationManager.setStakingManager(stakingManagerAddress)).wait();
  console.log("ReputationManager.stakingManager set to:", stakingManagerAddress);
  slashers.push(reputationManagerAddress);
  await (await reputationManager.setVerifiedDkgComplaintSlashWei(verifiedDkgComplaintSlashWei)).wait();
  const setComplaintFine = await reputationManager.verifiedDkgComplaintSlashWei();
  if (setComplaintFine !== verifiedDkgComplaintSlashWei)
    throw new Error(`ReputationManager.verifiedDkgComplaintSlashWei reads ${setComplaintFine}, not ${verifiedDkgComplaintSlashWei}`);
  console.log("ReputationManager.verifiedDkgComplaintSlashWei set to:", setComplaintFine.toString());

  await (await reputationManager.setInitialReputation(repConfig.initialReputation)).wait();
  console.log("ReputationManager.initialReputation set to:", repConfig.initialReputation);
  await (await reputationManager.setMaxReputation(repConfig.maxReputation)).wait();
  console.log("ReputationManager.maxReputation set to:", repConfig.maxReputation);
  await (await reputationManager.setSeriousPenaltyThreshold(repConfig.seriousPenaltyThreshold)).wait();
  console.log("ReputationManager.seriousPenaltyThreshold set to:", repConfig.seriousPenaltyThreshold);
  await (await reputationManager.setProofSuccessRepDelta(repConfig.proofSuccessDelta)).wait();
  console.log("ReputationManager.proofSuccessRepDelta set to:", repConfig.proofSuccessDelta);

  if (dkgAddress) {
    const dkg = await ethers.getContractAt("DKG", dkgAddress);
    await (await dkg.setReputationManager(reputationManagerAddress)).wait();
    console.log("DKG.reputationManager set to:", reputationManagerAddress);
  }

  if (dkgAddress && zkDkgDisputeManagerAddress) {
    const dkg = await ethers.getContractAt("DKG", dkgAddress);
    await (await dkg.setZkDkgDisputeManager(zkDkgDisputeManagerAddress)).wait();
    console.log("DKG.zkDkgDisputeManager set to:", zkDkgDisputeManagerAddress);
  }

  if (zkDkgDisputeManagerAddress) {
    const manager = await ethers.getContractAt("ZkDkgDisputeManager", zkDkgDisputeManagerAddress);
    await (await manager.setZkDkgDisputePeriod(dkgDisputePeriodSeconds)).wait();
    await (await manager.setReputationManager(reputationManagerAddress)).wait();
    console.log("ZkDkgDisputeManager.reputationManager set to:", reputationManagerAddress);
    await (await manager.setRewardManager(rewardManagerAddress)).wait();
    console.log("ZkDkgDisputeManager.rewardManager set to:", rewardManagerAddress);
  }

  let dkgRecovery;
  if (!zkDkgCoordinatorV2Address || !zkDkgDisputeManagerAddress)
    throw new Error('Recovery-v1 requires the coordinator and dispute manager; refusing incomplete publication');
  if (zkDkgCoordinatorV2Address) {
    const coordinator = await ethers.getContractAt("ZkDkgCoordinatorV2", zkDkgCoordinatorV2Address);
    await (await coordinator.setDkgKeyGenDeadline(dkgKeyGenDeadlineSeconds)).wait();
    console.log("ZkDkgCoordinatorV2.dkgKeyGenDeadline set to:", dkgKeyGenDeadlineSeconds.toString());
    await (await coordinator.setReputationManager(reputationManagerAddress)).wait();
    console.log("ZkDkgCoordinatorV2.reputationManager set to:", reputationManagerAddress);
    await (await coordinator.setRewardManager(rewardManagerAddress)).wait();
    console.log("ZkDkgCoordinatorV2.rewardManager set to:", rewardManagerAddress);
    await (await coordinator.setStakingManager(stakingManagerAddress)).wait();
    console.log("ZkDkgCoordinatorV2.stakingManager set to:", stakingManagerAddress);
    if (guardianShareProofAddress) {
      await (await coordinator.setGuardianShareProof(guardianShareProofAddress)).wait();
      console.log("ZkDkgCoordinatorV2.guardianShareProof set to:", guardianShareProofAddress);
    }
    dkgRecovery=await deployDkgRecovery({ethers,acl,coordinator,staking:stakingManager,reputation:reputationManager});
    console.log('DKG recovery-v1 contracts:',JSON.stringify(dkgRecovery.addresses));
    // No slashing or reward rights: the coordinator never calls StakingManager or
    // RewardManager (DKG work and collateral go through DkgAttemptEscrow).
    await (await acl.setDkgV2(zkDkgCoordinatorV2Address)).wait();
    console.log("ACL.dkgV2 set to:", zkDkgCoordinatorV2Address);
  }

  if (telgAddress) {
    const telg = await ethers.getContractAt("TElG", telgAddress);
    await (await telg.setReputationManager(reputationManagerAddress)).wait();
    console.log("TElG.reputationManager set to:", reputationManagerAddress);
  }

  if (telgV2Address) {
    const telgV2 = await ethers.getContractAt("TElGv2", telgV2Address);
    await (await telgV2.setReputationManager(reputationManagerAddress)).wait();
    console.log("TElGv2.reputationManager set to:", reputationManagerAddress);
    await (await telgV2.setRewardManager(rewardManagerAddress)).wait();
    console.log("TElGv2.rewardManager set to:", rewardManagerAddress);
    await (await telgV2.setStakingManager(stakingManagerAddress)).wait();
    console.log("TElGv2.stakingManager set to:", stakingManagerAddress);
    if (v2PrePartialVerifierAddress) {
      prePartialRouterAddress = await deployVerifierRouter(ethers, "prePartial", v2PrePartialVerifierAddress);
      await (await telgV2.setV2PrePartialVerifier(prePartialRouterAddress)).wait();
      await requireBoundRouter(telgV2, "v2PrePartialVerifier", prePartialRouterAddress, "TElGv2");
      console.log("TElGv2.v2PrePartialVerifier bound to its router:", prePartialRouterAddress);
    }
    slashers.push(telgV2Address);
    if (guardianShareProofAddress) {
      await (await telgV2.setGuardianShareProof(guardianShareProofAddress)).wait();
      console.log("TElGv2.guardianShareProof set to:", guardianShareProofAddress);
    }
  }

  // ZkDkgDisputeManager and ZkDkgCoordinatorV2 get no reward rights: neither calls
  // RewardManager. TElGv2 does (PRE credits, expiry refunds).
  if (telgV2Address) rewarders.push(telgV2Address);

  // Guardian work reward: its own contract, because RewardManager is close to the EIP-170
  // size limit. The DKG coordinator and TElGv2 call it; governance owns it after deploy.
  let guardianWorkReward = null;
  let guardianWorkRewardAddress = null;
  if (zkDkgCoordinatorV2Address && telgV2Address) {
    guardianWorkReward = await ethers.deployContract("GuardianWorkReward", [guardianRegistryAddress]);
    await guardianWorkReward.waitForDeployment();
    guardianWorkRewardAddress = await guardianWorkReward.getAddress();
    await (await guardianWorkReward.setRewards(
      guardianDkgRewardWei, guardianPreRewardWei, guardianPreReadyRewardWei, guardianWorkRewardCapWei,
    )).wait();
    if (guardianWorkRewardPoolWei > 0n) {
      await (await guardianWorkReward.deposit({ value: guardianWorkRewardPoolWei })).wait();
    }
    await (await guardianWorkReward.bindCallers([zkDkgCoordinatorV2Address, telgV2Address])).wait();
    const coordinatorForReward = await ethers.getContractAt("ZkDkgCoordinatorV2", zkDkgCoordinatorV2Address);
    await (await coordinatorForReward.setGuardianWorkReward(guardianWorkRewardAddress)).wait();
    const telgV2ForReward = await ethers.getContractAt("TElGv2", telgV2Address);
    await (await telgV2ForReward.setGuardianWorkReward(guardianWorkRewardAddress)).wait();
    console.log(
      "GuardianWorkReward deployed to:", guardianWorkRewardAddress,
      "DKG", guardianDkgRewardWei.toString(), "PRE", guardianPreRewardWei.toString(),
      "PRE ready", guardianPreReadyRewardWei.toString(), "wei, limit", guardianWorkRewardCapWei.toString(),
      "wei, pool", guardianWorkRewardPoolWei.toString(), "wei",
    );
  }

  await (await acl.setGuardianRegistry(guardianRegistryAddress)).wait();
  console.log("ACL.guardianRegistry set to:", guardianRegistryAddress);
  if (dkgAddress) {
    await (await acl.setDkg(dkgAddress)).wait();
    console.log("ACL.dkg set to:", dkgAddress);
  }

  if (telgAddress) {
    await (await acl.setTelg(telgAddress)).wait();
    console.log("ACL.telg set to:", telgAddress);
  }

  if (telgV2Address) {
    await (await acl.setTelgV2(telgV2Address)).wait();
    console.log("ACL.telgV2 set to:", telgV2Address);
  }

  if (telgAddress) {
    await (await dataVault.setTelg(telgAddress)).wait();
    console.log("DataVault.telg set to:", telgAddress);
  }

  if (dkgAddress) {
    await (await dataVault.setDkg(dkgAddress)).wait();
    console.log("DataVault.dkg set to:", dkgAddress);
  }

  if (zkDkgCoordinatorV2Address) {
    await (await dataVault.setDkgV2(zkDkgCoordinatorV2Address)).wait();
    console.log("DataVault.dkgV2 set to:", zkDkgCoordinatorV2Address);
  }

  let storageProofVerifierAddress = storageProofConfig.existingVerifierAdapter || null;
  let storageProofGeneratedVerifierAddress = storageProofConfig.generatedVerifier || null;
  let storageProofGeneratedVerifierContract = "";

  if (storageProofVerifierAddress) {
    console.log("Using existing StorageProof verifier adapter:", storageProofVerifierAddress);
  }

  if (!storageProofGeneratedVerifierAddress && !storageProofVerifierAddress) {
    const generated = await tryDeployFirstAvailable(
      ethers,
      candidateStorageProofVerifierNames(),
                                                    "StorageProof generated gnark verifier",
    );
    storageProofGeneratedVerifierAddress = generated.address;
    storageProofGeneratedVerifierContract = generated.contractName;

    if (!storageProofGeneratedVerifierAddress) {
      console.warn(
        "No compiled generated StorageProof verifier was deployed. " +
        "Generate keys/StorageProofGnarkVerifier.sol, copy it into filetrust/evm/contracts, " +
        "then run hardhat compile/deploy again, or set STORAGE_PROOF_GENERATED_VERIFIER_ADDRESS."
      );
    }
  } else if (storageProofGeneratedVerifierAddress) {
    storageProofGeneratedVerifierContract = process.env.STORAGE_PROOF_GENERATED_VERIFIER_CONTRACT || "external";
    console.log("Using existing StorageProof generated verifier:", storageProofGeneratedVerifierAddress);
  }

  if (!storageProofVerifierAddress && storageProofGeneratedVerifierAddress) {
    try {
      const storageProofVerifierAdapter = await ethers.deployContract(
        "GnarkStorageProofVerifierAdapter",
        [storageProofGeneratedVerifierAddress],
      );
      await storageProofVerifierAdapter.waitForDeployment();
      storageProofVerifierAddress = await storageProofVerifierAdapter.getAddress();
      console.log("GnarkStorageProofVerifierAdapter deployed to:", storageProofVerifierAddress);
    } catch (e) {
      console.warn("GnarkStorageProofVerifierAdapter deployment failed (skipping):", e.message || e);
    }
  }

  if (!storageProofVerifierAddress) {
    console.warn("StorageProofSC will be deployed with zero verifier. On-chain proof verification will not be active until a verifier adapter is set.");
  }

  // ── Partition proof verifier (new) ─────────────────────────────────────────
  // Partition proof verification is mandatory for a production deployment.
  // The generated verifier may be deployed here or supplied by address, but
  // both it and its adapter must exist before StorageProofSC is deployed.
  //
  // PartitionStorageProofGnarkVerifier uses two external Solidity libraries
  // (BN254MathLib and PublicInputMSMLib) to stay within the EIP-170 24 576-byte
  // deployed-bytecode limit.  Both libraries must be deployed first, then their
  // addresses passed as library links when deploying the verifier.
  const partitionCircuitSectors    = parseInt(process.env.PARTITION_CIRCUIT_SECTORS    || "16");
  const partitionCircuitChallenges = parseInt(process.env.PARTITION_CIRCUIT_CHALLENGES || "4");

  // Deploy (or reuse) the two support libraries.
  let bn254MathLibAddress = process.env.BN254_MATH_LIB_ADDRESS || null;
  let publicInputMSMLibAddress = process.env.PUBLIC_INPUT_MSM_LIB_ADDRESS || null;
  const publicInputMSMLibContract = process.env.PUBLIC_INPUT_MSM_LIB_CONTRACT
    || partitionMsmLibraryForBlockSize(storageProofZkBlockSize);

  if (!bn254MathLibAddress) {
    try {
      const lib = await ethers.deployContract("BN254MathLib");
      await lib.waitForDeployment();
      bn254MathLibAddress = await lib.getAddress();
      console.log("BN254MathLib deployed to:", bn254MathLibAddress);
    } catch (e) {
      console.warn("BN254MathLib deployment failed (skipping):", e.message || e);
    }
  } else {
    console.log("Using existing BN254MathLib:", bn254MathLibAddress);
  }

  if (!publicInputMSMLibAddress) {
    try {
      const lib = await ethers.deployContract(publicInputMSMLibContract);
      await lib.waitForDeployment();
      publicInputMSMLibAddress = await lib.getAddress();
      console.log(`${publicInputMSMLibContract} deployed to:`, publicInputMSMLibAddress);
    } catch (e) {
      console.warn(`${publicInputMSMLibContract} deployment failed (skipping):`, e.message || e);
    }
  } else {
    console.log(`Using existing ${publicInputMSMLibContract}:`, publicInputMSMLibAddress);
  }

  let storageProofPartitionGeneratedVerifierAddress = process.env.STORAGE_PROOF_PARTITION_GENERATED_VERIFIER_ADDRESS || null;
  let storageProofPartitionVerifierAddress = process.env.STORAGE_PROOF_PARTITION_VERIFIER_ADDRESS || null;
  let storageProofPartitionGeneratedVerifierContract = "";

  if (!storageProofPartitionGeneratedVerifierAddress && !storageProofPartitionVerifierAddress) {
    // Try to deploy a PartitionVerifier contract (generated by gnark partition-setup).
    // The gnark-generated file exports a contract named "Verifier"; use the fully-qualified
    // name so Hardhat resolves the right artifact when multiple Verifier contracts exist.
    const configuredPartitionVerifierContract =
      process.env.STORAGE_PROOF_PARTITION_GENERATED_VERIFIER_CONTRACT
      || partitionVerifierContractForBlockSize(storageProofZkBlockSize);
    const partitionVerifierNames = [
      configuredPartitionVerifierContract,
      ...(storageProofZkBlockSize === 128
        ? ["PartitionVerifier", "PartitionStorageProofGnarkVerifier"]
        : []),
    ];
    // Pass library addresses so the linker can resolve the two external libraries.
    const libraryLinks = (bn254MathLibAddress && publicInputMSMLibAddress)
      ? { libraries: { BN254MathLib: bn254MathLibAddress, [publicInputMSMLibContract]: publicInputMSMLibAddress } }
      : {};
    for (const name of partitionVerifierNames) {
      try {
        const pv = await ethers.deployContract(name, [], libraryLinks);
        await pv.waitForDeployment();
        storageProofPartitionGeneratedVerifierAddress = await pv.getAddress();
        storageProofPartitionGeneratedVerifierContract = name;
        console.log(`Partition generated verifier deployed as ${name} to:`, storageProofPartitionGeneratedVerifierAddress);
        break;
      } catch (_) {
        // not yet compiled or library linking failed; try next candidate
      }
    }
    if (!storageProofPartitionGeneratedVerifierAddress) {
      console.log("PartitionStorageProofGnarkVerifier not found — skipping partition verifier deployment.");
      console.log("Run: storageproof-prover --mode partition-setup --keys zk/gnark-storage-proof/keys");
      console.log("Then copy keys/partition/PartitionStorageProofGnarkVerifier.sol into filetrust/evm/contracts/ and recompile.");
    }
  } else if (storageProofPartitionGeneratedVerifierAddress) {
    storageProofPartitionGeneratedVerifierContract = process.env.STORAGE_PROOF_PARTITION_GENERATED_VERIFIER_CONTRACT || "external";
    console.log("Using existing partition generated verifier:", storageProofPartitionGeneratedVerifierAddress);
  }

  if (!storageProofPartitionVerifierAddress && storageProofPartitionGeneratedVerifierAddress) {
    const partitionAdapterName =
      (partitionCircuitSectors === 16 && partitionCircuitChallenges === 4)
        ? "GnarkPartitionProofVerifierAdapter132"
        : "";
    if (!partitionAdapterName) {
      console.warn(
        "No compiled partition verifier adapter for",
        `N=${partitionCircuitSectors}`,
        `M=${partitionCircuitChallenges}`,
        "— skipping partition verifier adapter deployment.",
      );
    } else {
      try {
        const adapter = await ethers.deployContract(
          partitionAdapterName,
          [storageProofPartitionGeneratedVerifierAddress],
        );
        await adapter.waitForDeployment();
        storageProofPartitionVerifierAddress = await adapter.getAddress();
        console.log(`${partitionAdapterName} deployed to:`, storageProofPartitionVerifierAddress);
      } catch (e) {
        console.warn(`${partitionAdapterName} deployment failed (skipping):`, e.message || e);
      }
    }
  }
  if (!storageProofPartitionGeneratedVerifierAddress || !storageProofPartitionVerifierAddress) {
    throw new Error(
      "Production storage proofs require both a generated partition verifier and " +
      "its adapter. Build the configured partition verifier profile or provide " +
      "STORAGE_PROOF_PARTITION_GENERATED_VERIFIER_ADDRESS and " +
      "STORAGE_PROOF_PARTITION_VERIFIER_ADDRESS.",
    );
  }
  // ───────────────────────────────────────────────────────────────────────────

  let storageProofAddress = null;
  try {
    const storageProof = await ethers.deployContract(
      "StorageProofSC",
      [storageProofVerifierAddress || ethers.ZeroAddress],
    );
    await storageProof.waitForDeployment();
    storageProofAddress = await storageProof.getAddress();
    console.log("StorageProofSC deployed to:", storageProofAddress);
    await (await storageProof.setProofPeriod(
      storageProofConfig.periodSeconds,
      storageProofConfig.deadlineSeconds,
      storageProofConfig.maxChallenges,
    )).wait();
    console.log(
      "StorageProofSC proof config set:",
      `period=${storageProofConfig.periodSeconds}`,
      `deadline=${storageProofConfig.deadlineSeconds}`,
      `maxChallenges=${storageProofConfig.maxChallenges}`,
    );
    // Wire partition verifier if available.
    if (storageProofPartitionVerifierAddress) {
      partitionRouterAddress = await deployVerifierRouter(ethers, "partition", storageProofPartitionVerifierAddress);
      await (await storageProof.setPartitionVerifier(partitionRouterAddress)).wait();
      await requireBoundRouter(storageProof, "partitionVerifier", partitionRouterAddress, "StorageProofSC");
      console.log("StorageProofSC.partitionVerifier bound to its router:", partitionRouterAddress);
    }
    // Set partition circuit params so the contract knows N and M.
    await (await storageProof.setPartitionCircuitParams(
      partitionCircuitSectors, partitionCircuitChallenges)).wait();
    console.log(
      "StorageProofSC partition circuit params set:",
      `sectors=${partitionCircuitSectors}`,
      `challenges=${partitionCircuitChallenges}`,
    );
    await (await storageProof.setZkBlockSizeBytes(storageProofZkBlockSize)).wait();
    console.log("StorageProofSC zk block size set to:", storageProofZkBlockSize);

    await (await storageProof.setReputationManager(reputationManagerAddress)).wait();
    console.log("StorageProofSC.reputationManager set to:", reputationManagerAddress);
    await (await reputationManager.setProtocolContract(storageProofAddress, true)).wait();
    console.log("ReputationManager authorized StorageProofSC:", storageProofAddress);

    await (await storageProof.setRewardManager(rewardManagerAddress)).wait();
    console.log("StorageProofSC.rewardManager set to:", rewardManagerAddress);
    rewarders.push(storageProofAddress);

    if (vkProofRewardWei > 0n) {
      await (await rewardManager.setVKProofRewardWei(vkProofRewardWei)).wait();
      console.log("RewardManager.vkProofRewardWei set to:", vkProofRewardWei.toString(), "wei");
    } else {
      console.log("VK proof reward not set (VK_PROOF_REWARD_WEI=0 — set env var to activate)");
    }
    if (vkProofRewardPoolWei > 0n) {
      await (await rewardManager.depositVKProofRewardPool({ value: vkProofRewardPoolWei })).wait();
      console.log("RewardManager VK proof reward pool funded:", vkProofRewardPoolWei.toString(), "wei");
    }

    // Wrong-proof punishment wiring: authorize StorageProofSC to slash stakes.
    await (await storageProof.setStakingManager(stakingManagerAddress)).wait();
    console.log("StorageProofSC.stakingManager set to:", stakingManagerAddress);
    slashers.push(storageProofAddress);

    // Escalation thresholds (attempts before each penalty level kicks in).
    await (await storageProof.setWrongProofThresholds(
      wrongProofRepThreshold, wrongProofSlashThreshold, wrongProofSuspendThreshold
    )).wait();
    console.log(
      "StorageProofSC wrong-proof thresholds set: rep=", wrongProofRepThreshold,
      "slash=", wrongProofSlashThreshold, "suspend=", wrongProofSuspendThreshold
    );

    // Slash sizes and suspension duration.
    await (await storageProof.setWrongProofSlashParams(
      wrongProofSlashBps, wrongProofSuspendSlashBps, wrongProofSuspendSeconds
    )).wait();
    console.log(
      "StorageProofSC wrong-proof slash params set: slashBps=", wrongProofSlashBps,
      "suspendSlashBps=", wrongProofSuspendSlashBps, "suspendSeconds=", wrongProofSuspendSeconds
    );
    // VaultKeeperRegistry link is set below after VaultKeeperRegistry is deployed.
  } catch (e) {
    throw new Error(`Required StorageProofSC deployment/wiring failed: ${e.message || e}`);
  }

  const vaultKeeperRegistry = await ethers.deployContract("VaultKeeperRegistry");
  await vaultKeeperRegistry.waitForDeployment();
  const vaultKeeperRegistryAddress = await vaultKeeperRegistry.getAddress();
  console.log("VaultKeeperRegistry deployed to:", vaultKeeperRegistryAddress);
  const admissionMarginBytes = BigInt(process.env.ADMISSION_MARGIN_BYTES || 100 * 1024 * 1024);
  await (await vaultKeeperRegistry.setDefaultAdmissionMarginBytes(admissionMarginBytes)).wait();
  console.log("VaultKeeperRegistry default admission margin set to:", admissionMarginBytes.toString());

  await (await vaultKeeperRegistry.setReputationManager(reputationManagerAddress)).wait();
  console.log("VaultKeeperRegistry.reputationManager set to:", reputationManagerAddress);

  await (await vaultKeeperRegistry.setStakingManager(stakingManagerAddress)).wait();
  console.log("VaultKeeperRegistry.stakingManager set to:", stakingManagerAddress);

  await (await stakingManager.setVaultKeeperRegistry(vaultKeeperRegistryAddress)).wait();
  console.log("StakingManager.vaultKeeperRegistry set to:", vaultKeeperRegistryAddress);

  await (await vaultKeeperRegistry.setRewardManager(rewardManagerAddress)).wait();
  console.log("VaultKeeperRegistry.rewardManager set to:", rewardManagerAddress);

  rewarders.push(vaultKeeperRegistryAddress);

  if (vkJoinRewardWei > 0n) {
    await (await rewardManager.setVKJoinRewardWei(vkJoinRewardWei)).wait();
    console.log("RewardManager.vkJoinRewardWei set to:", vkJoinRewardWei.toString(), "wei");
  } else {
    console.log("VK join reward not set (VK_JOIN_REWARD_WEI=0 — set env var to activate)");
  }
  if (vkJoinRewardPoolWei > 0n) {
    await (await rewardManager.depositVKJoinRewardPool({ value: vkJoinRewardPoolWei })).wait();
    console.log("RewardManager VK join reward pool funded:", vkJoinRewardPoolWei.toString(), "wei");
  }

  // Wire StorageProofSC → VaultKeeperRegistry for wrong-proof suspension (deferred from StorageProofSC block).
  if (storageProofAddress) {
    const storageProofForSuspend = await ethers.getContractAt("StorageProofSC", storageProofAddress);
    await (await storageProofForSuspend.setVaultKeeperRegistry(vaultKeeperRegistryAddress)).wait();
    console.log("StorageProofSC.vaultKeeperRegistry set to:", vaultKeeperRegistryAddress);
    await (await vaultKeeperRegistry.setAuthorizedEnforcer(storageProofAddress, true)).wait();
    console.log("VaultKeeperRegistry authorized StorageProofSC as enforcer:", storageProofAddress);
  }

  // Capacity accounting is a separate authority. StorageProofSC owns mutable
  // partition manifests; PartitionSnapshotProofSC owns post-freeze verification;
  // CapacityProofSC counts only exact epoch-bound receipts from that verifier.
  let capacityProofAddress = null;
  let partitionSnapshotProofAddress = null;
  let capacityProofContract = null;
  let capacityCertificationAddress = null;
  let capacityCertificationContract = null;
  let capacityIncrementalBatchAddress = null;
  // G.1A certification ring, owned by CapacityCertificationSC. Derived from the same timing
  // parameters the prover uses, so a reconfigured proof period or deadline count cannot
  // silently desynchronise the ring:
  //   slotSeconds = proofPeriodSeconds / deadlineCount
  //   ringSize    = ceil(certificationAgeSeconds / slotSeconds) + 2
  // The ring is immutable after deployment and is built against its OWN age parameter, not
  // the mutable admission gate `maxProofAgeSeconds`.
  const certificationDeadlineCount = BigInt(
    process.env.STORAGEPROOF_DEADLINE_COUNT || "48",
  );
  if (certificationDeadlineCount <= 0n) {
    throw new Error("STORAGEPROOF_DEADLINE_COUNT must be positive");
  }
  const certificationSlotSeconds =
    storageProofConfig.periodSeconds / certificationDeadlineCount;
  if (certificationSlotSeconds <= 0n) {
    throw new Error(
      "STORAGE_PROOF_PERIOD_SECONDS / STORAGEPROOF_DEADLINE_COUNT must be at least 1 second",
    );
  }
  const certificationRingSize =
    (capacityMaxProofAgeSeconds + certificationSlotSeconds - 1n) / certificationSlotSeconds + 2n;
  if (certificationRingSize > 256n) {
    throw new Error(
      `certification ring size ${certificationRingSize} exceeds the contract maximum of 256; ` +
      "increase STORAGE_PROOF_PERIOD_SECONDS/STORAGEPROOF_DEADLINE_COUNT or lower " +
      "CAPACITY_MAX_PROOF_AGE_SECONDS",
    );
  }
  try {
    // Required order: certification contract first (it needs no peer at construction),
    // then CapacityProofSC pinned to it, then the one-time reciprocal binding.
    capacityCertificationContract = await ethers.deployContract("CapacityCertificationSC", [
      certificationSlotSeconds,
      certificationRingSize,
      capacityMaxProofAgeSeconds,
    ]);
    await capacityCertificationContract.waitForDeployment();
    capacityCertificationAddress = await capacityCertificationContract.getAddress();

    capacityProofContract = await ethers.deployContract("CapacityProofSC", [
      capacityCertificationAddress,
    ]);
    await capacityProofContract.waitForDeployment();
    capacityProofAddress = await capacityProofContract.getAddress();

    // One-time, irreversible authority binding. The call itself verifies that
    // CapacityProofSC already points back at this certification contract.
    await (await capacityCertificationContract.bindCapacityProof(capacityProofAddress)).wait();

    // Fail closed on reciprocal wiring before any further configuration is applied.
    const boundAuthority = await capacityCertificationContract.capacityProofSC();
    const boundCertification = await capacityProofContract.certificationContract();
    if (boundAuthority.toLowerCase() !== capacityProofAddress.toLowerCase()) {
      throw new Error(
        `CapacityCertificationSC.capacityProofSC ${boundAuthority} != ${capacityProofAddress}`,
      );
    }
    if (boundCertification.toLowerCase() !== capacityCertificationAddress.toLowerCase()) {
      throw new Error(
        `CapacityProofSC.certificationContract ${boundCertification} != ${capacityCertificationAddress}`,
      );
    }
    console.log(
      "CapacityCertificationSC deployed/bound:", capacityCertificationAddress,
      `(slot=${certificationSlotSeconds} ring=${certificationRingSize} age=${capacityMaxProofAgeSeconds})`,
    );

    // VK capacity reward: the certification contract pays keepers for proven space
    // through RewardManager. The binding is one-time; the rate and limit stay on
    // RewardManager, which governance owns after deploy.
    rewarders.push(capacityCertificationAddress);
    await (await capacityCertificationContract.bindRewardManager(rewardManagerAddress)).wait();
    await (await rewardManager.setVKCapacityReward(vkCapacityRewardPerGbWei, vkCapacityRewardCapWei)).wait();
    if (vkCapacityRewardPoolWei > 0n) {
      await (await rewardManager.depositVKCapacityRewardPool({ value: vkCapacityRewardPoolWei })).wait();
    }
    console.log(
      "RewardManager VK capacity reward:", vkCapacityRewardPerGbWei.toString(), "wei/GB, limit",
      vkCapacityRewardCapWei.toString(), "wei, pool", vkCapacityRewardPoolWei.toString(), "wei",
    );

    await (await capacityProofContract.setVaultKeeperRegistry(
      vaultKeeperRegistryAddress,
    )).wait();
    await (await capacityProofContract.setStorageProof(storageProofAddress)).wait();
    await (await capacityProofContract.setMaxProofAgeSeconds(
      capacityMaxProofAgeSeconds,
    )).wait();
    await (await capacityProofContract.setMaxActiveTransferSeconds(
      maxStorageRegistrationTimeoutSeconds,
    )).wait();
    await (await capacityProofContract.setMaxManifestOverheadBytes(
      capacityMaxManifestOverheadBytes,
    )).wait();
    console.log("CapacityProofSC deployed/wired:", capacityProofAddress);

    const snapshotProof = await ethers.deployContract(
      "PartitionSnapshotProofSC",
      [storageProofAddress, partitionRouterAddress || storageProofPartitionVerifierAddress],
    );
    await snapshotProof.waitForDeployment();
    partitionSnapshotProofAddress = await snapshotProof.getAddress();
    if (partitionRouterAddress) {
      await requireBoundRouter(snapshotProof, "partitionVerifier", partitionRouterAddress, "PartitionSnapshotProofSC");
    }
    await (await snapshotProof.setVaultKeeperRegistry(
      vaultKeeperRegistryAddress,
    )).wait();
    await (await snapshotProof.setCapacityProof(capacityProofAddress)).wait();
    await (await capacityProofContract.setPartitionSnapshotProof(
      partitionSnapshotProofAddress,
    )).wait();

    // G.2A exact incremental membership. Required order: the batch contract is constructed
    // against CapacityProofSC (it reads the certification contract from there and verifies
    // that pair is reciprocal), the snapshot contract is pointed at it, and only then does the
    // batch contract accept the snapshot contract as its one-time acceptance authority.
    const incrementalBatch = await ethers.deployContract(
      "CapacityIncrementalBatchSC", [capacityProofAddress],
    );
    await incrementalBatch.waitForDeployment();
    capacityIncrementalBatchAddress = await incrementalBatch.getAddress();
    await (await incrementalBatch.setVaultKeeperRegistry(vaultKeeperRegistryAddress)).wait();
    await (await snapshotProof.setIncrementalBatch(
      capacityIncrementalBatchAddress, capacityCertificationAddress,
    )).wait();
    await (await incrementalBatch.bindSnapshotProof(partitionSnapshotProofAddress)).wait();
    // G.2B: the batch contract is also the per-VK capacity-campaign lock. One-time,
    // reciprocity-checked, and never replaceable.
    await (await capacityProofContract.setCampaignCoordinator(
      capacityIncrementalBatchAddress,
    )).wait();
    const boundCoordinator = await capacityProofContract.campaignCoordinator();
    if (boundCoordinator.toLowerCase() !== capacityIncrementalBatchAddress.toLowerCase()) {
      throw new Error(
        `CapacityProofSC.campaignCoordinator ${boundCoordinator} != ${capacityIncrementalBatchAddress}`,
      );
    }

    const boundSnapshot = await incrementalBatch.snapshotProof();
    const boundBatch = await snapshotProof.incrementalBatch();
    if (boundSnapshot.toLowerCase() !== partitionSnapshotProofAddress.toLowerCase()) {
      throw new Error(
        `CapacityIncrementalBatchSC.snapshotProof ${boundSnapshot} != ${partitionSnapshotProofAddress}`,
      );
    }
    if (boundBatch.toLowerCase() !== capacityIncrementalBatchAddress.toLowerCase()) {
      throw new Error(
        `PartitionSnapshotProofSC.incrementalBatch ${boundBatch} != ${capacityIncrementalBatchAddress}`,
      );
    }
    console.log("CapacityIncrementalBatchSC deployed/bound:", capacityIncrementalBatchAddress);

    const storageProof = await ethers.getContractAt("StorageProofSC", storageProofAddress);
    await (await storageProof.setCapacityProof(capacityProofAddress)).wait();
    await (await storageProof.setPartitionSnapshotProof(
      partitionSnapshotProofAddress,
    )).wait();
    console.log(
      "PartitionSnapshotProofSC deployed and StorageProofSC wired:",
      partitionSnapshotProofAddress,
    );
  } catch (e) {
    throw new Error(`Required capacity proof deployment/wiring failed: ${e.message || e}`);
  }

  // ── VKEscrow (privacy-preserving VK storage payment escrow) ────────────────
  // Constructor takes no arguments — owner = deployer, reclaimGraceSeconds = 30 days.
  // FileRegistration and DisputeContract are wired below via admin setters after those
  // contracts are deployed.
  let vkEscrowAddress = null;
  let vkEscrowContract = null;
  try {
    vkEscrowContract = await ethers.deployContract("VKEscrow");
    await vkEscrowContract.waitForDeployment();
    vkEscrowAddress = await vkEscrowContract.getAddress();
    console.log("VKEscrow deployed to:", vkEscrowAddress);

    await (await vkEscrowContract.setRewardManager(rewardManagerAddress)).wait();
    console.log("VKEscrow.rewardManager set to:", rewardManagerAddress);
    const deletionTxCostWei = vkPieceTxCostGas * fixedGasPriceWei;
    await (await vkEscrowContract.setDeletionTxCostEstimate(deletionTxCostWei)).wait();
    console.log(
      "VKEscrow.deletionTxCostEstimate set to:", deletionTxCostWei.toString(),
      `wei (${vkPieceTxCostGas} gas x ${fixedGasPriceWei} wei)`,
    );
    rewarders.push(vkEscrowAddress);

    if (vkFileRewardWei > 0n) {
      await (await rewardManager.setVKFileRewardWei(vkFileRewardWei)).wait();
      console.log("RewardManager.vkFileRewardWei set to:", vkFileRewardWei.toString(), "wei");
    } else {
      console.log("VK file reward not set (VK_FILE_REWARD_WEI=0 — set env var to activate)");
    }
    if (vkFileRewardPoolWei > 0n) {
      await (await rewardManager.depositVKFileRewardPool({ value: vkFileRewardPoolWei })).wait();
      console.log("RewardManager VK file reward pool funded:", vkFileRewardPoolWei.toString(), "wei");
    }
  } catch (e) {
    console.warn("VKEscrow deployment failed (skipping):", e.message || e);
  }
  // ───────────────────────────────────────────────────────────────────────────

  // ── StorageReceiptDispute (private DO-VK receipt dispute path) ─────────────
  let storageReceiptDisputeAddress = null;
  if (storageProofAddress) {
    try {
      const receiptDispute = await ethers.deployContract(
        "StorageReceiptDispute",
        [storageProofAddress],
      );
      await receiptDispute.waitForDeployment();
      storageReceiptDisputeAddress = await receiptDispute.getAddress();
      console.log("StorageReceiptDispute deployed to:", storageReceiptDisputeAddress);

      await (await receiptDispute.setStakingManager(stakingManagerAddress)).wait();
      console.log("StorageReceiptDispute.stakingManager set to:", stakingManagerAddress);

      await (await receiptDispute.setReputationManager(reputationManagerAddress)).wait();
      console.log("StorageReceiptDispute.reputationManager set to:", reputationManagerAddress);

      await (await receiptDispute.setVKRegistry(vaultKeeperRegistryAddress)).wait();
      console.log("StorageReceiptDispute.vkRegistry set to:", vaultKeeperRegistryAddress);

      await (await reputationManager.setProtocolContract(storageReceiptDisputeAddress, true)).wait();
      console.log("ReputationManager authorized StorageReceiptDispute:", storageReceiptDisputeAddress);

      slashers.push(storageReceiptDisputeAddress);

      await (await vaultKeeperRegistry.setAuthorizedEnforcer(storageReceiptDisputeAddress, true)).wait();
      console.log("VaultKeeperRegistry authorized StorageReceiptDispute as enforcer:", storageReceiptDisputeAddress);

      if (!ethers.isAddress(admissionReporterAddress) || admissionReporterAddress === ethers.ZeroAddress) {
        throw new Error(`invalid ADMISSION_REPORTER_ADDRESS: ${admissionReporterAddress}`);
      }
      await (await receiptDispute.setAuthorizedDisputeReporter(admissionReporterAddress, true)).wait();
      console.log("StorageReceiptDispute authorized admission Reporter:", admissionReporterAddress);

      await (await receiptDispute.setRepPenalties(
        repConfig.penaltyWarning,
        repConfig.penaltyMinor,
        repConfig.penaltyMajor,
        repConfig.penaltyMalicious,
      )).wait();
      console.log("StorageReceiptDispute rep penalties set:",
        `warning=${repConfig.penaltyWarning}`,
        `minor=${repConfig.penaltyMinor}`,
        `major=${repConfig.penaltyMajor}`,
        `malicious=${repConfig.penaltyMalicious}`,
      );

      // Wire VKEscrow ↔ StorageReceiptDispute (escrow refund on successful dispute). The
      // dispute contract names the escrow first: VKEscrow binds it once, and only if it
      // points back.
      if (vkEscrowAddress && vkEscrowContract) {
        await (await receiptDispute.setVKEscrow(vkEscrowAddress)).wait();
        console.log("StorageReceiptDispute.vkEscrow set to:", vkEscrowAddress);

        await (await vkEscrowContract.setDisputeContract(storageReceiptDisputeAddress)).wait();
        console.log("VKEscrow.disputeContract set to:", storageReceiptDisputeAddress);
      }
    } catch (e) {
      throw new Error(`required StorageReceiptDispute deployment/wiring failed: ${e.message || e}`);
    }
  } else {
    throw new Error("StorageReceiptDispute requires StorageProofSC, but StorageProofSC was not deployed");
  }
  // ───────────────────────────────────────────────────────────────────────────

  // ── FileRegistrationSC (privacy-preserving VK piece commitment anchor) ─────
  let fileRegistrationAddress = null;
  let fileRegistrationContract = null;
  let deletionReleaseAddress = null;
  let storageRegistrationTimeoutAddress = null;
  try {
    const fileRegistration = await ethers.deployContract("FileRegistrationSC", [storageProofAddress || ethers.ZeroAddress]);
    fileRegistrationContract = fileRegistration;
    await fileRegistration.waitForDeployment();
    fileRegistrationAddress = await fileRegistration.getAddress();
    console.log("FileRegistrationSC deployed to:", fileRegistrationAddress);

    if (storageReceiptDisputeAddress && fileRegistrationAddress) {
      const receiptDispute = await ethers.getContractAt("StorageReceiptDispute", storageReceiptDisputeAddress);
      await (await receiptDispute.setFileRegistration(fileRegistrationAddress)).wait();
      console.log("StorageReceiptDispute.fileRegistration set to:", fileRegistrationAddress);
    }

    if (storageProofAddress && fileRegistrationAddress) {
      const storageProof = await ethers.getContractAt("StorageProofSC", storageProofAddress);
      await (await storageProof.setFileRegistrationGuard(fileRegistrationAddress, true)).wait();
      console.log("StorageProofSC.fileRegistrationGuard set to:", fileRegistrationAddress, "(required)");
    }

    // Wire VKEscrow → FileRegistrationSC so normal and deletion claims can verify file registration.
    if (vkEscrowAddress && vkEscrowContract) {
      await (await vkEscrowContract.setFinalizeRegistrationTimeoutSeconds(storageRegistrationTimeoutSeconds)).wait();
      console.log("VKEscrow registration timeout set to:", storageRegistrationTimeoutSeconds, "seconds");
      await (await vkEscrowContract.setMaxRegistrationTimeoutSeconds(
        maxStorageRegistrationTimeoutSeconds,
      )).wait();
      console.log(
        "VKEscrow maximum size-aware registration timeout set to:",
        maxStorageRegistrationTimeoutSeconds,
        "seconds",
      );
      await (await vkEscrowContract.setFileRegistration(fileRegistrationAddress)).wait();
      console.log("VKEscrow.fileRegistration set to:", fileRegistrationAddress);
      await (await vkEscrowContract.setFileRegistrationForDeletion(fileRegistrationAddress)).wait();
      console.log("VKEscrow.fileRegistrationForDeletion set to:", fileRegistrationAddress);
    }

    // Wire FileRegistrationSC → VaultKeeperRegistry so each registerFileStorage
    // extends the VK's tracked latestServiceEnd, enabling stake withdrawal enforcement.
    await (await fileRegistration.setVaultKeeperRegistry(vaultKeeperRegistryAddress)).wait();
    console.log("FileRegistrationSC.vaultKeeperRegistry set to:", vaultKeeperRegistryAddress);
    await (await fileRegistration.setCapacityProof(capacityProofAddress)).wait();
    await (await fileRegistration.setPartitionSnapshotProof(
      partitionSnapshotProofAddress,
    )).wait();
    await (await capacityProofContract.setFileRegistration(
      fileRegistrationAddress,
    )).wait();
    console.log("FileRegistrationSC capacity/snapshot lifecycle wired");

    // G.4 reciprocal deletion-release ring. DeletionReleaseSC has immutable producer
    // addresses; each producer accepts this exact reciprocal candidate once only.
    const deletionRelease = await ethers.deployContract("DeletionReleaseSC", [
      fileRegistrationAddress,
      partitionSnapshotProofAddress,
      storageProofAddress,
    ]);
    await deletionRelease.waitForDeployment();
    deletionReleaseAddress = await deletionRelease.getAddress();
    const storageProof = await ethers.getContractAt("StorageProofSC", storageProofAddress);
    const snapshotProof = await ethers.getContractAt(
      "PartitionSnapshotProofSC", partitionSnapshotProofAddress,
    );
    await (await fileRegistration.setDeletionRelease(deletionReleaseAddress)).wait();
    await (await snapshotProof.setDeletionRelease(deletionReleaseAddress)).wait();
    await (await storageProof.setDeletionRelease(deletionReleaseAddress)).wait();
    const ring = [
      await fileRegistration.deletionRelease(),
      await snapshotProof.deletionRelease(),
      await storageProof.deletionRelease(),
    ];
    if (ring.some((address) => address.toLowerCase() !== deletionReleaseAddress.toLowerCase())) {
      throw new Error("DeletionReleaseSC reciprocal wiring mismatch");
    }
    console.log("DeletionReleaseSC deployed/bound:", deletionReleaseAddress);

    await (await vaultKeeperRegistry.setFileRegistrar(fileRegistrationAddress)).wait();
    console.log("VaultKeeperRegistry.fileRegistrar set to:", fileRegistrationAddress);

    if (vkEscrowAddress && vkEscrowContract) {
      const timeoutResolver = await ethers.deployContract(
        "StorageRegistrationTimeout", [vkEscrowAddress, fileRegistrationAddress],
      );
      await timeoutResolver.waitForDeployment();
      storageRegistrationTimeoutAddress = await timeoutResolver.getAddress();
      await (await fileRegistration.setRegistrationTimeoutResolver(storageRegistrationTimeoutAddress)).wait();
      await (await vkEscrowContract.setRegistrationTimeoutResolver(storageRegistrationTimeoutAddress)).wait();
      console.log("StorageRegistrationTimeout deployed/wired:", storageRegistrationTimeoutAddress);
    }
  } catch (e) {
    throw new Error(
      `Required storage lifecycle deployment failed: ${e.message || e}`,
    );
  }
  const requiredProductionContracts = {
    GuardianRegistry: guardianRegistryAddress,
    VaultKeeperRegistry: vaultKeeperRegistryAddress,
    AccessControlFT: aclAddress,
    DataVault: dvAddress,
    ShareVerifier: zkDkgShareVerifierAddress,
    V2PrePartialVerifier: v2PrePartialVerifierAddress,
    SharePossessionVerifier: sharePossessionVerifierAddress,
    ZkDkgDisputeManager: zkDkgDisputeManagerAddress,
    ZkDkgCoordinatorV2: zkDkgCoordinatorV2Address,
    GuardianShareProof: guardianShareProofAddress,
    TElGv2: telgV2Address,
    ReputationManager: reputationManagerAddress,
    StakingManager: stakingManagerAddress,
    RewardManager: rewardManagerAddress,
    VKEscrow: vkEscrowAddress,
    StorageProofSC: storageProofAddress,
    CapacityProofSC: capacityProofAddress,
    PartitionSnapshotProofSC: partitionSnapshotProofAddress,
    StorageProofPartitionVerifier: storageProofPartitionVerifierAddress,
    StorageProofPartitionGeneratedVerifier: storageProofPartitionGeneratedVerifierAddress,
    StorageReceiptDispute: storageReceiptDisputeAddress,
    FileRegistrationSC: fileRegistrationAddress,
    DeletionReleaseSC: deletionReleaseAddress,
    StorageRegistrationTimeout: storageRegistrationTimeoutAddress,
  };
  const missingProductionContracts = Object.entries(requiredProductionContracts)
    .filter(([, address]) => !address || address === ethers.ZeroAddress)
    .map(([name]) => name);
  if (missingProductionContracts.length > 0) {
    throw new Error(
      `Required FileTrust contracts were not deployed: ${missingProductionContracts.join(", ")}`,
    );
  }

  // Read-only batch reader for discovery nodes: full keeper and guardian rows,
  // a page per eth_call. Stateless and unowned, so it sits outside governance.
  const networkDirectoryReader = await ethers.deployContract("NetworkDirectoryReader", [
    vaultKeeperRegistryAddress,
    guardianRegistryAddress,
    reputationManagerAddress,
    vkEscrowAddress || ethers.ZeroAddress,
    storageProofAddress || ethers.ZeroAddress,
    capacityProofAddress || ethers.ZeroAddress,
    guardianShareProofAddress || ethers.ZeroAddress,
    telgV2Address || ethers.ZeroAddress,
  ]);
  await networkDirectoryReader.waitForDeployment();
  const networkDirectoryReaderAddress = await networkDirectoryReader.getAddress();
  console.log("NetworkDirectoryReader deployed to:", networkDirectoryReaderAddress);

  // Slashing and reward rights, bound once now that every protocol contract exists. After
  // this neither list can grow: a compromised entry can only be revoked.
  await (await stakingManager.bindSlashers(slashers)).wait();
  await (await rewardManager.bindRewarders(rewarders)).wait();
  // A ReputationManager protocol turns penalty points into slashes: no more may be added.
  await (await reputationManager.lockProtocolContracts()).wait();
  if (!(await reputationManager.protocolsLocked())) throw new Error("ReputationManager protocol list is not locked");
  for (const slasher of slashers) {
    if (!(await stakingManager.authorizedSlashers(slasher))) throw new Error(`slasher ${slasher} was not bound`);
  }
  for (const rewarder of rewarders) {
    if (!(await rewardManager.authorizedRewarders(rewarder))) throw new Error(`rewarder ${rewarder} was not bound`);
  }
  for (const unprivileged of [zkDkgCoordinatorV2Address, zkDkgDisputeManagerAddress]) {
    if (await stakingManager.authorizedSlashers(unprivileged) || await rewardManager.authorizedRewarders(unprivileged)) {
      throw new Error(`${unprivileged} must hold no slashing or reward rights`);
    }
  }
  if ((await stakingManager.treasury()).toLowerCase() !== treasuryAddress.toLowerCase()) {
    throw new Error("StakingManager treasury verification failed");
  }
  console.log("StakingManager slashers bound:", slashers.join(", "));
  console.log("RewardManager rewarders bound:", rewarders.join(", "));

  // Transfer every privileged protocol contract only after all initial wiring
  // is complete. From this point forward, maintenance calls require a public,
  // delayed TimelockController operation. Capacity and snapshot ownership are
  // part of the same boundary; leaving either with the deployer would permit
  // unilateral changes to the authoritative proof ledger.
  // Phase 2: the versioned address registry. The deployer records this deployment in it
  // below, before the timelock accepts its ownership with the others.
  const addressRegistry = await ethers.deployContract("FileTrustAddressRegistry");
  await addressRegistry.waitForDeployment();
  const addressRegistryAddress = await addressRegistry.getAddress();
  console.log("FileTrustAddressRegistry deployed to:", addressRegistryAddress);

  const governedContracts = [
    ["GuardianRegistry", guardianRegistry],
    ["AccessControlFT", acl],
    ["DataVault", dataVault],
    ["ReputationManager", reputationManager],
    ["StakingManager", stakingManager],
    ["RewardManager", rewardManager],
    ["VaultKeeperRegistry", vaultKeeperRegistry],
    ["CapacityProofSC", capacityProofContract],
  ];
  if (guardianWorkReward) governedContracts.push(["GuardianWorkReward", guardianWorkReward]);
  if (guardianShareProofAddress) {
    governedContracts.push([
      "GuardianShareProof",
      await ethers.getContractAt("GuardianShareProof", guardianShareProofAddress),
    ]);
  }
  if (storageProofAddress) {
    governedContracts.push([
      "StorageProofSC",
      await ethers.getContractAt("StorageProofSC", storageProofAddress),
    ]);
  }
  if (partitionSnapshotProofAddress) {
    governedContracts.push([
      "PartitionSnapshotProofSC",
      await ethers.getContractAt("PartitionSnapshotProofSC", partitionSnapshotProofAddress),
    ]);
  }
  if (storageReceiptDisputeAddress) {
    governedContracts.push([
      "StorageReceiptDispute",
      await ethers.getContractAt("StorageReceiptDispute", storageReceiptDisputeAddress),
    ]);
  }
  if (vkEscrowContract) governedContracts.push(["VKEscrow", vkEscrowContract]);
  if (fileRegistrationContract) governedContracts.push(["FileRegistrationSC", fileRegistrationContract]);
  governedContracts.push(["FileTrustAddressRegistry", addressRegistry]);
  for (const [label, address] of [
    ["PartitionVerifierRouter", partitionRouterAddress],
    ["SharePossessionVerifierRouter", sharePossessionRouterAddress],
    ["PrePartialVerifierRouter", prePartialRouterAddress],
  ]) {
    if (address) governedContracts.push([label, await ethers.getContractAt("FileTrustVerifierRouter", address)]);
  }

  // The OpenZeppelin-owned contracts only name the timelock as pending owner here: the
  // timelock takes them over by executing one acceptOwnership batch after its delay. In
  // the local profile the deployer is the proposer and schedules that batch now; on
  // mainnet the proposer multisig schedules it from governance_handover.json. Until the
  // batch runs, the deployer still owns those contracts. scripts/accept_governance_handover.js
  // executes it once ready and verifies every owner.
  const pendingAcceptance = await startHandover(governedContracts, timelockAddress);
  for (const [label] of governedContracts) {
    const pending = pendingAcceptance.some(([pendingLabel]) => pendingLabel === label);
    console.log(`${label} ${pending ? "named the timelock as pending owner" : "ownership transferred to timelock"}`);
  }
  const handoverBatch = await acceptanceBatch(ethers, pendingAcceptance);
  const handoverOperationId = await operationId(timelock, handoverBatch);
  const deployerProposes = await timelock.hasRole(await timelock.PROPOSER_ROLE(), deployerAddress);
  let handoverReadyAt = null;
  if (deployerProposes) {
    await scheduleAcceptance(timelock, handoverBatch, governance.delay);
    handoverReadyAt = (await timelock.getTimestamp(handoverOperationId)).toString();
    console.log(`Ownership acceptance scheduled: operation ${handoverOperationId}, ready at ${handoverReadyAt}`);
  } else {
    console.log(`Ownership acceptance must be proposed by ${governance.proposers.join(", ")}: operation ${handoverOperationId}`);
  }
  const governanceHandover = {
    timelock: timelockAddress,
    operationId: handoverOperationId,
    scheduled: deployerProposes,
    readyAt: handoverReadyAt,
    delaySeconds: governance.delay.toString(),
    ...handoverBatch,
  };
  // ───────────────────────────────────────────────────────────────────────────

  console.log("\nDeployment wiring and governance scheduling completed.");
  console.log("--------------------------------");
  console.log("GuardianRegistry:    ", guardianRegistryAddress);
  console.log("FileTrustTimelock:   ", timelockAddress);
  console.log("VaultKeeperRegistry: ", vaultKeeperRegistryAddress);
  console.log("NetworkDirectoryReader:", networkDirectoryReaderAddress);
  console.log("VKEscrow:            ", vkEscrowAddress || "");
  console.log("AccessControlFT:     ", aclAddress);
  console.log("DataVault:           ", dvAddress);
  console.log("DKG:                 ", dkgAddress);
  console.log("zkDKG ShareVerifier: ", zkDkgShareVerifierAddress);
  console.log("zkDKG Supported N:   ", zkDkgSupportedParticipantCounts.join(","));
  console.log("zkDKG ShareVerifier by N:", JSON.stringify(zkDkgShareVerifierAddressesByN));
  console.log("V2PrePartialVerifier:", v2PrePartialVerifierAddress);
  console.log("SharePossessionVerifier:", sharePossessionVerifierAddress);
  console.log("ZkDkgDisputeManager: ", zkDkgDisputeManagerAddress);
  console.log("ZkDkgCoordinatorV2:  ", zkDkgCoordinatorV2Address);
  console.log("GuardianShareProof:  ", guardianShareProofAddress);
  console.log("StorageProofSC:               ", storageProofAddress);
  console.log("CapacityProofSC:              ", capacityProofAddress);
  console.log("CapacityCertificationSC:      ", capacityCertificationAddress || "");
  console.log("CapacityIncrementalBatchSC:   ", capacityIncrementalBatchAddress || "");
  console.log("PartitionSnapshotProofSC:     ", partitionSnapshotProofAddress);
  console.log("StorageReceiptDispute:         ", storageReceiptDisputeAddress || "");
  console.log("StorageRegistrationTimeout:    ", storageRegistrationTimeoutAddress || "");
  console.log("FileRegistrationSC:            ", fileRegistrationAddress || "");
  console.log("StorageProofVerifier:          ", storageProofVerifierAddress || "");
  console.log("StorageProofPartitionVerifier: ", storageProofPartitionVerifierAddress || "");
  console.log("StorageProofPartitionGenVerifier:", storageProofPartitionGeneratedVerifierAddress || "");
  console.log("BN254MathLib:                  ", bn254MathLibAddress || "");
  console.log("PublicInputMSMLib:             ", publicInputMSMLibAddress || "");
  console.log("StorageProofGeneratedVerifier:", storageProofGeneratedVerifierAddress || "");
  console.log("StorageProofGeneratedVerifierContract:", storageProofGeneratedVerifierContract || "");
  console.log("TElG:                ", telgAddress);
  console.log("TElGv2:              ", telgV2Address);
  console.log("ReputationManager:   ", reputationManagerAddress);
  console.log("StakingManager:      ", stakingManagerAddress);
  console.log("RewardManager:       ", rewardManagerAddress);
  console.log("GuardianWorkReward:  ", guardianWorkRewardAddress || "");
  console.log("MinimumGuardianStake:", minGuardianStake.toString());
  console.log("MissedEpochPenalty:  ", missedEpochPenaltyWei.toString());
  console.log("DkgComplaintFine:    ", verifiedDkgComplaintSlashWei.toString());
  console.log("SU_TO_WEI_RATE:      ", suToWeiRate.toString());
  console.log("FIXED_GAS_PRICE_WEI: ", fixedGasPriceWei.toString());
  console.log(
    "Reward gas config:",
    `overheads(material=${rewardGasConfig.overheadDkgMaterial}, shareKey=${rewardGasConfig.overheadDkgShareKey}, pre=${rewardGasConfig.overheadPreBatchPartial})`,
              `estimates(material=${rewardGasConfig.estimateDkgMaterial}, shareKey=${rewardGasConfig.estimateDkgShareKey}, pre=${rewardGasConfig.estimatePreBatchPartial})`,
  );
  console.log(
    "Default SU prices:",
    `DKG_MATERIAL=${rewardPrices.dkgMaterialSu}`,
    `DKG_SHARE_KEY=${rewardPrices.dkgShareKeySu}`,
    `PRE_BATCH_PARTIAL=${rewardPrices.preBatchPartialSu}`,
    `V2_DKG_BASE=${rewardPrices.v2DkgBaseSu}`,
    `V2_PRE_BASE=${rewardPrices.v2PreBaseSu}`,
    `BUFFER_BPS=${rewardPrices.gasReimbursementBufferBps}`,
  );

  console.log("\nConfig values:");
  console.log(`FILETRUST_TIMELOCK_ADDRESS = "${timelockAddress}"`);
  console.log(`GUARDIAN_REGISTRY_ADDRESS = "${guardianRegistryAddress}"`);
  console.log(`VAULT_KEEPER_REGISTRY_ADDRESS = "${vaultKeeperRegistryAddress}"`);
  console.log(`NETWORK_DIRECTORY_READER_ADDRESS = "${networkDirectoryReaderAddress}"`);
  console.log(`VK_ESCROW_ADDRESS             = "${vkEscrowAddress || ""}"`);

  console.log(`ACL_ADDRESS               = "${aclAddress}"`);
  console.log(`DV_ADDRESS                = "${dvAddress}"`);
  console.log(`DKG_ADDRESS               = "${dkgAddress}"`);
  console.log(`ZKDKG_SHARE_VERIFIER_ADDRESS = "${zkDkgShareVerifierAddress || ""}"`);
  console.log(`ZKDKG_SUPPORTED_N = "${zkDkgSupportedParticipantCounts.join(",")}"`);
  console.log(`ZKDKG_SUPPORTED_PROFILES = "${zkDkgSupportedCommitteeProfiles.map(({ n, t }) => `${n}:${t}`).join(",")}"`);
  console.log(`ZKDKG_SHARE_VERIFIER_ADDRESSES = "${Object.entries(zkDkgShareVerifierAddressesByN).map(([n, address]) => `${n}:${address}`).join(",")}"`);
  console.log(`ZKDKG_SHARE_VERIFIER_PROFILE_ADDRESSES = "${Object.entries(zkDkgShareVerifierAddressesByProfile).map(([profile, address]) => `${profile}=${address}`).join(",")}"`);
  console.log(`V2_PRE_PARTIAL_VERIFIER_ADDRESS = "${v2PrePartialVerifierAddress || ""}"`);
  console.log(`SHARE_POSSESSION_VERIFIER_ADDRESS = "${sharePossessionVerifierAddress || ""}"`);
  console.log(`ZKDKG_DISPUTE_MANAGER_ADDRESS = "${zkDkgDisputeManagerAddress || ""}"`);
  console.log(`ZKDKG_COORDINATOR_V2_ADDRESS = "${zkDkgCoordinatorV2Address || ""}"`);
  console.log(`GUARDIAN_SHARE_PROOF_ADDRESS = "${guardianShareProofAddress || ""}"`);
  console.log(`STORAGE_PROOF_ADDRESS = "${storageProofAddress || ""}"`);
  console.log(`CAPACITY_PROOF_ADDRESS = "${capacityProofAddress || ""}"`);
  console.log(`PARTITION_SNAPSHOT_PROOF_ADDRESS = "${partitionSnapshotProofAddress || ""}"`);
  console.log(`STORAGE_RECEIPT_DISPUTE_ADDRESS = "${storageReceiptDisputeAddress || ""}"`);
  console.log(`STORAGE_REGISTRATION_TIMEOUT_ADDRESS = "${storageRegistrationTimeoutAddress || ""}"`);
  console.log(`FILE_REGISTRATION_ADDRESS = "${fileRegistrationAddress || ""}"`);
  console.log(`STORAGE_PROOF_VERIFIER_ADDRESS = "${storageProofVerifierAddress || ""}"`);
  console.log(`STORAGE_PROOF_GENERATED_VERIFIER_ADDRESS = "${storageProofGeneratedVerifierAddress || ""}"`);
  console.log(`TELG_ADDRESS              = "${telgAddress}"`);
  console.log(`TELG_V2_ADDRESS           = "${telgV2Address || ""}"`);
  console.log(`REPUTATION_MANAGER_ADDRESS = "${reputationManagerAddress}"`);
  console.log(`STAKING_MANAGER_ADDRESS = "${stakingManagerAddress}"`);
  console.log(`REWARD_MANAGER_ADDRESS = "${rewardManagerAddress}"`);
  console.log(`MIN_GUARDIAN_STAKE_WEI = "${minGuardianStake.toString()}"`);
  console.log(`SU_TO_WEI_RATE = "${suToWeiRate.toString()}"`);
  console.log(`FILETRUST_FIXED_GAS_PRICE_WEI = "${fixedGasPriceWei.toString()}"`);
  console.log(`ZKDKG_KEYGEN_DEADLINE_SECONDS = "${dkgKeyGenDeadlineSeconds.toString()}"`);

  const chain = await ethers.provider.getNetwork();
  fs.mkdirSync(reportsDir, { recursive: true });

  const envAddresses = {
    DKG_ATTEMPT_PROTOCOL: '1',
    DKG_ATTEMPT_CONTROLLER_ADDRESS: dkgRecovery.addresses.DkgAttemptController,
    DKG_ATTEMPT_REGISTRY_ADDRESS: dkgRecovery.addresses.DkgAttemptRegistry,
    DKG_ATTEMPT_ESCROW_ADDRESS: dkgRecovery.addresses.DkgAttemptEscrow,
    DKG_COMMITMENT_BOOK_ADDRESS: dkgRecovery.addresses.DkgCommitmentBook,
    FILETRUST_TIMELOCK_ADDRESS: timelockAddress,
    FILETRUST_TREASURY_ADDRESS: treasuryAddress,
    GUARDIAN_REGISTRY_ADDRESS: guardianRegistryAddress,
    VAULT_KEEPER_REGISTRY_ADDRESS: vaultKeeperRegistryAddress,
    NETWORK_DIRECTORY_READER_ADDRESS: networkDirectoryReaderAddress,
    VK_ESCROW_ADDRESS: vkEscrowAddress || "",
    ACL_ADDRESS: aclAddress,
    DV_ADDRESS: dvAddress,
    DKG_ADDRESS: dkgAddress || "",
    ZKDKG_SHARE_VERIFIER_ADDRESS: zkDkgShareVerifierAddress || "",
    ZKDKG_SUPPORTED_N: zkDkgSupportedParticipantCounts.join(","),
    ZKDKG_SUPPORTED_PROFILES: zkDkgSupportedCommitteeProfiles.map(({ n, t }) => `${n}:${t}`).join(","),
    ZKDKG_SHARE_VERIFIER_ADDRESSES: Object.entries(zkDkgShareVerifierAddressesByN).map(([n, address]) => `${n}:${address}`).join(","),
    ZKDKG_SHARE_VERIFIER_PROFILE_ADDRESSES: Object.entries(zkDkgShareVerifierAddressesByProfile).map(([profile, address]) => `${profile}=${address}`).join(","),
    V2_PRE_PARTIAL_VERIFIER_ADDRESS: v2PrePartialVerifierAddress || "",
    SHARE_POSSESSION_VERIFIER_ADDRESS: sharePossessionVerifierAddress || "",
    ZKDKG_DISPUTE_MANAGER_ADDRESS: zkDkgDisputeManagerAddress || "",
    ZKDKG_COORDINATOR_V2_ADDRESS: zkDkgCoordinatorV2Address || "",
    GUARDIAN_SHARE_PROOF_ADDRESS: guardianShareProofAddress || "",
    STORAGE_PROOF_ADDRESS: storageProofAddress || "",
    CAPACITY_PROOF_ADDRESS: capacityProofAddress || "",
    PARTITION_SNAPSHOT_PROOF_ADDRESS: partitionSnapshotProofAddress || "",
    STORAGE_RECEIPT_DISPUTE_ADDRESS: storageReceiptDisputeAddress || "",
    STORAGE_REGISTRATION_TIMEOUT_ADDRESS: storageRegistrationTimeoutAddress || "",
    STORAGE_REGISTRATION_TIMEOUT_SECONDS: String(storageRegistrationTimeoutSeconds),
    MAX_STORAGE_REGISTRATION_TIMEOUT_SECONDS: String(maxStorageRegistrationTimeoutSeconds),
    CAPACITY_MAX_PROOF_AGE_SECONDS: capacityMaxProofAgeSeconds.toString(),
    CAPACITY_MAX_MANIFEST_OVERHEAD_BYTES: capacityMaxManifestOverheadBytes.toString(),
    FILE_REGISTRATION_ADDRESS: fileRegistrationAddress || "",
    STORAGE_PROOF_VERIFIER_ADDRESS: storageProofVerifierAddress || "",
    STORAGE_PROOF_GENERATED_VERIFIER_ADDRESS: storageProofGeneratedVerifierAddress || "",
    STORAGE_PROOF_GENERATED_VERIFIER_CONTRACT: storageProofGeneratedVerifierContract || "",
    STORAGE_PROOF_PARTITION_VERIFIER_ADDRESS: storageProofPartitionVerifierAddress || "",
    STORAGE_PROOF_PARTITION_GENERATED_VERIFIER_ADDRESS: storageProofPartitionGeneratedVerifierAddress || "",
    STORAGE_PROOF_PARTITION_GENERATED_VERIFIER_CONTRACT: storageProofPartitionGeneratedVerifierContract || "",
    BN254_MATH_LIB_ADDRESS: bn254MathLibAddress || "",
    PUBLIC_INPUT_MSM_LIB_ADDRESS: publicInputMSMLibAddress || "",
    PUBLIC_INPUT_MSM_LIB_CONTRACT: publicInputMSMLibContract || "",
    STORAGEPROOF_ZK_BLOCK_SIZE: String(storageProofZkBlockSize),
    STORAGEPROOF_ZK_TREE_DEPTH: String(storageProofZkTreeDepth),
    TELG_ADDRESS: telgAddress || "",
    TELG_V2_ADDRESS: telgV2Address || "",
    REPUTATION_MANAGER_ADDRESS: reputationManagerAddress,
    STAKING_MANAGER_ADDRESS: stakingManagerAddress,
    REWARD_MANAGER_ADDRESS: rewardManagerAddress,
    MIN_GUARDIAN_STAKE_WEI: minGuardianStake.toString(),
    MISSED_EPOCH_PENALTY_WEI: missedEpochPenaltyWei.toString(),
    VERIFIED_DKG_COMPLAINT_SLASH_WEI: verifiedDkgComplaintSlashWei.toString(),
    SU_TO_WEI_RATE: suToWeiRate.toString(),
    FILETRUST_FIXED_GAS_PRICE_WEI: fixedGasPriceWei.toString(),
    ZKDKG_KEYGEN_DEADLINE_SECONDS: dkgKeyGenDeadlineSeconds.toString(),
  };
  const appConfig = {
    dkg_attempt_protocol: 1,
    filetrust_timelock_address: timelockAddress,
    guardian_registry_address: guardianRegistryAddress,
    vault_keeper_registry_address: vaultKeeperRegistryAddress,
    network_directory_reader_address: networkDirectoryReaderAddress,
    vk_escrow_address: vkEscrowAddress || "",
    acl_address: aclAddress,
    dv_address: dvAddress,
    dkg_address: dkgAddress || "",
    zkdkg_share_verifier_address: zkDkgShareVerifierAddress || "",
    zkdkg_supported_n: zkDkgSupportedParticipantCounts,
    zkdkg_supported_profiles: zkDkgSupportedCommitteeProfiles,
    zkdkg_share_verifier_addresses: zkDkgShareVerifierAddressesByN,
    zkdkg_share_verifier_profile_addresses: zkDkgShareVerifierAddressesByProfile,
    v2_pre_partial_verifier_address: v2PrePartialVerifierAddress || "",
    share_possession_verifier_address: sharePossessionVerifierAddress || "",
    zkdkg_dispute_manager_address: zkDkgDisputeManagerAddress || "",
    zkdkg_coordinator_v2_address: zkDkgCoordinatorV2Address || "",
    guardian_share_proof_address: guardianShareProofAddress || "",
    storageproof_address: storageProofAddress || "",
    capacity_proof_address: capacityProofAddress || "",
    partition_snapshot_proof_address: partitionSnapshotProofAddress || "",
    storage_receipt_dispute_address: storageReceiptDisputeAddress || "",
    storage_registration_timeout_address: storageRegistrationTimeoutAddress || "",
    do_registration_reconciliation_timeout_seconds: storageRegistrationTimeoutSeconds,
    file_registration_address: fileRegistrationAddress || "",
    storageproof_verifier_address: storageProofVerifierAddress || "",
    storageproof_generated_verifier_address: storageProofGeneratedVerifierAddress || "",
    storageproof_generated_verifier_contract: storageProofGeneratedVerifierContract || "",
    storageproof_partition_verifier_address: storageProofPartitionVerifierAddress || "",
    storageproof_partition_generated_verifier_address: storageProofPartitionGeneratedVerifierAddress || "",
    storageproof_partition_generated_verifier_contract: storageProofPartitionGeneratedVerifierContract || "",
    bn254_math_lib_address: bn254MathLibAddress || "",
    public_input_msm_lib_address: publicInputMSMLibAddress || "",
    telg_address: telgAddress || "",
    telg_v2_address: telgV2Address || "",
    reputation_manager_address: reputationManagerAddress,
    staking_manager_address: stakingManagerAddress,
    reward_manager_address: rewardManagerAddress,
    min_guardian_stake_wei: minGuardianStake.toString(),
    su_to_wei_rate: suToWeiRate.toString(),
    filetrust_fixed_gas_price_wei: fixedGasPriceWei.toString(),
    zkdkg_keygen_deadline_seconds: Number(dkgKeyGenDeadlineSeconds),
    zkdkg_dispute_period_seconds: Number(dkgDisputePeriodSeconds),
    share_proof_period_seconds: Number(shareProofConfig.periodSeconds),
    share_proof_grace_seconds: Number(shareProofConfig.graceSeconds),
    share_proof_slot_seconds: Number(shareProofConfig.slotSeconds),
    share_proof_window_seconds: Number(shareProofConfig.windowSeconds),
    share_proof_avg_block_seconds: Number(shareProofConfig.avgBlockSeconds),
    share_proof_window_enforced: shareProofConfig.enforceWindow,
    storageproof_proof_period_seconds: Number(storageProofConfig.periodSeconds),
    storageproof_proof_deadline_seconds: Number(storageProofConfig.deadlineSeconds),
    storageproof_max_challenges: Number(storageProofConfig.maxChallenges),
    storageproof_challenge_count: Number(storageProofConfig.maxChallenges),
    storageproof_deadline_count: parseInt(process.env.STORAGEPROOF_DEADLINE_COUNT || "48"),
    storageproof_partition_max_sectors: parseInt(process.env.PARTITION_CIRCUIT_SECTORS || "16"),
    zk_block_size: storageProofZkBlockSize,
    zk_tree_depth: storageProofZkTreeDepth,
    datavault_combined_v2_batch_upload: true,
  };
  const deployed = {
    generatedAt: nowIsoLocal(),
    network: network.name,
    chainId: chain.chainId.toString(),
    deployer: deployerAddress,
    governance: {
      profile: governance.profile,
      treasury: treasuryAddress,
      proposers: governance.proposers,
      executors: governance.executors,
      cancellers: governance.cancellers,
      delaySeconds: governance.delay.toString(),
      slashers,
      rewarders,
      handover: governanceHandover,
    },
    contracts: {
      ...dkgRecovery.addresses,
      FileTrustTimelock: timelockAddress,
      GuardianRegistry: guardianRegistryAddress,
      VaultKeeperRegistry: vaultKeeperRegistryAddress,
      NetworkDirectoryReader: networkDirectoryReaderAddress,
      VKEscrow: vkEscrowAddress || "",
      AccessControlFT: aclAddress,
      DataVault: dvAddress,
      DKG: dkgAddress || "",
      ShareVerifier: zkDkgShareVerifierAddress || "",
      ShareVerifierByParticipantCount: zkDkgShareVerifierAddressesByN,
      ShareVerifierByCommittee: zkDkgShareVerifierAddressesByProfile,
      V2PrePartialVerifier: v2PrePartialVerifierAddress || "",
      SharePossessionVerifier: sharePossessionVerifierAddress || "",
      ZkDkgDisputeManager: zkDkgDisputeManagerAddress || "",
      ZkDkgCoordinatorV2: zkDkgCoordinatorV2Address || "",
      GuardianShareProof: guardianShareProofAddress || "",
      StorageProofSC: storageProofAddress || "",
      CapacityProofSC: capacityProofAddress || "",
      CapacityCertificationSC: capacityCertificationAddress || "",
      CapacityIncrementalBatchSC: capacityIncrementalBatchAddress || "",
      PartitionSnapshotProofSC: partitionSnapshotProofAddress || "",
      StorageProofPartitionVerifier: storageProofPartitionVerifierAddress || "",
      StorageProofPartitionGeneratedVerifier: storageProofPartitionGeneratedVerifierAddress || "",
      StorageReceiptDispute: storageReceiptDisputeAddress || "",
      StorageRegistrationTimeout: storageRegistrationTimeoutAddress || "",
      FileRegistrationSC: fileRegistrationAddress || "",
      DeletionReleaseSC: deletionReleaseAddress || "",
      StorageProofVerifier: storageProofVerifierAddress || "",
      StorageProofGeneratedVerifier: storageProofGeneratedVerifierAddress || "",
      StorageProofGeneratedVerifierContract: storageProofGeneratedVerifierContract || "",
      BN254MathLib: bn254MathLibAddress || "",
      PublicInputMSMLib: publicInputMSMLibAddress || "",
      TElG: telgAddress || "",
      TElGv2: telgV2Address || "",
      ReputationManager: reputationManagerAddress,
      StakingManager: stakingManagerAddress,
      RewardManager: rewardManagerAddress,
      GuardianWorkReward: guardianWorkRewardAddress || "",
      FileTrustAddressRegistry: addressRegistryAddress,
      PartitionVerifierRouter: partitionRouterAddress,
      SharePossessionVerifierRouter: sharePossessionRouterAddress,
      PrePartialVerifierRouter: prePartialRouterAddress,
    },
    capabilities: {
      dkgAttemptProtocol: 1,
      datavaultCombinedV2BatchUpload: true,
      dataVaultCombinedV2BatchFunction: "createV2BatchWithCids",
      zkdkgSupportedParticipantCounts: zkDkgSupportedParticipantCounts,
      zkdkgSupportedCommitteeProfiles: zkDkgSupportedCommitteeProfiles,
      zkdkgShareVerifierByParticipantCount: zkDkgShareVerifierAddressesByN,
      zkdkgShareVerifierByCommittee: zkDkgShareVerifierAddressesByProfile,
    },
    env: envAddresses,
    appConfig,
    economics: {
      minimumGuardianStakeWei: minGuardianStake.toString(),
      missedEpochPenaltyWei: missedEpochPenaltyWei.toString(),
      verifiedDkgComplaintSlashWei: verifiedDkgComplaintSlashWei.toString(),
      suToWeiRate: suToWeiRate.toString(),
      fixedGasPriceWei: fixedGasPriceWei.toString(),
      rewardPrices: {
        dkgMaterialSu: rewardPrices.dkgMaterialSu.toString(),
        dkgShareKeySu: rewardPrices.dkgShareKeySu.toString(),
        dkgFinalizationSu: rewardPrices.dkgFinalizationSu.toString(),
        preBatchPartialSu: rewardPrices.preBatchPartialSu.toString(),
        preReadyNotUsedSu: rewardPrices.preReadyNotUsedSu.toString(),
        v2DkgBaseSu: rewardPrices.v2DkgBaseSu.toString(),
        v2PreBaseSu: rewardPrices.v2PreBaseSu.toString(),
        gasReimbursementBufferBps: rewardPrices.gasReimbursementBufferBps.toString(),
      },
      storageProof: {
        periodSeconds: storageProofConfig.periodSeconds.toString(),
        deadlineSeconds: storageProofConfig.deadlineSeconds.toString(),
        maxChallenges: storageProofConfig.maxChallenges.toString(),
      },
      rewardGasConfig: {
        overheadDkgMaterial: rewardGasConfig.overheadDkgMaterial.toString(),
        overheadDkgShareKey: rewardGasConfig.overheadDkgShareKey.toString(),
        overheadPreBatchPartial: rewardGasConfig.overheadPreBatchPartial.toString(),
        estimateDkgMaterial: rewardGasConfig.estimateDkgMaterial.toString(),
        estimateDkgShareKey: rewardGasConfig.estimateDkgShareKey.toString(),
        estimatePreBatchPartial: rewardGasConfig.estimatePreBatchPartial.toString(),
      },
    },
  };
  // Version 1 of every contract, in the registry, while the deployer still owns it: the
  // ownership acceptance scheduled above runs only after the timelock delay.
  await validateDeploymentBindings(ethers, deployed);
  const registered = await registerDeployment(
    ethers, addressRegistry, deployed.contracts, path.join(blockchainDir, "artifacts", "contracts"),
  );
  deployed.addressRegistry = { address: addressRegistryAddress, chainId: deployed.chainId, entries: registered };
  console.log(`FileTrustAddressRegistry: ${registered.length} contracts recorded as version 1`);

  // FILETRUST_DEPLOY_OUTPUT_DIR keeps a rehearsal deployment's files out of this
  // workspace (with FILETRUST_REPO_ROOT for the reports).
  const outputDir = process.env.FILETRUST_DEPLOY_OUTPUT_DIR || blockchainDir;
  const reportAddressesPath = path.join(reportsDir, "deployed_addresses.json");
  const blockchainAddressesPath = path.join(outputDir, "deployed_addresses.json");
  const handoverPath = path.join(reportsDir, "governance_handover.json");
  const deployedJson = `${JSON.stringify(deployed, null, 2)}\n`;
  fs.writeFileSync(reportAddressesPath, deployedJson, "utf8");
  fs.writeFileSync(blockchainAddressesPath, deployedJson, "utf8");
  fs.writeFileSync(handoverPath, `${JSON.stringify(governanceHandover, null, 2)}\n`, "utf8");
  console.log("\nDeployed addresses saved to:");
  console.log(`  ${reportAddressesPath}`);
  console.log(`  ${blockchainAddressesPath}`);
  console.log("Ownership acceptance batch saved to:");
  console.log(`  ${handoverPath}`);

  // One file holding the addresses and every ABI the network config service
  // publishes. That service runs on its own machine, away from the chain and
  // away from this 47 MB artifacts tree, so this is what gets copied there --
  // one file, so there is no way to copy half of it.
  const bundle = writeNetworkConfigBundle(blockchainDir, deployed, { outputDir });
  console.log("\nNetwork config bundle:");
  console.log(`  ${bundle.path}  (${bundle.present}/${bundle.required} ABIs)`);
  if (bundle.missing.length) {
    throw new Error(`Deployment bundle is incomplete: ${bundle.missing.join(', ')}`);
  } else {
    console.log("  Copy that one file to the network config server and restart nothing:");
    console.log("  it notices a new deploy by itself.");
  }

  console.log("Use the generated manifest and ABI bundle to configure clients.");
  console.log("\nDeployment completed successfully.");
  return deployed;
}

export const deployment = main();
deployment.catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
