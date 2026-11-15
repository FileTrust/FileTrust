import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatNodeTestRunner from "@nomicfoundation/hardhat-node-test-runner";
import { SOLIDITY_COMPILER } from "./scripts/lib/compiler_policy.js";
import stableSimulation from "./scripts/testing/stable_simulation.js";

export default defineConfig({
  plugins: [hardhatEthers, hardhatNodeTestRunner, stableSimulation],

  solidity: SOLIDITY_COMPILER,

  paths: {
    sources: "contracts",
    tests: "test",
    cache: "cache",
    artifacts: "artifacts",
  },

  networks: {
    // Simulated EVM used by the protocol test suite. It must stay identical to the
    // Blockchain workspace so a contract change is validated the same way in both.
    node: {
      type: "edr-simulated",
      // Match the approved chain/compiler target instead of following EDR's
      // moving "latest hardfork" default (currently Osaka).
      hardfork: "prague",
      allowBlocksWithSameTimestamp: true,
      // Portable checkpoint replay starts a fresh EVM at the captured genesis timestamp.
      // Normal runs remain wall-clock based when the opt-in variable is absent.
      initialDate: process.env.FILETRUST_HARDHAT_INITIAL_DATE || new Date(),
      initialBaseFeePerGas: 0,
      gasPrice: Number(process.env.FILETRUST_FIXED_GAS_PRICE_WEI || "1000000"),
    },

    // The FileTrust Cosmos EVM chain (filetrust_31338-1, EVM chain id 31338).
    // This is the deployment target; `scripts/local_filetrust_node.sh` starts it.
    filetrustLocal: {
      type: "http",
      chainType: "l1",
      url: process.env.FILETRUST_COSMOS_RPC_URL || "http://127.0.0.1:8545",
      gasPrice: Number(process.env.FILETRUST_FIXED_GAS_PRICE_WEI || "1000000"),
    },
  },
});
