import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";

export default defineConfig({
  plugins: [hardhatEthers],

  solidity: {
    version: "0.8.37",
    settings: {
      // The chain's newest enabled fork, named rather than left to the
      // compiler. solc 0.8.37 targets osaka by default, and this chain has
      // osaka switched off (x/vm/types/chain_config.go: OsakaTime is nil,
      // PragueTime is 0). Bytecode built for a fork the chain does not run
      // can reach for an opcode that does not exist there, and the failure
      // shows up as a deployment or a call that reverts with nothing to say.
      evmVersion: "prague",
      optimizer: {
        enabled: true,
        // StorageProof is a feature-dense protocol contract. A lower run count
        // keeps deployed bytecode below EIP-170 while retaining the optimizer;
        // proof verification gas is dominated by the verifier precompiles.
        runs: 1,
      },
      viaIR: true,
    },
  },

  paths: {
    sources: "contracts",
    tests: "test",
    cache: "cache",
    artifacts: "artifacts",
  },

  networks: {
    // Isolated simulated EVM for local development.
    node: {
      type: "edr-simulated",
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
