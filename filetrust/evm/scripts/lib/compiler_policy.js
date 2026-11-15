// One approved compiler/settings definition for builds and deployment preflight.
export const SOLIDITY_LONG_VERSION = '0.8.38+commit.1835d247';
export const SOLIDITY_COMPILER = {
  version: '0.8.38',
  settings: {
    // The chain enables Prague and leaves Osaka disabled. Never use the
    // compiler's default EVM target for release bytecode.
    evmVersion: 'prague',
    // Preserve the existing size/gas policy and the complete default optimizer.
    optimizer: { enabled: true, runs: 1 },
    viaIR: true,
  },
};
