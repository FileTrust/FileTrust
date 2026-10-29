#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Electra Sphere Innovations; see LICENSE-FILETRUST.

set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${FILETRUSTD_BINARY:-$ROOT_DIR/build/filetrustd}"
CHAIN_HOME="${FILETRUST_HOME:-$ROOT_DIR/.local/filetrustd}"
CHAIN_ID="${FILETRUST_CHAIN_ID:-filetrust_31338-1}"
EVM_CHAIN_ID="${FILETRUST_EVM_CHAIN_ID:-31338}"
BASE_DENOM="aftu"
DISPLAY_DENOM="ftu"
BASE_FEE_WEI="1000000"
BLOCK_MAX_GAS="100000000"
KEYRING="test"
VALIDATOR_KEY="validator"
MONIKER="filetrust-local-validator"

# Where the EVM JSON-RPC listens. Loopback by default, because the ordinary use
# of this script is one machine running everything and a chain RPC is not a thing
# to expose without meaning to. A deployment whose other roles live on other
# machines sets this to 0.0.0.0:8545 -- app.toml pins 127.0.0.1, so without an
# override the RPC is unreachable from anywhere else however it is advertised.
JSON_RPC_ADDRESS="${FILETRUST_JSON_RPC_ADDRESS:-127.0.0.1:8545}"
# Exactly 10 billion FTU. The local validator holds the undeployed protocol
# reserve and each of four known development accounts receives 1,000 FTU.
VALIDATOR_BALANCE="9999996000000000000000000000"
DEV_BALANCE="1000000000000000000000"
VALIDATOR_STAKE="1000000000000000000000"
EXPECTED_SUPPLY="10000000000000000000000000000"

# Fresh local identities are generated at initialization; no shared seeds.
DEV_ACCOUNT_COUNT=4

usage() {
  echo "Usage: $0 [--reset] [--no-build] [--init-only]"
}

RESET=false
BUILD=true
INIT_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=true ;;
    --no-build) BUILD=false ;;
    --init-only) INIT_ONLY=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
  shift
done

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

if [[ "$BUILD" == true ]]; then
  make -C "$ROOT_DIR" build
fi

[[ -x "$BINARY" ]] || { echo "filetrustd binary not found: $BINARY" >&2; exit 1; }

if [[ "$RESET" == true ]]; then
  [[ "$CHAIN_HOME" != "/" && "$CHAIN_HOME" != "$HOME" && "$CHAIN_HOME" != "$ROOT_DIR" ]] || { echo "refusing unsafe local reset path" >&2; exit 1; }
  rm -rf -- "$CHAIN_HOME"
fi

if [[ ! -f "$CHAIN_HOME/config/genesis.json" ]]; then
  mkdir -p "$CHAIN_HOME"

  "$BINARY" config set client chain-id "$CHAIN_ID" --home "$CHAIN_HOME"
  "$BINARY" config set client keyring-backend "$KEYRING" --home "$CHAIN_HOME"
  "$BINARY" keys add "$VALIDATOR_KEY" --keyring-backend "$KEYRING" --algo eth_secp256k1 --home "$CHAIN_HOME" --output json > "$CHAIN_HOME/validator-account.json"
  "$BINARY" init "$MONIKER" --overwrite --chain-id "$CHAIN_ID" --home "$CHAIN_HOME"

  GENESIS="$CHAIN_HOME/config/genesis.json"
  TMP="$CHAIN_HOME/config/genesis.tmp.json"

  # The EIP-2935 preinstall below is not optional for FileTrust. The BLOCKHASH opcode on
  # this chain is served from that contract's storage: BeginBlock writes the current hash
  # into it, and historical lookups read it back. The write is skipped entirely when the
  # contract is absent, so without the preinstall BLOCKHASH returns zero for every height
  # and PartitionSnapshotProofSC.sealPartitionSnapshot reverts with "anchor unavailable"
  # on every attempt — no capacity proof ever completes and VK admission never opens.
  # `filetrustd init` produces an empty preinstall list, so genesis has to state it.

  jq --arg denom "$BASE_DENOM" --arg display "$DISPLAY_DENOM" --arg baseFee "$BASE_FEE_WEI" --arg maxGas "$BLOCK_MAX_GAS" --arg maxSupply "$EXPECTED_SUPPLY" '
    .app_state.staking.params.bond_denom = $denom |
    .app_state.gov.params.min_deposit[0].denom = $denom |
    .app_state.gov.params.expedited_min_deposit[0].denom = $denom |
    .app_state.evm.params.evm_denom = $denom |
    .app_state.evm.params.extended_denom_options.extended_denom = $denom |
    .app_state.evm.params.active_static_precompiles = [
      "0x0000000000000000000000000000000000000100",
      "0x0000000000000000000000000000000000000400",
      "0x0000000000000000000000000000000000000800",
      "0x0000000000000000000000000000000000000801",
      "0x0000000000000000000000000000000000000802",
      "0x0000000000000000000000000000000000000803",
      "0x0000000000000000000000000000000000000804",
      "0x0000000000000000000000000000000000000805",
      "0x0000000000000000000000000000000000000806",
      "0x0000000000000000000000000000000000000807"
    ] |
    .app_state.evm.preinstalls = [{
      name: "EIP-2935 - Serve historical block hashes from state",
      address: "0x0000F90827F1C53a10cb7A02335B175320002935",
      code: "0x3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"
    }] |
    .app_state.erc20.native_precompiles = ["0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"] |
    .app_state.erc20.token_pairs = [{
      contract_owner: 1,
      erc20_address: "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
      denom: $denom,
      enabled: true
    }] |
    .app_state.mint.minter.inflation = "0.000000000000000000" |
    .app_state.mint.minter.annual_provisions = "0.000000000000000000" |
    .app_state.mint.params.mint_denom = $denom |
    .app_state.mint.params.inflation_rate_change = "0.000000000000000000" |
    .app_state.mint.params.inflation_max = "0.000000000000000000" |
    .app_state.mint.params.inflation_min = "0.000000000000000000" |
    .app_state.mint.params.max_supply = $maxSupply |
    .app_state.feemarket.params.no_base_fee = false |
    .app_state.feemarket.params.base_fee = ($baseFee + ".000000000000000000") |
    .app_state.feemarket.params.min_gas_price = ($baseFee + ".000000000000000000") |
    .app_state.feemarket.params.base_fee_change_denominator = 100 |
    .app_state.feemarket.params.elasticity_multiplier = 4 |
    .app_state.bank.denom_metadata = [{
      description: "Native FileTrust utility, gas, governance, and staking token.",
      denom_units: [
        {denom: $denom, exponent: 0, aliases: ["attoftu"]},
        {denom: $display, exponent: 18, aliases: ["FTU"]}
      ],
      base: $denom,
      display: $display,
      name: "FileTrust Unit",
      symbol: "FTU",
      uri: "",
      uri_hash: ""
    }] |
    .consensus.params.block.max_gas = $maxGas
  ' "$GENESIS" > "$TMP"
  mv "$TMP" "$GENESIS"

  "$BINARY" genesis add-genesis-account "$VALIDATOR_KEY" "${VALIDATOR_BALANCE}${BASE_DENOM}" --keyring-backend "$KEYRING" --home "$CHAIN_HOME"

  for ((i=0; i<DEV_ACCOUNT_COUNT; i++)); do
    key="dev${i}"
    "$BINARY" keys add "$key" --keyring-backend "$KEYRING" --algo eth_secp256k1 --home "$CHAIN_HOME" --output json > "$CHAIN_HOME/$key-account.json"
    "$BINARY" genesis add-genesis-account "$key" "${DEV_BALANCE}${BASE_DENOM}" --keyring-backend "$KEYRING" --home "$CHAIN_HOME"
  done

  "$BINARY" genesis gentx "$VALIDATOR_KEY" "${VALIDATOR_STAKE}${BASE_DENOM}" --gas-prices "${BASE_FEE_WEI}${BASE_DENOM}" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" --home "$CHAIN_HOME"
  "$BINARY" genesis collect-gentxs --home "$CHAIN_HOME"
  "$BINARY" genesis validate-genesis --home "$CHAIN_HOME"

  SUPPLY=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); denom=sys.argv[2]; print(sum(int(c["amount"]) for b in d["app_state"]["bank"]["balances"] for c in b["coins"] if c["denom"] == denom))' "$GENESIS" "$BASE_DENOM")
  [[ "$SUPPLY" == "$EXPECTED_SUPPLY" ]] || { echo "unexpected FTU genesis supply: $SUPPLY" >&2; exit 1; }

  sed -i.bak 's/timeout_commit = "5s"/timeout_commit = "1s"/' "$CHAIN_HOME/config/config.toml"
  sed -i.bak 's/type = "flood"/type = "app"/' "$CHAIN_HOME/config/config.toml"
  sed -i.bak 's/prometheus = false/prometheus = true/' "$CHAIN_HOME/config/config.toml"
fi

if [[ "$INIT_ONLY" == true ]]; then
  echo "FileTrust genesis initialized at $CHAIN_HOME"
  exit 0
fi

exec "$BINARY" start \
  --home "$CHAIN_HOME" \
  --chain-id "$CHAIN_ID" \
  --evm.evm-chain-id "$EVM_CHAIN_ID" \
  --minimum-gas-prices "0.000000000001${BASE_DENOM}" \
  --evm.min-tip 0 \
  --json-rpc.enable \
  --json-rpc.enable-indexer \
  --json-rpc.address "$JSON_RPC_ADDRESS" \
  --json-rpc.api eth,txpool,net,debug,web3 \
  --json-rpc.allow-insecure-unlock=false \
  --json-rpc.http-body-limit 1048576 \
  --json-rpc.batch-request-limit 100 \
  --json-rpc.batch-response-max-size 8388608 \
  --json-rpc.max-open-connections 256 \
  --json-rpc.http-timeout 15s \
  --json-rpc.http-idle-timeout 30s \
  --keyring-backend memory \
  --pruning nothing
