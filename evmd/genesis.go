// Modified by FileTrust from cosmos/evm v0.7.0 (f4ab9a3). What changed and
// why is in FILETRUST_UPSTREAM.md at the root of this repository.
// Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.

package evmd

import (
	"encoding/json"

	"github.com/cosmos/evm/evmd/config"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"cosmossdk.io/math"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
)

// GenesisState of the blockchain is represented here as a map of raw json
// messages key'd by an identifier string.
// The identifier is used to determine which module genesis information belongs
// to so it may be appropriately routed during init chain.
// Within this application default genesis information is retrieved from
// the ModuleBasicManager which populates json from each BasicModule
// object provided to it during init.
type GenesisState map[string]json.RawMessage

// NewEVMGenesisState returns the default genesis state for the EVM module.
//
// NOTE: for the example chain implementation we need to set the default EVM denomination,
// enable ALL precompiles, and include default preinstalls.
func NewEVMGenesisState() *evmtypes.GenesisState {
	evmGenState := evmtypes.DefaultGenesisState()
	evmGenState.Params.EvmDenom = config.NativeBaseDenom
	evmGenState.Params.ActiveStaticPrecompiles = evmtypes.AvailableStaticPrecompiles
	evmGenState.Preinstalls = evmtypes.DefaultPreinstalls

	return evmGenState
}

// NewErc20GenesisState returns the default genesis state for the ERC20 module.
//
// NOTE: for the example chain implementation we are also adding a default token pair,
// which is the base denomination of the chain (i.e. the WEVMOS contract).
func NewErc20GenesisState() *erc20types.GenesisState {
	erc20GenState := erc20types.DefaultGenesisState()
	erc20GenState.TokenPairs = []erc20types.TokenPair{{
		Erc20Address:  config.NativeERC20Address,
		Denom:         config.NativeBaseDenom,
		Enabled:       true,
		ContractOwner: erc20types.OWNER_MODULE,
	}}
	erc20GenState.NativePrecompiles = []string{config.NativeERC20Address}

	return erc20GenState
}

// NewMintGenesisState returns the default genesis state for the mint module.
//
// NOTE: for the example chain implementation we are also adding a default minter.
func NewMintGenesisState() *minttypes.GenesisState {
	mintGenState := minttypes.DefaultGenesisState()

	zero := math.LegacyZeroDec()
	maxSupply, ok := math.NewIntFromString(config.FixedSupplyBaseUnits)
	if !ok {
		panic("invalid FileTrust fixed supply constant")
	}
	mintGenState.Minter.Inflation = zero
	mintGenState.Minter.AnnualProvisions = zero
	mintGenState.Params.MintDenom = config.NativeBaseDenom
	mintGenState.Params.InflationRateChange = zero
	mintGenState.Params.InflationMax = zero
	mintGenState.Params.InflationMin = zero
	mintGenState.Params.MaxSupply = maxSupply
	return mintGenState
}

// NewFeeMarketGenesisState returns the default genesis state for the feemarket module.
//
// NOTE: for the example chain implementation we are disabling the base fee.
func NewFeeMarketGenesisState() *feemarkettypes.GenesisState {
	feeMarketGenState := feemarkettypes.DefaultGenesisState()
	feeMarketGenState.Params.NoBaseFee = false
	feeMarketGenState.Params.BaseFee = math.LegacyNewDec(config.InitialBaseFeeWei)
	feeMarketGenState.Params.MinGasPrice = math.LegacyNewDec(config.InitialBaseFeeWei)
	// A larger denominator makes fee changes gradual (1% per full block rather
	// than the Ethereum default maximum movement of 12.5%).
	feeMarketGenState.Params.BaseFeeChangeDenominator = 100
	feeMarketGenState.Params.ElasticityMultiplier = 4

	return feeMarketGenState
}
