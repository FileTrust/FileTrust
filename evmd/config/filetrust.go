package config

const (
	AppName            = "filetrustd"
	AppDescription     = "FileTrust sovereign Cosmos EVM chain"
	NativeBaseDenom    = "aftu"
	NativeDisplayDenom = "ftu"
	NativeTokenName    = "FileTrust Unit"
	NativeTokenSymbol  = "FTU"
	NativeDecimals     = uint32(18)

	// Local identifiers are development-only. Mainnet identifiers are chosen
	// and frozen as part of the public genesis ceremony.
	LocalCosmosChainID = "filetrust_31338-1"
	LocalEVMChainID    = uint64(31338)

	// Ten billion FTU represented in the 18-decimal base denomination.
	FixedSupplyBaseUnits = "10000000000000000000000000000"

	// 0.001 gwei. FileTrust has intentionally high on-chain activity, so the
	// fee floor starts low while the fee market still protects congestion.
	InitialBaseFeeWei = int64(1_000_000)
	BlockMaxGas       = int64(100_000_000)

	NativeERC20Address = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
)
