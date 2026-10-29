// Modified by FileTrust from cosmos/evm v0.7.0 (f4ab9a3). What changed and
// why is in FILETRUST_UPSTREAM.md at the root of this repository.
// Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.

package main

import (
	"fmt"
	"os"

	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/evmd/cmd/evmd/cmd"
	"github.com/cosmos/evm/evmd/config"
)

func main() {
	setupSDKConfig()

	rootCmd := cmd.NewRootCmd()
	if err := svrcmd.Execute(rootCmd, config.AppName, config.MustGetDefaultNodeHome()); err != nil {
		fmt.Fprintln(rootCmd.OutOrStderr(), err)
		os.Exit(1)
	}
}

func setupSDKConfig() {
	cfg := sdk.GetConfig()
	config.SetBech32Prefixes(cfg)
	cfg.Seal()
}
