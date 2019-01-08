package main

import (
	"fmt"
	"go-flags"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"github.com/OctAVProject/OctAV/internal/octav/scan"
	"strings"
	"github.com/OctAVProject/OctAV/internal/octav/core"
)

type positionalArgs struct {
	File string `positional-arg-name:"FILE"`
}

var commandLine struct {
	// Slice of bool will append 'true' each time the option is encountered (can be set multiple times, like -vvv)
	Verbose        []bool         `short:"v" long:"verbose" description:"Show verbose debug information"`
	Fastscan       bool           `short:"s" long:"fast-scan" description:"Full scan of the system, really time consuming"`
	Fullscan       bool           `long:"full-scan" description:"Smart scan, looking in most probable places"`
	Configscan     bool           `long:"config-scan" description:"Look at config files for security issues"`
	Sync           bool           `long:"sync" description:"Synchronizes database"`
	PositionalArgs positionalArgs `positional-args:"true"`
}

func main() {

	if len(os.Args) == 1 { // Will print help if no argument is given to the program
		os.Args = append(os.Args, "--help")
	}

	// Exclude program name from parsing with [1:]
	remainingArgs, err := flags.ParseArgs(&commandLine, os.Args[1:])

	if err != nil {
		logger.Fatal(err.Error())
	}

	fileToScan := commandLine.PositionalArgs.File

	if len(remainingArgs) > 0 {
		logger.Fatal(fmt.Sprintf("Unknown parameters: '%s'\n", strings.Join(remainingArgs, " ")))
	}

	if commandLine.Fastscan && commandLine.Fullscan {
		logger.Fatal(fmt.Sprintf("Can't specify both fastscan and fullscan at the same time."))
	}

	if commandLine.Fastscan && fileToScan != "" {
		logger.Fatal(fmt.Sprintf("Can't specify file '%s' when fastscan is used.\n", fileToScan))
	}

	if commandLine.Fullscan && fileToScan != "" {
		logger.Fatal(fmt.Sprintf("Can't specify file '%s' when fullscan is used.\n", fileToScan))
	}

	logger.SetVerboseLevel(len(commandLine.Verbose))

	if commandLine.Sync {
		core.SyncDatabase()
	}

	if commandLine.Fastscan {
		scan.FastScan()
	} else if commandLine.Fullscan {
		scan.FullScan()
	} else {
		err := core.Analyse(fileToScan)

		if err != nil {
			logger.Fatal(err.Error())
		}
	}

	if commandLine.Configscan {
		scan.FullConfigScan()
	}
}
