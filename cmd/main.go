package main

import (
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core"
	"github.com/OctAVProject/OctAV/internal/octav/core/daemon"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/OctAVProject/OctAV/internal/octav/scan"
	"github.com/jessevdk/go-flags"
	"os"
	"strings"
)

type positionalArgs struct {
	File string `positional-arg-name:"FILE"`
}

var commandLine struct {
	Verbose        string         `short:"l" long:"log-level" description:"Log level" choice:"DEBUG" choice:"INFO" choice:"WARNING" default:"INFO"`
	Daemon         bool           `short:"d" long:"daemon" description:"Put OctAV in an endless loop, watching for events on the computer"`
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

	if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
		return
	}

	if commandLine.Daemon {
		if err = daemon.Manage("start"); err != nil {
			logger.Error(err.Error())
		}
		return
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

	logger.SetVerboseLevel(commandLine.Verbose)

	if _, err := os.Stat("/path/to/whatever"); os.IsNotExist(err) || commandLine.Sync {
		core.SyncDatabase()
	}

	if err = core.Initialize(); err != nil {
		logger.Fatal("Can't initialize the core : " + err.Error())
	}

	if commandLine.Fastscan {
		scan.FastScan()
	} else if commandLine.Fullscan {
		scan.FullScan()
	} else if fileToScan != "" {
		err := core.Analyse(fileToScan)

		if err != nil {
			logger.Fatal(err.Error())
		}
	}

	if commandLine.Configscan {
		scan.FullConfigScan()
	}

	if err = core.Stop(); err != nil {
		logger.Fatal("Can't stop the core properly : " + err.Error())
	}
}
