package core

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"strings"
)

func Analyse(filename string) error {

	exe, err := analysis.LoadExecutable(filename)

	if err != nil {
		return err
	}

	logger.Info("Analysing " + filename)
	logger.Debug(exe.String())

	threatScore, err := staticAnalysis(exe)

	if err != nil {
		return errors.New("Not able to perform static analysis : " + err.Error())
	}

	fmt.Println("Score: ", threatScore)

	// TODO : If static analysis is sure the binary is a threat, skip dynamic analysis

	threatScore, err = dynamicAnalysis(exe)

	if err != nil {
		return errors.New("Not able to perform dynamic analysis : " + err.Error())
	}

	fmt.Println("Score: ", threatScore)
	return nil
}

func staticAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("\n_____STATIC__ANALYSIS_____")

	hashIsKnown, err := static.IsHashKnownToBeMalicious(exe)

	if err != nil {
		logger.Error(err.Error())
		logger.Debug("Trying to fix the error by syncing the database.")
		err = SyncDatabase()

		if err != nil {
			return 0, err
		}

		hashIsKnown, err = static.IsHashKnownToBeMalicious(exe)

		if err != nil {
			return 0, err
		}
	}

	if hashIsKnown {
		malwareDetected(exe)
	}
	/*
		ssDeepIsKnown, err := static.IsSSDeepHashKnownToBeMalicious(exe)

		if err != nil {
			logger.Error(err.Error())
			logger.Debug("Trying to fix the error by syncing the database.")
			err = SyncDatabase()

			if err != nil {
				return 0, err
			}

			hashIsKnown, err = static.IsHashKnownToBeMalicious(exe)

			if err != nil {
				return 0, err
			}
		}
	*/
	var score uint = 0

	/*
		if ssDeepIsKnown {
			logger.Warning("SSDeep hash is known, potential malware ! Running further analysis...")
			score += 50
		}
	*/
	matches, err := yaraGrep.GetAllMatchingRules(exe)

	if err != nil {
		return 0, err
	}

	if len(matches) <= 0 {
		logger.Info("No YARA match.")
	} else {
		for _, match := range matches {

			// Skip is__elf rule
			if match.Rule == "is__elf" {
				continue
			}

			logger.Info("[" + match.Namespace + "]" + " is matching with " + match.Rule)

			switch match.Namespace {
			case "malware":

				// Add here rules that can't be considered as malware detection
				if match.Rule == "with_sqlite" {
					break
				}

				switch match.Rule {
				case "suspicious_packer_section":
					logger.Warning("Suspicious packed binary detected")
					score += 50

				case "ldpreload":
					logger.Warning("LD_PRELOAD detected")
					score += 20

				default:
					malwareDetected(exe)
				}

			case "packer":
				if strings.HasPrefix(match.Rule, "UPX") {
					logger.Warning("Suspicious packed binary detected")
					score += 50
				}

			case "anti-debug/vm":
				if match.Rule == "vmdetect_misc" {
					logger.Warning("The binary tries to detect if it's running in a VM")
					score += 60
				} else if strings.HasPrefix(match.Rule, "network_") {
					logger.Warning("The binary uses typical malware communications")
					score += 20
				} else {
					score += 40
				}

			default:
				logger.Warning(fmt.Sprintf("Namespace '%v' not supported yet !", match.Namespace))
			}
		}
	}

	return score, nil
}

func dynamicAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("\n_____DYNAMIC_ANALYSIS_____")
	return 0, nil
}

func malwareDetected(exe *analysis.Executable) {
	var (
		err    error
		choice string
	)

	logger.Danger(exe.Filename + " is a malware")
	reader := bufio.NewReader(os.Stdin)

	for choice != "yes" && choice != "no" {
		fmt.Print("Do you want to delete this file ? [yes/no] ")
		choice, err = reader.ReadString('\n')

		if err != nil {
			logger.Fatal(err.Error())
		}

		choice = strings.ToLower(choice[:len(choice)-1])
	}

	if choice == "yes" {
		logger.Info("Deleting malware...")
	} else {
		logger.Info("Ignoring...")
	}
}
