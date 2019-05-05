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
	/*
		threatScore, err = dynamicAnalysis(exe)

		if err != nil {
			return errors.New("Not able to perform dynamic analysis : " + err.Error())
		}

		fmt.Println("Score: ", threatScore)
	*/

	if threatScore >= 100 {
		logger.Danger("Threat score >= 100")
		malwareDetected(exe)
	}

	return nil
}

func staticAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("\n_____STATIC__ANALYSIS_____")
	var score uint = 0

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
		return 100, nil
	}

	logger.Info("Looking for IPs and domains known to be malicious")
	var maliciousIPorDomainFound bool

	if maliciousIPorDomainFound, err = static.MaliciousDomainFound(exe.Content); err != nil {
		return 0, err
	} else if maliciousIPorDomainFound {
		score += 70
	} else {

		if maliciousIPorDomainFound, err = static.MaliciousIPFound(exe.Content); err != nil {
			return 0, err
		} else if maliciousIPorDomainFound {
			score += 70
		}
	}

	ssDeepDistance, err := static.GetHighestSSDeepDistance(exe)

	if err != nil {
		logger.Error(err.Error())
		logger.Debug("Trying to fix the error by syncing the database.")
		err = SyncDatabase()

		if err != nil {
			return 0, err
		}

		ssDeepDistance, err = static.GetHighestSSDeepDistance(exe)

		if err != nil {
			return 0, err
		}
	}

	if ssDeepDistance > 80 {
		logger.Danger(fmt.Sprintf("SSDeep distance is higher than 80 (%v), considered a malware.", ssDeepDistance))
		malwareDetected(exe)
		return 0, nil
	}

	logger.Info("Looking for matching YARA rules")
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
					return 0, nil
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
