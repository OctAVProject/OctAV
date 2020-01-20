package core

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/dynamic"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/sqweek/dialog"
	"os"
	"strings"
	"time"
)

type LogEntry struct {
	Content string
	IsError bool
}

type Analysis struct {
	Files             []string
	FileBeingAnalysed string
	IsRunning         bool
	Progress          float64
	Logs              []LogEntry
}

func (currentAnalysis *Analysis) AddInfo(msg string) {
	currentAnalysis.Logs = append(currentAnalysis.Logs, LogEntry{Content: msg, IsError: false})
}

func (currentAnalysis *Analysis) AddError(msg string) {
	currentAnalysis.Logs = append(currentAnalysis.Logs, LogEntry{Content: msg, IsError: true})
}

func (currentAnalysis *Analysis) Start() error {

	var (
		staticThreatScore  uint
		dynamicThreatScore uint
		exe                *analysis.Executable
		start              time.Time
		elapsed            time.Duration
		err                error
	)

	currentAnalysis.IsRunning = true
	maxProgressPerFile := 100. / float64(len(currentAnalysis.Files))

	for _, filepath := range currentAnalysis.Files {
		fileProgress := 0.
		currentAnalysis.Progress += fileProgress * maxProgressPerFile / 100.

		logger.Info("Analysing " + filepath)
		currentAnalysis.AddInfo("Analysing " + filepath)
		exe, err = analysis.LoadExecutable(filepath)

		if err != nil {
			logger.Error(err.Error())
			currentAnalysis.AddError(err.Error())
			goto NextFile
		}

		fileProgress = 5.                                          // 5% of the file analysis is done
		currentAnalysis.Progress += 5. * maxProgressPerFile / 100. // +5%

		logger.Debug(exe.String())

		start = time.Now()
		staticThreatScore, err = staticAnalysis(exe)

		if err != nil {
			errStr := "Not able to perform static analysis : " + err.Error()
			logger.Error(errStr)
			currentAnalysis.AddError(errStr)
			goto NextFile
		}

		fileProgress = 25.                                          // 25% of the file analysis is done
		currentAnalysis.Progress += 20. * maxProgressPerFile / 100. // +20%

		elapsed = time.Now().Sub(start)
		logger.Info(fmt.Sprintf("Static Analysis done in %v", elapsed))

		logger.Info(fmt.Sprintf("Static score: %v", staticThreatScore))

		if staticThreatScore >= 100 {
			malwareDetected(exe)
			goto NextFile
		}

		start = time.Now()
		dynamicThreatScore, err = dynamicAnalysis(exe)

		if err != nil {
			errStr := "Not able to perform dynamic analysis : " + err.Error()
			logger.Error(errStr)
			currentAnalysis.AddError(errStr)
			goto NextFile
		}

		fileProgress = 99.                                          // 99% of the file analysis is done
		currentAnalysis.Progress += 74. * maxProgressPerFile / 100. // +74%

		elapsed = time.Now().Sub(start)
		logger.Info(fmt.Sprintf("Dynamic Analysis done in %v", elapsed))

		logger.Info(fmt.Sprintf("Dynamic score: %v", dynamicThreatScore))

		if dynamicThreatScore >= 100 {
			currentAnalysis.AddError("Malware detected : " + filepath)
			malwareDetected(exe)
		} else if staticThreatScore+dynamicThreatScore >= 170 {
			currentAnalysis.AddError("Malware detected : " + filepath)
			malwareDetected(exe)
		}

		elapsed = time.Now().Sub(start)
		currentAnalysis.AddInfo(fmt.Sprintf("File analysis done in %v", elapsed))

	NextFile:
		currentAnalysis.Progress += (100. - fileProgress) * maxProgressPerFile / 100. // Add the remaining to make 100%
	}

	currentAnalysis.IsRunning = false
	return nil
}

func staticAnalysis(exe *analysis.Executable) (uint, error) {
	logger.Header("static analysis")

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

	if ssDeepDistance > 90 {
		logger.Danger("SSDeep distance is higher than 90")
		score += 80
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
					logger.Danger(fmt.Sprintf("Program matched YARA rule '%v' meaning it's a malware", match.Rule))
					return 100, nil
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

	logger.Header("dynamic analysis")
	logger.Info("Analysing binary in a sandboxed environment, this might take some time...")

	jsonReport, err := dynamic.SendFileToSandBox(exe)
	if err != nil {
		return 0, err
	}

	if jsonReport["dynamic_analysis"] == nil {
		return 0, errors.New("no behavior analysis in the report")
	}

	behavior := jsonReport["dynamic_analysis"].(map[string]interface{})
	processes := behavior["processes"].([]interface{})
	openedFiles := behavior["open_files"].([]interface{})

	logger.Debug(fmt.Sprintf("%v processes were created", len(processes)))

	for _, file := range openedFiles {
		logger.Debug(fmt.Sprintf("Opened file: %v", file))
	}

	syscallsIds := make([]int, 0)

	for _, process := range processes {
		pid := fmt.Sprintf("%v", process.(map[string]interface{})["pid"].(float64)) // float to str
		syscalls := behavior["syscalls"].([]interface{})

		if len(syscalls) == 0 {
			return 0, errors.New("no syscall were returned by the sandbox")
		}

		for _, syscall := range syscalls {

			if syscall.(map[string]interface{})["pid"].(string) != pid {
				continue
			}

			syscallName := syscall.(map[string]interface{})["name"].(string)

			if syscall, present := dynamic.Syscalls[syscallName]; present {
				syscallsIds = append(syscallsIds, syscall)
			}
		}
	}

	prediction, err := dynamic.ApplyModel(syscallsIds)

	prediction_threshold := 0.5

	if prediction > prediction_threshold {
		return 100, err
	} else if err != nil {
		return 0, err
	}

	return uint(prediction * 100 / 0.5), nil
}

func malwareDetected(exe *analysis.Executable) {
	var (
		err    error
		choice string
	)

	logger.Danger(exe.Filename + " classified as a malware")

	if !DaemonMode {
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
			logger.Danger("Not deleting " + exe.Filename)
		}
	} else {

		if dialog.Message("%s", exe.Filename+" has been identified as a malware, do you want to delete it ?").Title("Malware detected !").YesNo() {
			logger.Info("Deleting malware...")
		} else {
			logger.Danger("Not deleting " + exe.Filename)
		}
	}

}
