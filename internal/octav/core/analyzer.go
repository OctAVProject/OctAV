package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/dynamic"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

func Analyse(filename string) error {

	exe, err := analysis.LoadExecutable(filename)

	if err != nil {
		return err
	}

	logger.Info("Analysing " + filename)
	logger.Debug(exe.String())

	start := time.Now()
	staticThreatScore, err := staticAnalysis(exe)

	if err != nil {
		return errors.New("Not able to perform static analysis : " + err.Error())
	}

	elapsed := time.Now().Sub(start)
	logger.Info(fmt.Sprintf("Static Analysis done in %v", elapsed))

	fmt.Println("Static score: ", staticThreatScore)

	if staticThreatScore >= 100 {
		logger.Danger("Threat score >= 100")
		malwareDetected(exe)
		return nil
	}

	start = time.Now()
	dynamicThreatScore, err := dynamicAnalysis(exe)

	if err != nil {
		return errors.New("Not able to perform dynamic analysis : " + err.Error())
	}

	elapsed = time.Now().Sub(start)
	logger.Info(fmt.Sprintf("Dynamic Analysis done in %v", elapsed))

	fmt.Println("Dynamic score: ", dynamicThreatScore)

	if dynamicThreatScore >= 100 {
		logger.Danger("Threat score >= 100")
		malwareDetected(exe)
		return nil
	}

	if staticThreatScore+dynamicThreatScore >= 170 {
		logger.Danger("Additional score >= 170")
		malwareDetected(exe)
		return nil
	}

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

	var requestBody bytes.Buffer

	writer := multipart.NewWriter(&requestBody)

	fieldWriter, err := writer.CreateFormFile("file", exe.Filename)
	if err != nil {
		return 0, err
	}

	_, err = fieldWriter.Write(exe.Content)
	if err != nil {
		return 0, err
	}

	fieldWriter, err = writer.CreateFormField("unique")
	if err != nil {
		return 0, err
	}

	_, err = fieldWriter.Write([]byte("true"))
	if err != nil {
		return 0, err
	}

	writer.Close()

	request, err := http.NewRequest("POST", "http://localhost:8090/tasks/create/file", &requestBody)
	if err != nil {
		return 0, err
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	var jsonResponse map[string]interface{}
	var taskID int

	if resp.StatusCode == http.StatusOK {
		logger.Debug("Binary has been submitted to the Cuckoo Sandbox")

		if json.NewDecoder(resp.Body).Decode(&jsonResponse) != nil {
			return 0, err
		}

		taskID = int(jsonResponse["task_id"].(float64))

	} else if resp.StatusCode == http.StatusBadRequest {
		logger.Debug("Binary has already been analysed by the Cuckoo Sandbox")

		resp, err = http.Get("http://localhost:8090/files/view/sha256/" + exe.SHA256)
		if err != nil {
			return 0, err
		}

		if json.NewDecoder(resp.Body).Decode(&jsonResponse) != nil {
			return 0, nil
		}

		sample := jsonResponse["sample"].(map[string]interface{})
		logger.Debug(fmt.Sprintf("sample: %v", sample))
		taskID = int(sample["id"].(float64))
		resp.Body.Close()
	}

	logger.Debug(fmt.Sprintf("Cuckoo Task ID: %v", taskID))

	for {
		resp, err = http.Get(fmt.Sprintf("http://localhost:8090/tasks/report/%v", taskID))
		if err != nil {
			return 0, err
		}

		if resp.StatusCode == http.StatusOK {
			break
		}

		resp.Body.Close()

		logger.Debug("Waiting for the report...")
		time.Sleep(2 * time.Second)
	}

	logger.Debug(string("Report ready !"))

	if json.NewDecoder(resp.Body).Decode(&jsonResponse) != nil {
		return 0, nil
	}

	resp.Body.Close()

	if jsonResponse["behavior"] == nil {
		return 0, errors.New("no behavior analysis in the report")
	}

	behavior := jsonResponse["behavior"].(map[string]interface{})
	processes := behavior["processes"].([]interface{})

	for _, process := range processes {
		calls := process.(map[string]interface{})["calls"].([]interface{})
		syscalls := make([]int, 1)

		for _, call := range calls {
			syscallName := call.(map[string]interface{})["api"].(string)
			syscalls = append(syscalls, dynamic.Syscalls[syscallName])
		}

		modelScore, err := dynamic.ApplyModel(syscalls)

		if modelScore > 60 {
			return 100, err
		}
	}

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
