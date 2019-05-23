package static

import (
	"bufio"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"regexp"
)

func MaliciousIPFound(exeContent []byte) (bool, error) {
	//TODO : Manager must clean the file first
	return false, nil
}

func MaliciousDomainFound(exeContent []byte) (bool, error) {

	domainRegex := regexp.MustCompile(`([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}`)
	domains := domainRegex.FindAll(exeContent, -1)

	if len(domains) == 0 {
		return false, nil
	}

	for _, domain := range domains {
		logger.Debug(fmt.Sprintf("Found '%v' in binary", string(domain)))
	}

	file, err := os.Open("files/justdomains")
	if err != nil {
		logger.Error("Error occurred when opening 'justdomains' : " + err.Error())
		return false, err
	}

	defer file.Close() // No need to handle error, file in read only

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		domainInFile := scanner.Text()

		for _, domainFoundInExe := range domains {
			domainFoundInExe := string(domainFoundInExe)
			if domainInFile == domainFoundInExe {
				logger.Danger("Malicious domain found.")
				logger.Debug(domainFoundInExe)
				return true, nil
			}
		}
	}

	return false, nil
}
