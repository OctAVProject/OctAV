package static

import (
	"bufio"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
)

func IsHashKnownToBeMalicious(exe *analysis.Executable) (bool, error) {
	logger.Info("Comparing MD5 hash signatures...")
	filename := "files/hashes.md5"

	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)

	if err != nil {
		return false, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if scanner.Text() == exe.MD5 {
			return true, nil
		}
	}

	// Check local database hash existence
	// If the database hasn't been built yet, suggest the user to do so

	//Select in signature table a row with exe.MD5 hash
	return false, scanner.Err()
}

func IsSSDeepHashKnownToBeMalicious(exe *analysis.Executable) (bool, error) {
	// https://github.com/ssdeep-project/ssdeep
	logger.Info("Comparing SSDeep hash signatures...")
	return false, nil
}
