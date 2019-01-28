package static

import (
	"bufio"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"path/filepath"
)

func IsHashKnownToBeMalicious(exe *analysis.Executable) (bool, error) {
	logger.Info("Comparing MD5 hash signatures...")

	var md5HashesFiles []string

	err := filepath.Walk("files/md5_hashes/", func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return err
		}

		if !info.IsDir() {
			md5HashesFiles = append(md5HashesFiles, path)
		}

		return nil
	})

	if err != nil {
		return false, err
	}

	for _, filename := range md5HashesFiles {
		logger.Debug(fmt.Sprintf("Opening '%v' ...", filename))

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

		if scanner.Err() != nil {
			return false, scanner.Err()
		}
	}

	return false, nil
}

func IsSSDeepHashKnownToBeMalicious(exe *analysis.Executable) (bool, error) {
	logger.Info("Comparing SSDeep hash signatures...")

	filename := "files/hashes.ssdeep"

	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)

	if err != nil {
		return false, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		// TODO : compute distance instead of strict equality
		if scanner.Text() == exe.SSDeep {
			return true, nil
		}
	}

	// Check local database hash existence
	// If the database hasn't been built yet, suggest the user to do so

	//Select in signature table a row with exe.MD5 hash
	return false, scanner.Err()
}
