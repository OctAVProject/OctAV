package static

import (
	"bufio"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"path/filepath"
	"unsafe"
)

// #cgo LDFLAGS: -lfuzzy
// #include <fuzzy.h>
// #include <stdlib.h>
import "C"

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
		//logger.Debug(fmt.Sprintf("Opening '%v' ...", filename))

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

func GetHighestSSDeepDistance(exe *analysis.Executable) (int, error) {
	logger.Info("Comparing SSDeep hash signatures...")

	if len(exe.Content) < 4096 {
		logger.Warning("File is too small to use SSDeep")
		return 0, nil
	}

	filename := "files/ssdeep_hashes/ssdeep.txt"

	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)

	if err != nil {
		return 0, err
	}

	defer file.Close()

	cSSDeep := C.CString(exe.SSDeep)

	defer func() {
		C.free(unsafe.Pointer(cSSDeep))
	}()

	scanner := bufio.NewScanner(file)
	highestSSDeepDistance := 0

	for scanner.Scan() {
		cCurrentSSDeep := C.CString(scanner.Text())

		distance := int(C.fuzzy_compare(cCurrentSSDeep, cSSDeep))

		if highestSSDeepDistance < distance {
			highestSSDeepDistance = distance
		}
	}

	return highestSSDeepDistance, scanner.Err()
}
