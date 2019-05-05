package scan

import (
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"path/filepath"
)

func FullScan() {
	fmt.Println("Full scan starting...")
	scanDirectory("/")
}

// The idea is to scan places where unprivileged users can write
func FastScan() {

	directoriesToScan := []string{
		//"/home",
		"/tmp/malwares",
		//"/opt",
	}

	logger.Info("Fast scan starting...")

	for _, directory := range directoriesToScan {
		scanDirectory(directory)
	}
}

func scanDirectory(directory string) {
	err := filepath.Walk(directory, func(path string, f os.FileInfo, err error) error {

		// Skip directories errors (such as permission denied)
		if f.IsDir() && err != nil {
			return filepath.SkipDir
		}

		// Analysing files
		if !f.IsDir() {
			//TODO : use goroutines here, but be careful not to start 100k analysis at the same time !
			_ = core.Analyse(path) // We don't care about errors in a multiple files scan
		}

		return err
	})

	if err != nil {
		panic(err)
	}
}
