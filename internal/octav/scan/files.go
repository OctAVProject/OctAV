package scan

import (
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"path/filepath"
	"strings"
)

func FullScan() {
	fmt.Println("Full scan starting...")
	scanDirectory("/")
}

func FastScan() {

	directoriesToScan := []string{
		"/home",
		"/opt",
	}

	path := os.Getenv("PATH")

	for _, directory := range strings.Split(path, ":") {
		directoriesToScan = append(directoriesToScan, directory)
	}

	logger.Info("Fast scan starting...")

	for _, directory := range directoriesToScan {
		scanDirectory(directory)
	}
}

func scanDirectory(directory string) {

	analysis := core.Analysis{}

	err := filepath.Walk(directory, func(path string, f os.FileInfo, err error) error {

		// Skip directories errors (such as permission denied)
		if f.IsDir() && err != nil {
			return filepath.SkipDir
		}

		// Analysing files
		if !f.IsDir() {
			analysis.Files = append(analysis.Files, path)
		}

		return err
	})

	if err != nil {
		logger.Fatal("Directory scanning error : " + err.Error())
	}

	if err = analysis.Start(); err != nil {
		logger.Fatal("Directory scanning error : " + err.Error())
	}
}
