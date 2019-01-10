package core

import (
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
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
		logger.Fatal("Not able to perform static analysis.")
	}

	fmt.Println("Score: ", threatScore)

	// TODO : If static analysis is sure the binary is a threat, skip dynamic analysis

	threatScore, err = dynamicAnalysis(exe)

	if err != nil {
		logger.Fatal("Not able to perform dynamic analysis.")
	}

	fmt.Println("Score: ", threatScore)
	return nil
}

func staticAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("_____STATIC__ANALYSIS_____")
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

	var score uint = 0

	if ssDeepIsKnown {
		logger.Warning("SSDeep hash is known, potential malware ! Running further analysis...")
		score += 50
	}

	return score, nil
}

func dynamicAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("\n_____DYNAMIC_ANALYSIS_____")
	return 0, nil
}

func malwareDetected(exe *analysis.Executable) {
	logger.Warning("Malware detected")
	//TODO : ask the user what to do
}
