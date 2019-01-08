package core

import (
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"gopkg.in/src-d/go-git.v4"
	"log"
	"os"
	"path/filepath"
)

func SyncDatabase() {
	logger.Info("Start syncing database...")

	databaseDir, err := filepath.Abs(filepath.Dir(os.Args[0]))

	if err != nil {
		log.Fatal(err.Error())
	}

	currentDatabase, err := git.PlainClone(databaseDir+"/files", false, &git.CloneOptions{
		URL:      "https://github.com/OctAVProject/OctAV-Files",
		Progress: nil,
	})

	if err == git.ErrRepositoryAlreadyExists {
		logger.Debug("Pulling latest changes from repository...")
		currentDatabase, err = git.PlainOpen(databaseDir)

		if err != nil {
			logger.Error("Not able to load git repository : " + err.Error())
			//TODO : force clone
			return
		}

		workTree, err := currentDatabase.Worktree()

		if err != nil {
			logger.Error("Not able to load git repository : " + err.Error())
			//TODO : force clone
			return
		}

		err = workTree.Pull(&git.PullOptions{RemoteName: "origin"})

		if err == git.NoErrAlreadyUpToDate {
			logger.Info("The database is already up to date.")
		} else if err != nil {
			logger.Error("Not able to pull changes : " + err.Error())
			//TODO : force clone ?
			return
		} else {
			logger.Info("The database has been updated.")
		}
	} else if err != nil {
		logger.Error("Not able to sync database : " + err.Error())
		return
	} else {
		logger.Info("Database retrieved successfully.")
	}

	ref, err := currentDatabase.Head()

	if err != nil {
		logger.Error(err.Error())
		return
	}

	logger.Debug("Latest commit : " + ref.Hash().String())
}
