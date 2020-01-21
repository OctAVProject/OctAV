package gui

import (
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/jcmuller/gozenity"
	"github.com/zserge/lorca"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
)

var guiMutex sync.Mutex
var currentAnalysis *core.Analysis

func GetFilesBeingAnalysed() []string {
	if currentAnalysis != nil {
		return currentAnalysis.Files
	} else {
		return []string{} // empty array
	}
}

func ChooseFiles() []string {
	files, _ := gozenity.FileSelection("Choose files or directories to analyse", nil)
	return files
}

func LaunchAnalysis(files []string) {
	guiMutex.Lock()

	if currentAnalysis == nil || !currentAnalysis.IsRunning {
		currentAnalysis = &core.Analysis{Files: files}
		guiMutex.Unlock()

		if err := currentAnalysis.Start(); err != nil {
			currentAnalysis.AddError(err.Error())
		}
	} else {
		currentAnalysis.AddError("An analysis is already ongoing !")
		guiMutex.Unlock()
	}
}

func GetDetectedMalwares() []analysis.Executable {
	var malwares []analysis.Executable

	for _, malware := range core.DetectedMalwares {
		malwares = append(malwares, *malware)
	}

	return malwares
}

func RemoveMalware(filepath string) {
	var newMalwareArray []*analysis.Executable

	for _, malware := range core.DetectedMalwares {
		if malware.Filename != filepath {
			newMalwareArray = append(newMalwareArray, malware)
		}
	}

	core.DetectedMalwares = newMalwareArray
	logger.Info(filepath + " deleted !")
}

func IsAnalysisRunning() bool {
	if currentAnalysis != nil {
		return currentAnalysis.IsRunning
	} else {
		return false
	}
}

func GetLogs() []core.LogEntry {
	if currentAnalysis != nil {
		return currentAnalysis.Logs
	} else {
		return []core.LogEntry{}
	}
}

func GetProgress() float64 {
	guiMutex.Lock()
	defer guiMutex.Unlock()

	if currentAnalysis != nil {
		return currentAnalysis.Progress
	} else {
		return 0.
	}
}

func CreateGUIBindings() error {
	args := []string{"--class=Lorca"}

	ui, err := lorca.New("", "", 1080, 600, args...)
	if err != nil {
		return err
	}

	defer ui.Close()

	err = ui.Bind("start", func() {

	})
	if err != nil {
		return err
	}

	// Create and bind Go object to the UI

	if err = ui.Bind("launchAnalysis", LaunchAnalysis); err != nil {
		return err
	}

	if err = ui.Bind("getLogs", GetLogs); err != nil {
		return err
	}

	if err = ui.Bind("isAnalysisRunning", IsAnalysisRunning); err != nil {
		return err
	}

	if err = ui.Bind("openFileChooser", ChooseFiles); err != nil {
		return err
	}

	if err = ui.Bind("getFilesBeingAnalysed", GetFilesBeingAnalysed); err != nil {
		return err
	}

	if err = ui.Bind("getProgress", GetProgress); err != nil {
		return err
	}

	if err = ui.Bind("getDetectedMalwares", GetDetectedMalwares); err != nil {
		return err
	}

	if err = ui.Bind("removeMalware", RemoveMalware); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	defer ln.Close()

	go http.Serve(ln, http.FileServer(FS))
	if err = ui.Load(fmt.Sprintf("http://%s", ln.Addr())); err != nil {
		return err
	}

	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)

	select {
	case <-sigc:
	case <-ui.Done():
	}

	return nil
}
