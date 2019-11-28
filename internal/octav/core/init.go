package core

import (
	"errors"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/dynamic"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/coreos/go-systemd/dbus"
	"github.com/hillu/go-yara"
)

var yaraGrep *static.YaraGrep
var DaemonMode = false

// Initialize tools that need to stay available over multiple analysis (Ex: it doesn't make sense to initialize YARA rules every time a new file is being analyzed)
func Initialize(daemonMode bool) error {
	var err error

	if yaraGrep, err = static.NewYaraMatcher(); err != nil {
		return err
	}

	DaemonMode = daemonMode

	if isUp, err := dynamic.IsSandBoxUp(); !isUp {

		if err != nil {
			if DaemonMode { // In daemon mode, OctAV has root privileges
				logger.Info("Docker daemon down, starting it...")
				conn, err := dbus.NewSystemdConnection()
				if err != nil {
					return err
				}

				defer conn.Close()

				_, err = conn.StartUnit("docker.service", "replace", nil)
				if err != nil {
					return err
				}
			} else { // Command line mode
				return errors.New("the docker daemon is down, run 'sudo systemctl start docker'")
			}
		}

		logger.Info("The sandbox is down, starting it...")
		if err := dynamic.StartSandBox(); err != nil {
			return err
		}
	}

	return nil
}

func Stop() error {
	if err := yara.Finalize(); err != nil {
		return err
	}

	return nil
}
