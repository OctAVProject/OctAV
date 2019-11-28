package scan

import (
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/config"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
)

var sshConfig string = "/etc/ssh/sshd_config"

func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func FullConfigScan() error {
	logger.Header("config scan")

	if FileExists(sshConfig) {
		if err := config.AnalyseSSHConfig(sshConfig); err != nil {
			return err
		}
	}

	return nil
}
