package daemon

import (
	"github.com/OctAVProject/OctAV/internal/octav/core"
	"os"
	"strings"
)

func Manage(command string) error {

	var (
		err                  error
		directories_to_watch []string
	)

	if err = core.Initialize(); err != nil {
		return err
	}

	home := os.Getenv("HOME")
	path := os.Getenv("PATH")

	directories_to_watch = strings.Split(path, ":")
	directories_to_watch = append(directories_to_watch, home+"/Downloads")

	if err = Watch(directories_to_watch); err != nil {
		return err
	}

	if err = core.Stop(); err != nil {
		return err
	}

	return nil
}
