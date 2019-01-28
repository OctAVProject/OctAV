package core

import (
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/hillu/go-yara"
)

var yaraGrep *static.YaraGrep

// Initialize tools that need to stay available over multiple analysis (Ex: it doesn't make sense to initialize YARA rules every time a new file is being analyzed)
func Initialize() error {
	var err error

	if yaraGrep, err = static.NewYaraMatcher(); err != nil {
		return err
	}

	return nil
}

func Stop() error {
	if err := yara.Finalize(); err != nil {
		return err
	}

	return nil
}
