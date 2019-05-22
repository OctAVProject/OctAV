package daemon

import (
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/fsnotify/fsnotify"
	"log"
)

func Watch(directories []string) error {

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	defer watcher.Close()

	done := make(chan bool)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if /*event.Op & fsnotify.Write > 0 || */ event.Op&fsnotify.Create > 0 {
					logger.Info(fmt.Sprintf("Event %v", event))
					if err := core.Analyse(event.Name); err != nil {
						logger.Debug(err.Error())
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error(err.Error())
			}
		}
	}()

	for _, directory := range directories {

		logger.Info("Watching " + directory)

		if err = watcher.Add(directory); err != nil {
			log.Fatal(err)
		}
	}

	<-done

	return nil
}
