package logger

import (
	"fmt"
	"time"
)

const (
	InfoColor    = "\033[1;34m"
	WarningColor = "\033[1;33m"
	ErrorColor   = "\033[1;31m"
	DebugColor   = "\033[0;36m"
	ResetColor   = "\033[0m"
)

// TODO : file output, print time only in file

func Debug(msg string) {
	fmt.Printf("%v[DEBUG] [%v] %v%v\n", DebugColor, getCurrentTime(), msg, ResetColor)
}

func Info(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[INFO] [%v] %v%v\n", InfoColor, getCurrentTime(), msg, ResetColor)
	} else if verboseLevel >= VERBOSE_INFO {
		fmt.Printf("%v[INFO] %v%v\n", InfoColor, msg, ResetColor)
	}
}

func Warning(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[WARNING] [%v] %v%v\n", WarningColor, getCurrentTime(), msg, ResetColor)
	} else if verboseLevel >= VERBOSE_WARNING {
		fmt.Printf("%v[WARNING] %v%v\n", WarningColor, msg, ResetColor)
	}
}

func Error(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[ERROR] [%v] %v%v\n", ErrorColor, getCurrentTime(), msg, ResetColor)
	} else {
		fmt.Printf("%v[ERROR] %v%v\n", ErrorColor, msg, ResetColor)
	}
}

func Fatal(msg string) {
	panic(fmt.Sprintf("%v[FATAL] [%v] %v%v", ErrorColor, getCurrentTime(), msg, ResetColor))
}

func getCurrentTime() string {
	return time.Now().Format("15:04:05")
}
