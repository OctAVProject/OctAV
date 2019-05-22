package logger

import (
	"fmt"
	"strings"
	"time"
)

const (
	HeaderColor  = "\u001b[45;1m"
	InfoColor    = "\033[1;34m"
	WarningColor = "\033[1;33m"
	ErrorColor   = "\033[1;31m"
	DebugColor   = "\033[0;36m"
	ResetColor   = "\033[0m"
)

func Debug(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[DEBUG]%v [%v] %v\n", DebugColor, getCurrentTime(), ResetColor, msg)
	}
}

func Info(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[INFO]%v [%v] %v\n", InfoColor, getCurrentTime(), ResetColor, msg)
	} else if verboseLevel >= VERBOSE_INFO {
		fmt.Printf("%v[INFO]%v %v\n", InfoColor, ResetColor, msg)
	}
}

func Header(title string) {
	fmt.Printf("\n%v[  %v  ]%v\n", HeaderColor, strings.ToUpper(title), ResetColor)
}

func Warning(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[WARN]%v [%v] %v\n", WarningColor, getCurrentTime(), ResetColor, msg)
	} else if verboseLevel >= VERBOSE_WARNING {
		fmt.Printf("%v[WARN]%v %v\n", WarningColor, ResetColor, msg)
	}
}

func Error(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[ERROR] [%v] %v%v\n", ErrorColor, getCurrentTime(), msg, ResetColor)
	} else {
		fmt.Printf("%v[ERROR] %v%v\n", ErrorColor, msg, ResetColor)
	}
}

func Danger(msg string) {
	if verboseLevel == VERBOSE_DEBUG {
		fmt.Printf("%v[DANGER] [%v] %v%v\n", ErrorColor, getCurrentTime(), msg, ResetColor)
	} else {
		fmt.Printf("%v[DANGER] %v%v\n", ErrorColor, msg, ResetColor)
	}
}

func Fatal(msg string) {
	panic(fmt.Sprintf("%v[FATAL] [%v] %v%v", ErrorColor, getCurrentTime(), msg, ResetColor))
}

func getCurrentTime() string {
	return time.Now().Format("15:04:05")
}
