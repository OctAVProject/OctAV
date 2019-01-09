package logger

import (
	"fmt"
)

// TODO : colors, file output

func Debug(msg string) {
	fmt.Println("[@] " + msg)
}

func Info(msg string) {
	if verboseLevel >= VERBOSE_INFO {
		fmt.Println("[+] " + msg)
	}
}

func Warning(msg string) {
	if verboseLevel >= VERBOSE_WARNING {
		fmt.Println("[!] " + msg)
	}
}

func Error(msg string) {
	fmt.Println("[x] " + msg)
}

func Fatal(msg string) {
	panic("[FATAL] " + msg)
}
