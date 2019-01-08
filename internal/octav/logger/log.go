package logger

import (
	"fmt"
	"os"
)

// TODO : colors, file output

func Debug(msg string) {
	fmt.Printf("[@] %v\n", msg)
}

func Info(msg string) {
	if verboseLevel >= VERBOSE_INFO {
		fmt.Printf("[+] %v\n", msg)
	}
}

func Warning(msg string) {
	if verboseLevel >= VERBOSE_WARNING {
		fmt.Printf("[!] %v\n", msg)
	}
}

func Error(msg string) {
	fmt.Printf("[x] %v\n", msg)
}

func Fatal(msg string) {
	Error(msg)
	os.Exit(1)
}