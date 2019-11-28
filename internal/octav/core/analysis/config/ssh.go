package config

import (
	"bufio"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"os"
	"strconv"
	"strings"
)

// Initialize with default values
var sshConfig = map[string]interface{}{
	"Port":                 22,
	"PermitRootLogin":      "prohibit-password",
	"PermitEmptyPasswords": "no",
	"X11Forwarding":        "no",
	"AllowUsers":           nil,
}

func checkConfigLine(line string) error {

	fields := strings.Fields(line)

	if fields[0] == "Port" {
		portAsInt, err := strconv.Atoi(fields[1])
		if err != nil {
			return err
		}

		sshConfig["Port"] = portAsInt
	} else if fields[0] == "PermitRootLogin" {
		sshConfig["PermitRootLogin"] = fields[1]
	} else if fields[0] == "PermitEmptyPasswords" {
		sshConfig["PermitEmptyPasswords"] = fields[1]
	} else if fields[0] == "X11Forwarding" {
		sshConfig["X11Forwarding"] = fields[1]
	} else if fields[0] == "AllowUsers" {
		sshConfig["AllowUsers"] = fields[1]
	}

	return nil
}

func checkSecurityIssues() {
	if sshConfig["Port"] == 22 {
		logger.Warning("The SSH service uses the default listening port (22), to prevent bots from detecting it easily, it's recommended to change it")
	}

	if sshConfig["PermitRootLogin"] != "no" {
		logger.Warning("You shouldn't allow root to connect through SSH (PermitRootLogin no)")
	}

	if sshConfig["PermitEmptyPasswords"] == "yes" {
		logger.Danger("PermitEmptyPasswords should be set to 'no'")
	}

	if sshConfig["X11Forwarding"] != "no" {
		logger.Warning("If you're not using it, you should disable the X11 forwarding (X11Forwarding no)")
	}

	if sshConfig["AllowUsers"] == nil {
		logger.Warning("It's recommended to specify the users that should be able to connect using the AllowUsers statement")
	}

}

func AnalyseSSHConfig(filename string) error {

	f, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if len(line) > 0 && line[0] != '#' {
			if err = checkConfigLine(line); err != nil {
				return err
			}
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}

	checkSecurityIssues()

	return nil
}
