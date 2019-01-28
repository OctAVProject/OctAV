package static

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/hillu/go-yara"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

var (
	// stuff that could be put in a config file
	yaraPath            = "files/yara/"
	pathToRulesIndex    = yaraPath + "index.yar" // TODO : remove
	idFile              = "MD5_index.id"
	pathToCompiledRules = "rulesSet.lst"
)

var namespaces = map[string]string{
	"packer":        "Packers_index.yar",
	"malware":       "malware_index.yar",
	"anti-debug/vm": "Antidebug_AntiVM_index.yar",
}

type YaraGrep struct {
	*yara.Rules
}

func (yaraMatcher *YaraGrep) GetAllMatchingRules(exe *analysis.Executable) (yara.MatchRules, error) {

	matches, err := yaraMatcher.ScanMem(exe.Content, 0, 0)
	if err != nil {
		return nil, err
	}

	return matches, nil
}

func NewYaraMatcher() (*YaraGrep, error) {

	var (
		err               error
		saveCompiledRules = false
		yaraMatcher       *YaraGrep
	)

	logger.Debug("Initializing the compiler...")

	if updated, errCheckUpdate := haveYaraBeenUpdated(); errCheckUpdate != nil {
		return nil, errCheckUpdate

	} else if updated {

		logger.Debug("Updating the compiled rules...")

		if yaraMatcher, err = buildRules(); err != nil {
			// TODO : load existing rules anyway ?
			return nil, err
		}

		saveCompiledRules = true

	} else {

		var rules *yara.Rules
		rules, err = yara.LoadRules(pathToCompiledRules)

		if err == nil {
			yaraMatcher = &YaraGrep{rules}

		} else {
			logger.Error("Failed to load compiled rules : " + err.Error())
			logger.Debug("Creating new compiled rules...")

			if yaraMatcher, err = buildRules(); err != nil {
				return nil, err
			}

			saveCompiledRules = true
		}
	}

	if saveCompiledRules {
		if err = yaraMatcher.Save(pathToCompiledRules); err != nil {
			logger.Error("Failed to save the rules set : " + err.Error())
			return nil, err
		}
	}

	logger.Info(fmt.Sprintf("%v yara rules loaded", len(yaraMatcher.GetRules())))
	return yaraMatcher, nil
}

func buildRules(blacklist ...string) (*YaraGrep, error) {

	compiler, err := yara.NewCompiler()
	if err != nil {
		logger.Error("Failed to initialize YARA compiler : " + err.Error())
		return nil, err
	}

	defer compiler.Destroy()

	for namespace, filename := range namespaces {
		stringRules := parseIncludeFile(yaraPath + filename)

		for _, includeStatment := range stringRules {

			statementIsBlacklisted := false

			for _, blacklistedStatement := range blacklist {
				if includeStatment == blacklistedStatement {
					statementIsBlacklisted = true
					break
				}
			}

			if statementIsBlacklisted {
				logger.Debug("Skipping blacklisted statement : " + includeStatment)
				continue
			}

			if err := compiler.AddString(includeStatment, namespace); err != nil {
				logger.Warning(fmt.Sprintf("Failed to load a rule in %v : %v", includeStatment, err.Error()))
				logger.Info("Recreating a new compiler ignoring that statement...")
				return buildRules(append(blacklist, includeStatment)...)
			}
		}
	}

	var rules *yara.Rules
	rules, err = compiler.GetRules()

	// We convert the Rules struct to our YaraGrep in order to be able to call custom methods on it
	return &YaraGrep{rules}, err
}

func hashFileMD5(filePath string) (string, error) {
	//function that could be put elsewhere
	var returnedMD5String string
	var deferr error

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	defer func() {
		if err := file.Close(); err != nil {
			deferr = err
		}
	}()
	if deferr != nil {
		return "", deferr
	}

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashInBytes := hash.Sum(nil)[:16]
	returnedMD5String = hex.EncodeToString(hashInBytes)

	return returnedMD5String, nil

}

func createIDFile(pathToIdFile string, md5 string) error {

	byteMD5 := []byte(md5)
	err := ioutil.WriteFile(pathToIdFile, byteMD5, 0644)
	if err != nil {
		logger.Error("Can't create the ID file : " + err.Error())

		return err
	}

	return nil
}

// TODO : use repo's HEAD instead ?
func haveYaraBeenUpdated() (bool, error) {

	var (
		res                  bool
		storedIndexMD5String string
		deferr               error
	)

	currentIndexMD5String, _ := hashFileMD5(pathToRulesIndex)

	if _, err := os.Stat(idFile); err == nil {
		logger.Debug("Checking if rules have been updated. ")

		file, err := os.Open(idFile)
		if err != nil {
			logger.Error("Can't open the ID file : " + err.Error())

			return false, err // todo : is there a cleaner way to do it ?
		}

		defer func() {
			if err := file.Close(); err != nil {
				deferr = err
			}
		}()
		if deferr != nil {
			return false, deferr
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			storedIndexMD5String += scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			logger.Error("Error occurred when reading the ID file : " + err.Error())

			return false, err
		}

		if currentIndexMD5String == storedIndexMD5String {
			logger.Info("YARA rules have not been updated. ")
			res = false
		} else {
			logger.Info("YARA rules have been updated. ")
			err = createIDFile(idFile, currentIndexMD5String)
			if err != nil {
				return false, deferr
			}

			res = true
		}

	} else {
		logger.Info("Can't find the ID file : creating it.")

		err = createIDFile(idFile, currentIndexMD5String)
		if err != nil {
			return false, deferr
		}

		res = true
	}

	return res, nil
}

func parseIncludeFile(path string) []string {
	var includeStatements []string

	file, err := os.Open(path)
	if err != nil {
		logger.Error("Error occurred when opening the index rule file : " + err.Error())
		return nil
	}

	defer file.Close() // No need to handle error, file in read only
	scanner := bufio.NewScanner(file)

	var validLine = regexp.MustCompile(`^include ".*"`)
	yaraIncludePatcher := strings.NewReplacer("./", yaraPath)

	for scanner.Scan() {
		line := scanner.Text()
		if validLine.MatchString(line) {
			line = yaraIncludePatcher.Replace(line)
			includeStatements = append(includeStatements, line)
		}
	}

	return includeStatements
}
