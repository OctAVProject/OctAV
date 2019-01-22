package static

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/hillu/go-yara"
	"io"
	"io/ioutil"
	"os"
	"regexp"
)

/*
	How to make this stuff work ?
	=============================

	1. Install yara on your machine
	2. go get github.com/hillu/go-yara
	3. go install github.com/hillu/go-yara
	4. If it's not already the case, create a folder dedicated to the "dependency files"
	4. Clone the yara rules repo in this folder : git clone https://github.com/Yara-Rules/rules
	5. Patch the index_gen.sh script (ask for the patch) :
		- patch path/of/yararules/repo/index_gen.sh path/to/the/patch/index_gen.patch
	5. Launch the index_gen.sh script (/!\ from the yara repo)
	6. Adapt the below vars

	How to use it ?
	===============

		var pathToFile = "/path/to/file"

		scanner, err := CreateYaraScanner()
		if err != nil{
			logger.Error("Error occurs when setting up the compiler.")
			logger.Info("Aborting the analysis")
		}else{
			matches, err := Yaranalysis(pathToFile, scanner)
			if err != nil{
				logger.Error("[ERROR] Error occurs when processing analysis on %s", pathToFile)
				logger.Info("Skipping %s", pathToFile)
			}else{
				PrintMatches(matches)
			}
		}

*/

var (
	// stuff that could be put in a config file
	pathToRulesIndex    = "/path/to/the/folder/yararepo/index.yar"
	idFile              = "/path/to/the/folder/MD5_index.id"
	pathToCompiledRules = "/path/to/the/folder/rulesSet.lst"
)

func hashFileMD5(filePath string) (string, error) {
	//function that could be put elsewhere
	var returnedMD5String string
	var deferr error

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("ok")
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

func haveYaraBeenUpdated() (bool, error) {

	var (
		res                  bool
		storedIndexMD5String string
		deferr               error
	)

	currentIndexMD5String, _ := hashFileMD5(pathToRulesIndex)

	if _, err := os.Stat(idFile); err == nil {
		logger.Info("Checking if rules have been updated. ")

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
			logger.Info("Rules have not been updated. ")
			res = false
		} else {
			logger.Info("Rules have been updated. ")
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
	var res []string

	file, err := os.Open(path)
	if err != nil {
		logger.Error("Error occurred when opening the index rule file : " + err.Error())

		return nil
	}

	var deferr error
	defer func() {
		if err := file.Close(); err != nil {
			deferr = err
		}
	}()
	if deferr != nil {
		return nil
	}

	scanner := bufio.NewScanner(file)

	var validLine = regexp.MustCompile(`^include "`) //todo : enhance the regexp

	for scanner.Scan() {
		line := scanner.Text()
		if validLine.MatchString(line) {
			res = append(res, line)
		}
	}

	return res
}

func createTheCompiler() (*yara.Compiler, error) {

	validatedCompiler, err := yara.NewCompiler()
	if err != nil {
		logger.Error("Failed to initialize YARA compiler : " + err.Error())

		return nil, err
	}

	priorCompiler, priorErr := yara.NewCompiler()
	if priorErr != nil {
		logger.Error("Failed to initialize YARA prior compiler : " + err.Error())

		return nil, priorErr
	}

	stringRules := parseIncludeFile(pathToRulesIndex) // allows us to avoid a general error and to debug file by file

	logger.Info(string(len(stringRules)) + " files to load !")

	for _, includeStatment := range stringRules {

		priorErr = priorCompiler.AddString(includeStatment, ".")

		if priorErr == nil {
			err = validatedCompiler.AddString(includeStatment, ".")
			if err != nil {
				logger.Error("cf. comments --> " + err.Error()) // we need to find a solution for priorCompiler to have the rules in validatedCompiler to avoid this case

				return nil, err
			}

		} else {
			logger.Warning("Failded to load a rule in " + includeStatment + " : " + err.Error())

			priorCompiler, priorErr = yara.NewCompiler()
			if priorErr != nil {
				logger.Error("Failed to re-initialize YARA callback compiler :" + priorErr.Error())

				return nil, priorErr
			}

			//todo : put priorCompiler in validatedCompiler --> copy of pointer content to avoid duplicate

		}
	}

	/* // todo : if we find a solution to copy the content of the compiler, the following algorithm would be better
	validatedCompiler, err := yara.NewCompiler()
	if err != nil {
		log.Printf("[ERROR] Failed to initialize YARA compiler: %s", err)
		return nil, err
	}

	bufferCompiler := validatedCompiler // replace by the copy function


	stringRules := parseIncludeFile(pathToRulesIndex)

	for _, includeStatment := range stringRules {

		err = validatedCompiler.AddString(includeStatment, ".")
		if err != nil {
			//log.Printf("Failded to load a rule : %s ", err)
			validatedCompiler = bufferCompiler // replace by the copy function
		}else{
			//log.Println("OK")
			bufferCompiler = validatedCompiler // replace by the copy function
		}
	}*/

	return validatedCompiler, nil
}

func CreateYaraScanner() (*yara.Rules, error) {
	// todo : probably a few more cases to manage
	var (
		r                *yara.Rules
		err              error
		c                *yara.Compiler
		thereIsACompiler = false
	)

	logger.Info("Initiating the compiler.")

	if updated, errCheckUpdate := haveYaraBeenUpdated(); updated && errCheckUpdate == nil {

		logger.Info("Creating the updated compiler.")

		c, err = createTheCompiler()
		if err != nil {
			return nil, err
		}

		logger.Info("Extracting the compiled rules.")

		r, err = c.GetRules()
		if err != nil {
			logger.Error("Failed to compile rules : " + err.Error())

			return nil, err
		}

	} else if !updated && errCheckUpdate == nil {
		var compilerFile = pathToCompiledRules

		logger.Info("Checking if a compiler exists.")
		if _, err := os.Stat(compilerFile); err == nil {
			logger.Info("Found a compiler.")
			logger.Info("Loading the compiler.")

			r, err = yara.LoadRules(compilerFile)
			if err != nil {
				logger.Error("Failed to load compiled rules : " + err.Error())

				return nil, err

			} else {
				thereIsACompiler = true
			}

		} else {
			logger.Info("Can't find a compiler")
			logger.Info("Creating the compiler.")

			c, err = createTheCompiler()
			if err != nil {
				return nil, err
			}

			logger.Info("Extracting the compiled rules.")
			r, err = c.GetRules()
			if err != nil {
				logger.Error("Failed to compile rules : " + err.Error())

				return nil, err
			}
		}
	} else {
		return nil, errCheckUpdate
	}

	if !thereIsACompiler {
		err = r.Save(pathToCompiledRules)
		if err != nil {
			logger.Error("Failed to save the rules set : " + err.Error())

			return nil, err
		}
	}

	return r, nil
}

func PrintMatches(m []yara.MatchRule) {
	if len(m) <= 0 {
		logger.Info("No matches.")
	} else {
		for _, match := range m {
			logger.Info("[" + match.Namespace + "]" + " is matching with " + match.Rule)
		}
	}
}

func Yaranalysis(pathToFile string, yaraScanner *yara.Rules) (yara.MatchRules, error) {

	logger.Info("Scanning file %s " + pathToFile)
	m, err := yaraScanner.ScanFile(pathToFile, 0, 0)
	if err != nil {
		logger.Error("Failed to scan file(s) :" + err.Error())
		return nil, err
	}

	err = yara.Finalize()
	if err != nil {
		return nil, err
	}

	return m, nil
}
