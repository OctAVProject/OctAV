package core

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/rakyll/magicmime"
	"io/ioutil"
)

var supportedMIME = []string{
	"application/x-executable",
	"application/x-sharedlib",
}

func Analyse(filename string) error {

	exe := analysis.Executable{Filename: filename}

	content, err := ioutil.ReadFile(filename)
	exe.Content = content

	if err != nil {
		return err
	}

	if len(exe.Content) == 0 {
		return errors.New("file is empty")
	}

	exe.MIME, err = getMIME(exe.Content)

	if err != nil {
		return err
	}

	exe.MD5, exe.SHA1, exe.SHA256 = getHashes(exe.Content)

	logger.Info("Analysing " + filename)
	logger.Debug(exe.String())

	threatScore, err := staticAnalysis(&exe)

	if err != nil {
		logger.Fatal("Not able to perform static analysis.")
	}

	fmt.Println("Score: ", threatScore)

	// TODO : If static analysis is sure the binary is a threat, skip dynamic analysis

	threatScore, err = dynamicAnalysis(&exe)

	if err != nil {
		logger.Fatal("Not able to perform dynamic analysis.")
	}

	fmt.Println("Score: ", threatScore)
	return nil
}

func staticAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("\n_____STATIC__ANALYSIS_____")
	hashIsKnown, err := static.IsHashKnownToBeMalicious(exe)

	if err != nil {
		logger.Error(err.Error())
		logger.Debug("Trying to fix the error by syncing the database.")
		err = SyncDatabase()

		if err != nil {
			return 0, err
		}

		hashIsKnown, err = static.IsHashKnownToBeMalicious(exe)

		if err != nil {
			return 0, err
		}
	}

	if hashIsKnown {
		malwareDetected(exe)
	}

	ssDeepIsKnown, err := static.IsSSDeepHashKnownToBeMalicious(exe)

	if err != nil {
		logger.Error(err.Error())
		logger.Debug("Trying to fix the error by syncing the database.")
		err = SyncDatabase()

		if err != nil {
			return 0, err
		}

		hashIsKnown, err = static.IsHashKnownToBeMalicious(exe)

		if err != nil {
			return 0, err
		}
	}

	var score uint = 0

	if ssDeepIsKnown {
		logger.Warning("SSDeep hash is known, potential malware ! Running further analysis...")
		score += 50
	}

	return score, nil
}

func dynamicAnalysis(exe *analysis.Executable) (uint, error) {
	fmt.Println("\n_____DYNAMIC_ANALYSIS_____")
	return 0, nil
}

func isMIMETypeSupported(MIME string) bool {
	for _, supported := range supportedMIME {
		if MIME == supported {
			return true
		}
	}

	return false
}

func getMIME(fileContent []byte) (string, error) {

	if err := magicmime.Open(magicmime.MAGIC_MIME_TYPE | magicmime.MAGIC_SYMLINK | magicmime.MAGIC_ERROR); err != nil {
		panic(err)
	}

	defer magicmime.Close()

	mimetype, err := magicmime.TypeByBuffer(fileContent)

	if err != nil {
		panic(err)
	}

	if !isMIMETypeSupported(mimetype) {
		return "", errors.New(fmt.Sprintf("MIME type '%s' is not supported\n", mimetype))
	}

	return mimetype, nil
}

func getHashes(fileContent []byte) (string, string, string) {

	m := md5.Sum(fileContent)
	s1 := sha1.Sum(fileContent)
	s256 := sha256.Sum256(fileContent)

	return hex.EncodeToString(m[:]), hex.EncodeToString(s1[:]), hex.EncodeToString(s256[:])
}

func malwareDetected(exe *analysis.Executable) {
	logger.Warning("Malware detected")
	//TODO : ask the user what to do
}
