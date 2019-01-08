package core

import (
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis/static"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"magicmime"
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

	threatScore := staticAnalysis(&exe)
	fmt.Println("Score: ", threatScore)

	// TODO : If static analysis is sure the binary is a threat, skip dynamic analysis

	threatScore = dynamicAnalysis(&exe)
	fmt.Println("Score: ", threatScore)
	return nil
}

func staticAnalysis(exe *analysis.Executable) uint {
	fmt.Println("\n_____STATIC__ANALYSIS_____")
	resKnownHashes := static.CheckKnownHashes(exe)
	resKnownSSDeep := static.CheckKnownSSDeep(exe)
	if resKnownHashes && resKnownSSDeep {
		return 3
	} else if resKnownSSDeep {
		return 2
	} else if resKnownHashes {
		return 1
	} else {
		return 0
	}
}

func dynamicAnalysis(exe *analysis.Executable) uint {
	fmt.Println("\n_____DYNAMIC_ANALYSIS_____")
	return 0
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
