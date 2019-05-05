package analysis

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rakyll/magicmime"
	"io/ioutil"
	"unsafe"
)

// #cgo LDFLAGS: -lfuzzy
// #include <fuzzy.h>
// #include <stdlib.h>
import "C"

var supportedMIME = []string{
	"application/x-executable",
	"application/x-sharedlib",
}

type Executable struct {
	Filename string
	Content  []byte
	MIME     string
	MD5      string
	SHA1     string
	SHA256   string
	SSDeep   string
}

func (exe Executable) String() string {
	return fmt.Sprintf("File name:\t%s\n"+
		"File size:\t%d bytes\n"+
		"MIME Type:\t%s\n"+
		"MD5:\t\t%s\n"+
		"SHA1:\t\t%s\n"+
		"SHA256:\t\t%s\n"+
		"SSDeep:\t\t%s\n",
		exe.Filename, len(exe.Content), exe.MIME,
		exe.MD5, exe.SHA1, exe.SHA256, exe.SSDeep)
}

func LoadExecutable(filename string) (*Executable, error) {
	exe := Executable{Filename: filename}
	content, err := ioutil.ReadFile(filename)
	exe.Content = content

	if err != nil {
		return nil, err
	}

	if len(exe.Content) == 0 {
		return nil, errors.New("file is empty")
	}

	exe.MIME, err = getMIME(exe.Content)

	if err != nil {
		return nil, err
	}

	exe.MD5, exe.SHA1, exe.SHA256 = getHashes(exe.Content)

	cFilename := C.CString(exe.Filename)
	cBufferResult := C.malloc(C.FUZZY_MAX_RESULT)

	defer func() {
		C.free(unsafe.Pointer(cBufferResult))
		C.free(unsafe.Pointer(cFilename))
	}()

	if retCode := C.fuzzy_hash_filename(cFilename, (*C.char)(cBufferResult)); retCode != C.int(0) {
		return nil, errors.New("can't compute SSDeep hash")
	}

	exe.SSDeep = C.GoString((*C.char)(cBufferResult))
	return &exe, nil
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
