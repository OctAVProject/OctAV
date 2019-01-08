package analysis

import "fmt"

type Executable struct {
	Filename string
	Content  []byte
	MIME     string
	MD5      string
	SHA1     string
	SHA256   string
}

func (exe Executable) String() string {
	return fmt.Sprintf(	"File name:\t%s\n" +
						"File size:\t%d bytes\n" +
						"MIME Type:\t%s\n" +
						"MD5:\t\t%s\n" +
						"SHA1:\t\t%s\n" +
						"SHA256:\t\t%s\n",
						exe.Filename, len(exe.Content), exe.MIME,
						exe.MD5, exe.SHA1, exe.SHA256)
}

