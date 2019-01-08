package logger

const (
	VERBOSE_WARNING = iota
	VERBOSE_INFO
	VERBOSE_DEBUG
)

var verboseLevel = VERBOSE_INFO

func SetVerboseLevel(level int) {

	if level > VERBOSE_DEBUG {
		level = VERBOSE_DEBUG
	}

	verboseLevel = level
}

func GetVerboseLevel() int {
	return verboseLevel
}