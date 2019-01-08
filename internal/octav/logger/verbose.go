package logger

const (
	VERBOSE_WARNING = iota
	VERBOSE_INFO
	VERBOSE_DEBUG
)

var verboseLevel = VERBOSE_INFO

func SetVerboseLevel(level string) {

	if level == "DEBUG" {
		verboseLevel = VERBOSE_DEBUG
	} else if level == "INFO" {
		verboseLevel = VERBOSE_INFO
	} else if level == "WARNING" {
		verboseLevel = VERBOSE_WARNING
	}
}
