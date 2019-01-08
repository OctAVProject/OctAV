package static

import "github.com/OctAVProject/OctAV/internal/octav/core/analysis"

func CheckKnownHashes(exe *analysis.Executable) bool {
	// Check local database hash existence
	// If the database hasn't been built yet, suggest the user to do so

	//Select in signature table a row with exe.MD5 hash
	return true
}

func CheckKnownSSDeep(exe *analysis.Executable) bool {
	// https://github.com/ssdeep-project/ssdeep
	return true
}
