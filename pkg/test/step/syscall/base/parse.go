package base

import (
	"fmt"
	"strconv"
	"strings"
)

func parseFD(value string) (int, error) {
	fd, err := strconv.ParseInt(value, 10, 0)
	if err != nil {
		return 0, err
	}

	return int(fd), nil
}

func parseBufferLen(value string) (int, error) {
	bufferLen, err := strconv.ParseInt(value, 10, 0)
	if err != nil {
		return 0, err
	}

	if bufferLen < 0 {
		return 0, fmt.Errorf("value is negative")
	}

	return int(bufferLen), nil
}

func parseFilePath(value string) ([]byte, error) {
	if strings.IndexByte(value, 0) != -1 {
		return nil, fmt.Errorf("unexpected NULL byte")
	}

	filePath := make([]byte, len(value)+1)
	copy(filePath, value)
	return filePath, nil
}

func parseOpenFlags(value string) (int, error) {
	if flags, err := strconv.ParseInt(value, 10, 0); err == nil {
		return int(flags), nil
	}

	flags := 0
	for _, flag := range strings.Split(value, "|") {
		flagValue, ok := openFlags[flag]
		if !ok {
			return 0, fmt.Errorf("unknown flag %q", flag)
		}
		flags |= flagValue
	}

	return flags, nil
}

func parseOpenMode(value string) (int, error) {
	if flags, err := strconv.ParseInt(value, 10, 0); err == nil {
		return int(flags), nil
	}

	flags := 0
	for _, flag := range strings.Split(value, "|") {
		flagValue, ok := openModes[flag]
		if !ok {
			return 0, fmt.Errorf("unknown mode %q", flag)
		}
		flags |= flagValue
	}

	return flags, nil
}
