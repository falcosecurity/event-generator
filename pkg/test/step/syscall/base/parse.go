package base

import (
	"fmt"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
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

func parseOpenHow(value string) (*unix.OpenHow, error) {
	dec := yaml.NewDecoder(strings.NewReader(value))
	// Force the decoding to fail if the YAML document contains unknown fields
	dec.KnownFields(true)
	var openHowView struct {
		Flags   string `yaml:"flags"`
		Mode    string `yaml:"mode"`
		Resolve string `yaml:"resolve"`
	}
	if err := dec.Decode(&openHowView); err != nil {
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	openHow := &unix.OpenHow{}
	if len(openHowView.Flags) != 0 {
		flags, err := parseOpenFlags(openHowView.Flags)
		if err != nil {
			return nil, fmt.Errorf("error parsing flags: %v", err)
		}
		openHow.Flags = uint64(flags)
	}

	if len(openHowView.Mode) != 0 {
		mode, err := parseOpenMode(openHowView.Mode)
		if err != nil {
			return nil, fmt.Errorf("error parsing mode: %v", err)
		}
		openHow.Mode = uint64(mode)
	}

	if len(openHowView.Resolve) != 0 {
		resolve, err := parseOpenHowResolve(openHowView.Resolve)
		if err != nil {
			return nil, fmt.Errorf("error parsing resolve: %v", err)
		}
		openHow.Mode = uint64(resolve)
	}

	return openHow, nil
}

func parseOpenHowResolve(value string) (int, error) {
	if flags, err := strconv.ParseInt(value, 10, 0); err == nil {
		return int(flags), nil
	}

	flags := 0
	for _, flag := range strings.Split(value, "|") {
		flagValue, ok := openHowResolveFlags[flag]
		if !ok {
			return 0, fmt.Errorf("unknown flag %q", flag)
		}
		flags |= flagValue
	}

	return flags, nil
}

func parseLinkAtFlags(value string) (int, error) {
	if flags, err := strconv.ParseInt(value, 10, 0); err == nil {
		return int(flags), nil
	}

	flags := 0
	for _, flag := range strings.Split(value, "|") {
		flagValue, ok := linkAtFlags[flag]
		if !ok {
			return 0, fmt.Errorf("unknown flag %q", flag)
		}
		flags |= flagValue
	}

	return flags, nil
}
