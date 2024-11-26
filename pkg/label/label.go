// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package label

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	testIndexKey     = "testIndex"
	procIndexKey     = "procIndex"
	isContainerKey   = "isContainer"
	imageNameKey     = "imageName"
	containerNameKey = "containerName"
)

// Set stores values for the supported labels.
type Set struct {
	TestIndex     int
	ProcIndex     int
	IsContainer   bool
	ImageName     string
	ContainerName string
}

// Write writes the set to the provided writer.
func (s *Set) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s=%v,%s=%v,%s=%v,%s=%v,%s=%v",
		testIndexKey, s.TestIndex,
		procIndexKey, s.ProcIndex,
		isContainerKey, s.IsContainer,
		imageNameKey, s.ImageName,
		containerNameKey, s.ContainerName)
	return err
}

// Clone creates and returns a clone of the set.
func (s *Set) Clone() *Set {
	set := &Set{
		TestIndex:     s.TestIndex,
		ProcIndex:     s.ProcIndex,
		IsContainer:   s.IsContainer,
		ImageName:     s.ImageName,
		ContainerName: s.ContainerName,
	}
	return set
}

// ParseSet parses the provided labels and returns the parsed set. If an empty string is provided, the function returns
// nil.
func ParseSet(labels string) (*Set, error) {
	if labels == "" {
		return nil, nil
	}

	set := &Set{}
	for _, label := range strings.Split(labels, ",") {
		parts := strings.Split(label, "=")
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		switch key {
		case testIndexKey:
			testIndex, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing testIndex: %w", err)
			}

			set.TestIndex = testIndex
		case procIndexKey:
			testIndex, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing procIndex: %w", err)
			}

			set.ProcIndex = testIndex
		case isContainerKey:
			isContainer, err := strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing isContainer: %w", err)
			}

			set.IsContainer = isContainer
		case imageNameKey:
			set.ImageName = value
		case containerNameKey:
			set.ContainerName = value
		default:
			return nil, fmt.Errorf("unknown label %q", key)
		}
	}

	return set, nil
}
