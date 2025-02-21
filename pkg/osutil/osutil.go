// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
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

package osutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// MkdirAll creates a directory at the provided path as well as any necessary parents, and returns the path of the first
// created directory along the path.  It returns an empty string if the provided path exists and points to a directory.
func MkdirAll(dirPath string) (string, error) {
	// Optimization: if there is a directory at the specified path, skip all the following operations.
	exist, err := dirExists(dirPath)
	if err != nil {
		return "", fmt.Errorf("error verifying path existence: %w", err)
	}

	if exist {
		return "", nil
	}

	firstNonExistingDirSubPath, err := findShortestNonExistingDirSubPath(dirPath)
	if err != nil {
		return "", fmt.Errorf("error retrieving first non-existing directory path: %w", err)
	}

	if err := os.MkdirAll(dirPath, 0o750); err != nil {
		return "", err
	}

	return firstNonExistingDirSubPath, nil
}

// dirExists returns true if the provided path exists and is a directory path.
func dirExists(dirPath string) (bool, error) {
	stat, err := os.Stat(dirPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}

		return false, nil
	}

	if !stat.IsDir() {
		return false, errNotADir
	}

	return true, nil
}

var errNotADir = fmt.Errorf("not a directory")

// findShortestNonExistingDirSubPath returns the shortest non-existing directory sub-path of the provided directory
// path. It returns an empty string if the provided path exists and points to a directory.
func findShortestNonExistingDirSubPath(dirPath string) (string, error) {
	pathSegments := splitPathSegments(dirPath)
	path := ""
	for _, pathSegment := range pathSegments {
		path = filepath.Join(path, pathSegment)
		exist, err := dirExists(path)
		if err != nil {
			return "", fmt.Errorf("error veryfing directory path %q existence: %w", path, err)
		}

		if !exist {
			return path, nil
		}
	}
	return "", nil
}

// splitPathSegments splits the provided path into multiple segments.
func splitPathSegments(path string) []string {
	dir, last := filepath.Split(path)
	if dir == "" {
		return []string{last}
	}

	if last == "" {
		return []string{dir}
	}

	return append(splitPathSegments(filepath.Clean(dir)), last)
}
