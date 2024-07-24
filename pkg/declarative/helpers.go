// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package declarative

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// It creates a tar reader for the file in given path.
func CreateTarReader(filePath string) (io.Reader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("error getting file info: %v", err)
	}

	// Create a tar archive in memory
	tarBuffer := new(bytes.Buffer)
	tw := tar.NewWriter(tarBuffer)
	defer tw.Close()

	header := &tar.Header{
		Name: fileInfo.Name(),
		Mode: 0755,
		Size: fileInfo.Size(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return nil, fmt.Errorf("error writing tar header: %v", err)
	}

	if _, err := io.Copy(tw, file); err != nil {
		return nil, fmt.Errorf("error copying file to tar writer: %v", err)
	}

	return tarBuffer, nil
}

func WriteSyscall(filepath string, content string) error {
	// Open the file using unix.Open syscall
	fd, err := unix.Open(filepath, unix.O_WRONLY|unix.O_CREAT, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer unix.Close(fd)

	// Write to the file using unix.Write
	_, err = unix.Write(fd, []byte(content))
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}
	return nil
}
