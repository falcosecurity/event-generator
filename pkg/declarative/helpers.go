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

func OpenSyscall(filepath string, flags int, mode uint32) (int, error) {
	fd, err := unix.Open(filepath, flags, mode)
	if err != nil {
		return -1, fmt.Errorf("error opening file: %v", err)
	}
	return fd, nil
}

func OpenatSyscall(dirfd int, filepath string, flags int, mode uint32) (int, error) {
	fd, err := unix.Openat(dirfd, filepath, flags, mode)
	if err != nil {
		return -1, fmt.Errorf("error opening file: %v", err)
	}
	return fd, nil
}

func Openat2Syscall(dirfd int, filepath string, flags int, mode uint32, resolve uint64) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(flags),
		Mode:    uint64(mode),
		Resolve: resolve,
	}

	fd, err := unix.Openat2(dirfd, filepath, how)
	if err != nil {
		return -1, fmt.Errorf("error opening file: %v", err)
	}
	return fd, nil
}

func ExecveSyscall(exepath string, cmnd []string, envv []string) error {
	return unix.Exec(exepath, cmnd, envv)
}

func ConnectSyscall(sockfd int, socketAddr unix.Sockaddr) error {
	return unix.Connect(sockfd, socketAddr)
}

func SocketSyscall(domain int, socktype int, protocol int) (int, error) {
	fd, err := unix.Socket(domain, socktype, protocol)
	if err != nil {
		return -1, fmt.Errorf("error creating a socket: %v", err)
	}
	return fd, nil
}

func SymlinkSyscall(oldpath string, newpath string) error {
	return unix.Symlink(oldpath, newpath)
}

func LinkSyscall(oldpath string, newpath string) error {
	return unix.Link(oldpath, newpath)
}

func DupSyscall(oldfd int) (int, error) {
	newfd, err := unix.Dup(oldfd)
	if err != nil {
		return -1, err
	}
	return newfd, nil
}

func PtraceSyscall(pid int, signal int) error {
	return unix.PtraceSyscall(pid, signal)
}
