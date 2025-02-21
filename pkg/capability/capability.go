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

package capability

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// SetFile sets the provided capabilities on the file at the provided path. The provided capabilities must be  encoded
// using the syntax specified in cap_from_text(3).
func SetFile(filePath, capabilities string) (err error) {
	caps, err := cap.FromText(capabilities)
	if err != nil {
		return fmt.Errorf("error parsing capabilities: %w", err)
	}

	file, err := os.Open(filePath) //nolint:gosec // Disable G304
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if e := file.Close(); e != nil {
			if err == nil {
				err = fmt.Errorf("error closing file after setting capabilities: %w", e)
			} else {
				err = fmt.Errorf("%w; error closing file: %w", err, e)
			}
		}
	}()

	return caps.SetFd(file)
}

// RunWithSecBitNoRootEnabled runs the provided function with the thread secure bit SECBIT_NOROOT enabled.
func RunWithSecBitNoRootEnabled(f func() error) error {
	runtime.LockOSThread()
	secureBits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("error retrieving thread secure bits: %w", err)
	}

	secureBitsPlusSecBitNoRoot := secureBits | int(cap.SecbitNoRoot)
	return runWithSecBits(f, secureBits, secureBitsPlusSecBitNoRoot)
}

// RunWithSecBitNoRootDisabled runs the provided function with the thread secure bit SECBIT_NOROOT disabled.
func RunWithSecBitNoRootDisabled(f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	secureBits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("error retrieving thread secure bits: %w", err)
	}

	secureBitsMinusSecBitNoRoot := secureBits & ^int(cap.SecbitNoRoot)
	return runWithSecBits(f, secureBits, secureBitsMinusSecBitNoRoot)
}

// runWithSecBits runs the provided function with the new secure bits set, and restores the old secure bits set at the
// end of its execution.
func runWithSecBits(f func() error, oldSecBits, newSecBits int) (err error) {
	if oldSecBits == newSecBits {
		return runFuncAndWrapErr(f)
	}

	if err := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(newSecBits), 0, 0, 0); err != nil {
		if errors.Is(err, unix.EPERM) {
			err = fmt.Errorf("%w (consider adding the CAP_SETPCAP capability)", err)
		}
		return fmt.Errorf("error setting thread secure bits: %w", err)
	}
	defer func() {
		if e := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(oldSecBits), 0, 0, 0); e != nil {
			if errors.Is(e, unix.EPERM) {
				e = fmt.Errorf("%w (consider adding the CAP_SETPCAP capability)", e)
			}
			e = fmt.Errorf("error restoring thread secure bits: %w", e)
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}()

	return runFuncAndWrapErr(f)
}

// runFuncAndWrapErr runs the provided function and wraps the returned error with FuncError.
func runFuncAndWrapErr(f func() error) error {
	if err := f(); err != nil {
		return &FuncError{err: err}
	}
	return nil
}

// FuncError wraps the error produced by the execution of the function provided to RunWithSecBitNoRootEnabled and
// RunWithSecBitNoRootDisabled.
type FuncError struct {
	err error
}

func (e *FuncError) Error() string {
	return e.err.Error()
}
