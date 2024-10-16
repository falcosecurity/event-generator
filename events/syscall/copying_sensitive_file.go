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

package syscall 

import (
	"os"
    "io"
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	DownloadSensitiveFile,
    events.WithDisabled(),  //this rule is not default_rules
)

func DownloadSensitiveFile(h events.Helper) error{
	filename := "/etc/shadow"
	destFilename := "/tmp/copied-by-event-generator"

	file, err := os.Open(filename)
	if err != nil{
		return err
	}
	defer file.Close()

	destFile, err := os.Create(destFilename)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, file)
	if err != nil {
		h.Log().WithError(err).Error("Failed to copy sensitive file content")
		return err
	}
    
	return nil
}