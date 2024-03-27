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
    "bytes"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ReadEnvironmentVariableFromProcFiles)

func ReadEnvironmentVariableFromProcFiles(h events.Helper) error {

    pid := os.Getpid()

    file := filepath.Join("/proc", fmt.Sprintf("%d", pid), "environ")

    h.Log().Infof("reading environment variable from %s", file)

    buf, err := ioutil.ReadFile(file)
    if err != nil {
        return err
    }

    h.Log().Infof("Environment Variables:\n%s", bytes.Split(buf, []byte{0}))

    return nil
}
