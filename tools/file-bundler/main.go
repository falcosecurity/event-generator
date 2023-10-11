// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const (
	goFileName     = "bundle.go"
	goFileTemplate = `package %s

var Bundle = %#v
	
`
)

func genBundle(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	outFilepath := filepath.Join(path, goFileName)
	if err := os.Remove(outFilepath); err != nil && !os.IsNotExist(err) {
		return err
	}

	packageName := filepath.Base(path)

	bundle := make(map[string][]byte)
	if err := filepath.Walk(path, func(filename string, info os.FileInfo, err error) error {
		if !info.Mode().IsRegular() {
			return nil
		}

		if bundle[filepath.Base(filename)], err = ioutil.ReadFile(filename); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return ioutil.WriteFile(
		filepath.Join(path, goFileName),
		[]byte(fmt.Sprintf(goFileTemplate, packageName, bundle)),
		os.FileMode(0644),
	)
}

func main() {

	cmd := &cobra.Command{
		Use:   "file-bundler <directory>",
		Short: "Generate a bundle.go from <directory>'s files",

		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return genBundle(args[0])
		},
	}

	if err := cmd.Execute(); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
