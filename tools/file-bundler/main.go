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
