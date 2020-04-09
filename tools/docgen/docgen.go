package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/falcosecurity/event-generator/cmd"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const outputDir = "docs"
const websiteTemplate = `---
title: %s
weight: %d
---

`

var (
	targetWebsite    bool
	websitePrepender = func(num int) func(filename string) string {
		total := num
		return func(filename string) string {
			num = num - 1
			title := strings.TrimPrefix(strings.TrimSuffix(strings.ReplaceAll(filename, "_", " "), ".md"), fmt.Sprintf("%s/", outputDir))
			return fmt.Sprintf(websiteTemplate, title, total-num)
		}
	}
	websiteLinker = func(filename string) string {
		if filename == "event-generator.md" {
			return "_index.md"
		}
		return filename
	}
)

// fixme(leogr): we must not expose the local home dir / temp workaround here
func fixDefaults(c *cobra.Command) {
	for _, cc := range c.Commands() {
		if f := cc.Flags().Lookup("cache-dir"); f != nil {
			f.DefValue = "$HOME/.kube/http-cache"
		}
	}
}

// docgen
func main() {
	// Get mode
	flag.BoolVar(&targetWebsite, "website", targetWebsite, "")
	flag.Parse()

	// Get root command
	evtgen := cmd.New(nil)
	fixDefaults(evtgen)
	num := len(evtgen.Commands()) + 1

	// Setup prepender hook
	prepender := func(num int) func(filename string) string {
		return func(filename string) string {
			return ""
		}
	}
	if targetWebsite {
		prepender = websitePrepender
	}

	// Setup links hook
	linker := func(filename string) string {
		return filename
	}
	if targetWebsite {
		linker = websiteLinker
	}

	// Generate markdown docs
	err := doc.GenMarkdownTreeCustom(evtgen, outputDir, prepender(num), linker)
	if err != nil {
		logger.WithError(err).Fatal("docs generation")
	}

	if targetWebsite {
		err := os.Rename(path.Join(outputDir, "event-generator.md"), path.Join(outputDir, "_index.md"))
		if err != nil {
			logger.WithError(err).Fatal("renaming main docs page")
		}
	}
}
