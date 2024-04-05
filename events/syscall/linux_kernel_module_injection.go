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
	"os/exec"
	"path/filepath"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(LinuxKernelModuleInjection)

func LinuxKernelModuleInjection(h events.Helper) error {
	if h.InContainer() {
		// Create a unique temp directory
		tempDirectoryName, err := os.MkdirTemp("/home", "falco-event-generator-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tempDirectoryName)

		// Create a c file and make file for building a kernel module
		cFilePath := filepath.Join(tempDirectoryName, "basic_driver.c")
		cFileContent := `#include <linux/init.h>
		#include <linux/module.h>
		#include <linux/uaccess.h>
		#include <linux/fs.h>
		#include <linux/proc_fs.h>
		
		// Module metadata
		MODULE_AUTHOR("Falco");
		MODULE_DESCRIPTION("Hello world driver for falco");
		MODULE_LICENSE("GPL");
		
		static int __init custom_init(void) {
			printk(KERN_INFO "Hello from Basic kernel module.");
			return 0;
		}
		static void __exit custom_exit(void) {
			printk(KERN_INFO "Exit the kernel module");
		}
		
		module_init(custom_init);
		module_exit(custom_exit);
		`

		if err := os.WriteFile(cFilePath, []byte(cFileContent), 0644); err != nil {
			return err
		}

		makefilePath := filepath.Join(tempDirectoryName, "Makefile")
		makefileContent := `obj-m += basic_driver.o

		all:
			make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
		clean:
			make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean`

		if err := os.WriteFile(makefilePath, []byte(makefileContent), 0644); err != nil {
			return err
		}

		// Run make command
		cmd := exec.Command("make")
		cmd.Dir = tempDirectoryName
		if err := cmd.Run(); err != nil {
			return err
		}

		// Load kernel module with insmod
		koFilePath := filepath.Join(tempDirectoryName, "basic_driver.ko")
		defer exec.Command("rmmod", "basic_driver.ko") // Unload the kernel module at end
		return exec.Command("insmod", koFilePath).Run()
	}
	return nil
}
