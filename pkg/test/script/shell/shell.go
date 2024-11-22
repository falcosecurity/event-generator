// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package shell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/capability"
	"github.com/falcosecurity/event-generator/pkg/test"
)

// shellScript is an implementation of test.Script. The "before" and "after" parts are executed in the same shell
// script, letting the user leverage the declarations/definitions of the "before" part in the "after" part.
type shellScript struct {
	logger logr.Logger
	script string
}

const (
	// signalingToken is a token emitted by the script on standard output, after the "before" script execution has been
	// completed. It is used to unblock the RunBefore call and let the user proceed with the "after" part.
	signalingToken = "__TOKEN"
	// scriptTemplate defines the template used to build a single script from "before" and "after" test scripts. Its
	// defines three placeholders: a placeholder for the "before" script, one for the signalingToken, and one for the
	// "after" script.
	scriptTemplate = `
# __SLEEP_PID is the PID of the sleep process used to block the current script execution.
__SLEEP_PID=

# __cleanup is used as handler for SIGTERM and SIGINT signals, as well as handler for script EXIT pseudo-signal.
__cleanup() {
	[ -n "$__SLEEP_PID" ] && kill -9 $__SLEEP_PID
	exit
}

# __usr1 is used as handler for SIGUSR1.
__usr1() {
	kill -9 $__SLEEP_PID && __SLEEP_PID=
}

# Register signal handler to delete resources and exit upon SIGTERM and SIGINT or upon script EXIT.
trap __cleanup TERM INT EXIT;

# Launch "before" script.
%s

# Launch sleep process and register SIGUSR1 signal handler. The signal handler is responsible to kill the sleep process
# to unblock the current process waiting for it to exit (see "wait $__SLEEP_PID"" below).
sleep infinity & __SLEEP_PID=$!
trap __usr1 USR1

# Send token to parent process to signal "before" script execution completion.
echo %s

# Wait for sleep process to exit.
wait $__SLEEP_PID

# The SIGUSR1 signal triggers __usr1 handler invocation and sets the exit code to 138. Existing from wait, we check if
# the exit code value is as expected and reset it to 0; otherwise, we return the obtained exit code.
if [ $? != 138 ]; then
	echo "Wait on sleep unblocked due to a reason different from USR1 signal" >&2
	exit $?
else
	true # Reset exit code
fi

# Launch "after" script.
%s`
)

// New creates a new shell script by merging beforeScript and afterScript. Since the "before" and "after" are part of
// the same shell script, it is possible to reuse the declarations/definitions of the "before" part in the "after" part.
func New(logger logr.Logger, beforeScript, afterScript *string) test.Script {
	var before, after string
	if beforeScript != nil && *beforeScript != "" {
		before = strings.TrimSpace(*beforeScript) + ";"
	}
	if afterScript != nil && *afterScript != "" {
		after = strings.TrimSpace(*afterScript) + ";"
	}
	script := fmt.Sprintf(scriptTemplate, before, signalingToken, after)
	s := &shellScript{
		logger: logger,
		script: script,
	}
	return s
}

func (s *shellScript) RunBefore(ctx context.Context) (func(context.Context) error, error) {
	processCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(processCtx, "sh", "-c", s.script) //nolint:gosec // Disable G204
	cmd.Cancel = func() error {
		return cmd.Process.Signal(unix.SIGTERM)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error creating script stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error creating script stderr pipe: %w", err)
	}

	wg := &sync.WaitGroup{}
	stdoutLogLinesCh := readScriptLogLines(stdoutPipe, wg)
	stderrLogLinesCh := readScriptLogLines(stderrPipe, wg)
	waitSignalCh := consumeScriptStdoutLogLines(s.logger, stdoutLogLinesCh)
	waitSignalCh = takeFirstWaitSignal(waitSignalCh)
	consumeScriptStderrLog(s.logger, stderrLogLinesCh)

	if err := capability.RunWithSecBitNoRootDisabled(cmd.Start); err != nil {
		var funcErr *capability.FuncError
		if !errors.As(err, &funcErr) {
			_ = stdoutPipe.Close()
			_ = stderrPipe.Close()
		}
		cancel()
		wg.Wait()
		return nil, fmt.Errorf("error starting before script: %w", err)
	}

	if err := waitBeforeScript(ctx, waitSignalCh); err != nil {
		cancel()
		wg.Wait()
		if err := cmd.Wait(); err != nil {
			s.logger.Error(err, "Error waiting for script")
		}
		return nil, err
	}

	return func(_ context.Context) error {
		defer cancel()
		// Signal script continuation (a.k.a: running "after" script)
		if err := cmd.Process.Signal(unix.SIGUSR1); err != nil {
			cancel()
			wg.Wait()
			if err := cmd.Wait(); err != nil {
				s.logger.Error(err, "Error waiting for script")
			}
			return fmt.Errorf("error running after script: %w", err)
		}

		wg.Wait()
		if err := cmd.Wait(); err != nil {
			s.logger.Error(err, "Error waiting for script")
		}

		return nil
	}, nil
}

// readScriptLogLines reads log lines from the provided reader and outputs them into the returned channel.
func readScriptLogLines(reader io.Reader, wg *sync.WaitGroup) <-chan string {
	logLines := make(chan string)
	wg.Add(1)
	scanner := bufio.NewScanner(reader)
	go func() {
		defer wg.Done()
		defer close(logLines)
		for scanner.Scan() {
			logLines <- scanner.Text()
		}
	}()
	return logLines
}

// consumeScriptStdoutLogLines reads stdout log lines from the provided channel and outputs them using the provided
// logger. Each time a signalingToken is encountered in the logLines, a signal is sent on the returned channel.
func consumeScriptStdoutLogLines(logger logr.Logger, logLinesCh <-chan string) <-chan struct{} {
	waitSignalCh := make(chan struct{})
	go func() {
		defer close(waitSignalCh)
		for logLine := range logLinesCh {
			if strings.Contains(logLine, signalingToken) {
				waitSignalCh <- struct{}{}
				continue
			}
			logger.Info("Script log line", "type", "stdout", "line", logLine)
		}
	}()
	return waitSignalCh
}

// takeFirstWaitSignal mirrors the first element obtained from waitSignalCh into the returned channel. Any other
// subsequent element is ignored.
func takeFirstWaitSignal(waitSignalCh <-chan struct{}) <-chan struct{} {
	outputCh := make(chan struct{})
	go func() {
		defer close(outputCh)
		waitSignal := <-waitSignalCh
		outputCh <- waitSignal
		go func() {
			// Drain the input channel.
			for range waitSignalCh { //revive:disable-line:empty-block
			}
		}()
	}()
	return outputCh
}

// consumeScriptStderrLog reads stderr log lines from the provided channel and outputs them using the provided
// logger.
func consumeScriptStderrLog(logger logr.Logger, logLinesCh <-chan string) {
	go func() {
		for logLine := range logLinesCh {
			logger.Info("Script log line", "type", "stderr", "line", logLine)
		}
	}()
}

// waitBeforeScript waits until a signal is received on the provided waitSignalCh or the provided context is canceled.
// It returns an error in case it is unblocked by the context being canceled.
func waitBeforeScript(ctx context.Context, waitSignalCh <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitSignalCh:
	}
	return nil
}
