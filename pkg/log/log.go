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

package log

import (
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	uzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// DefaultLogger is initialized at startup time and must only be used by any package that wants to produce log lines
	// before Logger is initialized through InitLogger.
	DefaultLogger = getProductionLogger()
	// Logger is the main exported logger. It must be initialized through InitLogger.
	Logger logr.Logger
)

// Profile is the logging profile.
type Profile string

const (
	// ProfileProduction denotes a production-grade logger.
	ProfileProduction Profile = "prod"
	// ProfileDevelopment denotes a logger useful during the developing phase.
	ProfileDevelopment Profile = "dev"
)

// InitLogger initialized the global Logger instance.
func InitLogger(profile Profile) error {
	switch profile {
	case ProfileProduction:
		Logger = getProductionLogger()
	case ProfileDevelopment:
		Logger = getDevelopmentLogger()
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
	return nil
}

// getProductionLogger returns a production-grade logger.
func getProductionLogger() logr.Logger {
	encoderConfig := uzap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder
	jsonEncoder := zapcore.NewJSONEncoder(encoderConfig)

	level := uzap.NewAtomicLevelAt(zapcore.InfoLevel)
	cores := []zapcore.Core{
		zapcore.NewCore(jsonEncoder, os.Stderr, level),
	}
	tee := zapcore.NewTee(cores...)

	options := []uzap.Option{
		uzap.ErrorOutput(os.Stderr),
		uzap.AddCaller(),
		uzap.AddStacktrace(uzap.ErrorLevel),
		uzap.WrapCore(func(core zapcore.Core) zapcore.Core {
			return zapcore.NewSamplerWithOptions(core, time.Second, 100, 100)
		}),
	}
	logger := uzap.New(tee, options...)
	return zapr.NewLogger(logger)
}

// getDevelopmentLogger returns a logger useful during the developing phase.
func getDevelopmentLogger() logr.Logger {
	encoderConfig := uzap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.LowercaseColorLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)
	level := uzap.NewAtomicLevelAt(zapcore.DebugLevel)
	cores := []zapcore.Core{
		zapcore.NewCore(consoleEncoder, os.Stderr, level),
	}
	tee := zapcore.NewTee(cores...)
	options := []uzap.Option{
		uzap.ErrorOutput(os.Stderr),
		uzap.Development(),
		uzap.AddCaller(),
		uzap.AddStacktrace(uzap.WarnLevel),
	}
	logger := uzap.New(tee, options...)
	return zapr.NewLogger(logger)
}
