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

package validate

import (
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

// V is the validator single instance.
//
// It is a singleton so to cache the structs info.
var V *validator.Validate

// T is the universal translator for validatiors.
var T ut.Translator

func init() {
	V = validator.New()

	// Register a function to get the field name from "name" tags.
	V.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("name"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	if err := V.RegisterValidation("filepath", isFilePath); err != nil {
		panic(err)
	}

	if err := V.RegisterValidation("logrus", isLogrusLevel); err != nil {
		panic(err)
	}

	V.RegisterAlias("format", "eq=text|eq=json")

	eng := en.New()
	uni := ut.New(eng, eng)
	T, _ = uni.GetTranslator("en")
	if err := en_translations.RegisterDefaultTranslations(V, T); err != nil {
		panic(err)
	}

	if err := V.RegisterTranslation(
		"filepath",
		T,
		func(ut ut.Translator) error {
			return ut.Add("filepath", `'{0}' must be a valid file path`, true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("filepath", fe.Field())
			return t
		},
	); err != nil {
		panic(err)
	}

	if err := V.RegisterTranslation(
		"logrus",
		T,
		func(ut ut.Translator) error {
			return ut.Add("logrus", `'{0}' is not a valid log level`, true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("logrus", fe.Value().(string))
			return t
		},
	); err != nil {
		panic(err)
	}

	if err := V.RegisterTranslation(
		"format",
		T,
		func(ut ut.Translator) error {
			return ut.Add("format", `'{0}' is not a valid log format`, true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("format", fe.Value().(string))
			return t
		},
	); err != nil {
		panic(err)
	}
}
