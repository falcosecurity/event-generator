# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
SHELL=/bin/bash -o pipefail

GO ?= go
DOCKER ?= docker

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}-dirty,${COMMIT_NO})
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")

VERSION = $(shell git describe --tags)

CLIENTGO_VERSION := $(shell grep 'k8s.io/client-go' go.mod | cut -dv -f2)

IMAGE_NAME ?= docker.io/falcosecurity/event-generator

IMAGE_NAME_BRANCH := $(IMAGE_NAME):$(GIT_BRANCH_CLEAN)
IMAGE_NAME_COMMIT := $(IMAGE_NAME):$(GIT_COMMIT)

LDFLAGS = -X k8s.io/client-go/pkg/version.gitCommit=v$(CLIENTGO_VERSION) \
			-X k8s.io/client-go/pkg/version.gitVersion=$(VERSION)

TEST_FLAGS ?= -v -race

main ?= .
output ?= event-generator
docgen ?= evtgen-docgen

.PHONY: build
build: prepare ${output}

.PHONY: prepare
prepare: clean events/k8saudit/yaml/bundle.go

.PHONY: ${output}
${output}:
	CGO_ENABLED=0 $(GO) build -buildmode=pie -buildvcs=false -ldflags "$(LDFLAGS)" -o $@ ${main}

.PHONY: clean
clean:
	$(RM) -R ${output}
	$(RM) events/k8saudit/yaml/bundle.go
	$(RM) -R ${output} ${docgen}

.PHONY: test
test: events/k8saudit/yaml/bundle.go
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

events/k8saudit/yaml/bundle.go: events/k8saudit/yaml events/k8saudit/yaml/*.yaml
	GOOS= GOARCH= $(GO) run ./tools/file-bundler/ $<

.PHONY: ${docgen}
${docgen}: ${PWD}/tools/docgen/docgen.go
	$(GO) build -buildvcs=false -v -o $@ $^

.PHONY: docs
docs: ${docgen}
	$(RM) -R docs/*
	@mkdir -p docs
	${PWD}/${docgen}

.PHONY: image
image:
	$(DOCKER) build \
		-t "$(IMAGE_NAME_BRANCH)" \
		-f Dockerfile .
	$(DOCKER) tag "$(IMAGE_NAME_BRANCH)" "$(IMAGE_NAME_COMMIT)"

.PHONY: push
push:
	$(DOCKER) push "$(IMAGE_NAME_BRANCH)"
	$(DOCKER) push "$(IMAGE_NAME_COMMIT)"
