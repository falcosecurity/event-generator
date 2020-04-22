SHELL=/bin/bash -o pipefail

GO ?= go
DOCKER ?= docker

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}-dirty,${COMMIT_NO})
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")

IMAGE_NAME ?= docker.io/falcosecurity/event-generator

IMAGE_NAME_BRANCH := $(IMAGE_NAME):$(GIT_BRANCH_CLEAN)
IMAGE_NAME_COMMIT := $(IMAGE_NAME):$(GIT_COMMIT)

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
	$(GO) build -o $@ ${main}

.PHONY: clean
clean:
	$(RM) -R ${output}
	$(RM) -f events/k8saudit/yaml/bundle.go
	$(RM) -R ${output} ${docgen}

.PHONY: test
test: events/k8saudit/yaml/bundle.go
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

events/k8saudit/yaml/bundle.go: events/k8saudit/yaml events/k8saudit/yaml/*.yaml
	$(GO) run ./tools/file-bundler/ $<

.PHONY: ${docgen}
${docgen}: ${PWD}/tools/docgen/docgen.go
	$(GO) build -v -o $@ $^

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
	$(DOCKER) tag $(IMAGE_NAME_BRANCH) $(IMAGE_NAME_COMMIT)
	$(DOCKER) tag "$(IMAGE_NAME_BRANCH)" $(IMAGE_NAME_COMMIT)


.PHONY: push
push:
	$(DOCKER) push $(IMAGE_NAME_BRANCH)
	$(DOCKER) push $(IMAGE_NAME_COMMIT)