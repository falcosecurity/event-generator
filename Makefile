SHELL=/bin/bash -o pipefail

GO ?= go

TEST_FLAGS ?= -v -race

main ?= .
output ?= event-generator

.PHONY: build
build: clean events/k8saudit/yaml/bundle.go ${output}

.PHONY: ${output}
${output}:
	$(GO) build -o $@ ${main}

.PHONY: clean
clean:
	$(RM) -R ${output}
	$(RM) -f events/k8saudit/yaml/bundle.go

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

events/k8saudit/yaml/bundle.go: events/k8saudit/yaml events/k8saudit/yaml/*.yaml
	$(GO) run ./tools/file-bundler/ $<