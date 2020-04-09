SHELL=/bin/bash -o pipefail

GO ?= go

TEST_FLAGS ?= -v -race

main ?= .
output ?= event-generator
docgen ?= evtgen-docgen

.PHONY: build
build: clean events/k8saudit/yaml/bundle.go ${output}

.PHONY: ${output}
${output}:
	$(GO) build -o $@ ${main}

.PHONY: clean
clean:
	$(RM) -R ${output}
	$(RM) -f events/k8saudit/yaml/bundle.go
	$(RM) -R ${output} ${docgen}

.PHONY: test
test:
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
