SHELL=/bin/bash -o pipefail

GO ?= go

TEST_FLAGS ?= -v -race

main ?= .
output ?= event-generator

.PHONY: build
build: clean ${output}

.PHONY: ${output}
${output}:
	$(GO) build -o $@ ${main}

.PHONY: clean
clean:
	$(RM) -R ${output}

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...