## event-generator suite

Manage test suites described via YAML files

### Synopsis

Provide sub-commands to work with test suites described via YAML files.

A *test* is a single, declaratively-specified scenario that performs one or more suspicious actions and, optionally,
verifies that a running Falco instance reacts to them as expected. Tests are not described in Go code: they are
described in a YAML file, and the `suite` sub-commands consume that file.

Tests are grouped into *test suites* based on the rule they are attempting to test. A test suite is uniquely associated
with a single rule: all tests with the same `rule` field belong to the same suite. This grouping is what gives the
sub-command its name and is reflected in the way reports are collected and emitted: results are always grouped by suite.

There are three sub-commands:

* `run` reads a YAML description and performs the described actions, without verifying any outcome.
* `test` reads a YAML description, performs the described actions, and verifies that the running Falco instance
  produced the expected alerts.
* `explain` produces documentation for the YAML description language itself, by following the property hierarchies.

The YAML description language is shared by all three sub-commands and is documented in full in
[the YAML description reference](event-generator_suite_yaml.md).

```
event-generator suite [command]
```

### Options

```
  -h, --help   help for suite
```

### Options inherited from parent commands

```
  -c, --config string      Config file path (default $HOME/.falco-event-generator.yaml if exists)
      --logformat string   available formats: "text" or "json" (default "text")
  -l, --loglevel string    Log level (default "info")
```

### SEE ALSO

* [event-generator](event-generator.md)	 - A command line tool to perform a variety of suspect actions.
* [event-generator suite explain](event-generator_suite_explain.md)	 - Document test(s) YAML description properties
* [event-generator suite run](event-generator_suite_run.md)	 - Run test(s) specified via a YAML description
* [event-generator suite test](event-generator_suite_test.md)	 - Run test(s) specified via a YAML description and verify that they produce the expected outcomes
* [YAML description reference](event-generator_suite_yaml.md)	 - The YAML description language consumed by `run` and `test`
