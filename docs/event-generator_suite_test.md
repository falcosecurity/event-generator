## event-generator suite test

Run test(s) specified via a YAML description and verify that they produce the expected outcomes

### Synopsis

Run test(s) specified via a YAML description and verify that they produce the expected outcomes.

This command performs all the actions [`event-generator suite run`](event-generator_suite_run.md) performs (build the
process chain, create the resources, run the steps), and additionally connects to a running Falco instance to verify
that the alerts produced by Falco match the `expectedOutcome` declared in each test. Tests are grouped into test
suites by their `rule` field, and the results are produced per-suite once all tests have been executed.

Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.

```
event-generator suite test [flags]
```

### Description

The YAML description language is documented in full in [the YAML description reference](event-generator_suite_yaml.md).
Unlike `run`, **`test` requires every test to declare a non-empty `rule` field**: the rule name is what the command
uses both to group tests into suites and to match Falco alerts back to the originating test. Loading a description that
contains a test without a rule fails with an explicit error from the suite loader, before any action is run.

Demonstrative descriptions are available under the [`samples/`](../samples) folder. Not all of them are usable with
`test`, since some samples omit the `rule` field on purpose; the ones that include it can be passed to this command as
they are.

### Falco configuration

For this command to work, Falco must be configured to use its HTTP output (see PR
[#301](https://github.com/falcosecurity/event-generator/pull/301)). The event-generator hosts an HTTP server that Falco
posts alerts to; that server can be insecure, TLS-protected, or mTLS-protected via the `--http-server-security-mode`
flag. Falco must also be configured to append `proc.env` to its alert output fields, so that the event-generator can
match alerts back to the originating test by inspecting the test UID it propagated through the process chain
environment. A working Falco invocation looks like this:

```
sudo falco -c /etc/falco/falco.yaml \
  -o http_output.enabled=true \
  -o http_output.url=http://localhost:8080 \
  -o json_output=true \
  -o 'append_output[]={"extra_fields": ["proc.env"]}'
```

### Outcome verification

Each test in the description can declare an `expectedOutcome` section, with any subset of the following keys:
`source`, `hostname`, `priority`, `outputFields`. After the test has been executed, the command waits for Falco alerts
to arrive on the HTTP server and considers a test successful if at least one alert matches the rule name and every
field declared in `expectedOutcome`. Fields that are not declared are not matched against. An empty
`expectedOutcome: {}` therefore matches any alert produced for the test's rule, which is the lightest possible form of
verification.

Report retrieval uses an incremental backoff (see PR
[#272](https://github.com/falcosecurity/event-generator/pull/272)): the command tries up to four times to obtain a
non-empty report, doubling the wait between attempts. If no matching alert is observed within the attempts (or before
`--timeout` elapses), an empty report is produced for the test and the test is accounted as failed.

If the `--skip-outcome-verification` flag is passed, the verification step is skipped entirely and the command behaves
exactly like `event-generator suite run`. All the `--http-*` flags are ignored when this flag is set.

### Reports

Reports are accumulated per-suite (see PR [#270](https://github.com/falcosecurity/event-generator/pull/270) and PR
[#271](https://github.com/falcosecurity/event-generator/pull/271)) and emitted once every test in the description has
been executed. The encoding is selected by `--report-format`:

* `text` (default): a human-friendly text format printed to standard output.
* `json`: one JSON object per test suite, useful for programmatic consumption.
* `yaml`: a YAML representation, useful for diffing against expected suite results.

Each test report includes information about the originating test case when the test was generated from a template (see
PR [#291](https://github.com/falcosecurity/event-generator/pull/291) and the `cases` keyword in the
[YAML description reference](event-generator_suite_yaml.md)), so that the user can tell which specific value
combination produced which result.

### Configuration

It is possible to provide the YAML description in multiple ways. The order of evaluation is the following:

1. If `--description-file=<file_path>` and/or `--description-dir=<dir_path>` are provided, the description is read from
   the file(s) at `<file_path>` and from the YAML files inside `<dir_path>` (sub-directories are not recursively
   loaded, and only files with the `.yaml` extension are considered). Both flags accept a comma-separated list of
   pathnames and can be repeated; pathnames are evaluated in the order they appear.
2. If `--description=<description>` is provided instead, the description is read from the `<description>` string. This
   flag is mutually exclusive with both `--description-file` and `--description-dir`.
3. Otherwise, the description is read from standard input.

Every flag can also be supplied via an environment variable or via a key in the config file. The order of precedence
is: command-line flag, then environment variable, then config file, then the flag's default value. The environment
variable corresponding to a flag named `--<flag-name>` is `FALCO_EVENT_GENERATOR_<FLAG_NAME>`, with dashes replaced by
underscores and the whole name uppercased. This applies to the flags documented on this page and not to the fields of
the YAML description.

### Examples

Run the full samples directory against a Falco instance bound to the default `localhost:8080`:

```shell
sudo event-generator suite test --description-dir ./samples
```

Run a single test file and emit the suite report as JSON, so it can be piped into another tool:

```shell
sudo event-generator suite test \
  --description-file ./samples/expected_outcome.yaml \
  --report-format json
```

Run with mutual-TLS between Falco and the event-generator HTTP server:

```shell
sudo event-generator suite test \
  --description-dir ./samples \
  --http-server-security-mode mtls \
  --http-server-cert /etc/falco/certs/server.crt \
  --http-server-key  /etc/falco/certs/server.key \
  --http-client-ca   /etc/falco/certs/ca.crt
```

Run the actions but skip outcome verification, so the command behaves like `suite run` even though it was invoked as
`test`:

```shell
sudo event-generator suite test --description-dir ./samples --skip-outcome-verification
```

### Running in a container

The event-generator is distributed as the
[`falcosecurity/event-generator`](https://hub.docker.com/r/falcosecurity/event-generator) Docker image, so `suite test`
can be invoked inside a container instead of installing the binary on the host. The command performs real system calls
and modifies system state, so the container must be started with `--privileged`.

Falco must also be able to reach the alert-collection HTTP server hosted by the event-generator inside the container.
Publish the container's port to the host's loopback interface only (`-p 127.0.0.1:8080:8080`) and bind the server to
all interfaces inside the container (`--http-server-address 0.0.0.0:8080`) so Docker's port forwarding can route to it.
The published port is then reachable from a host-resident Falco at the default `http://localhost:8080`, but is not
exposed to any other host interface.

Feed the description through standard input:

```shell
docker run --rm -i --privileged \
  -p 127.0.0.1:8080:8080 \
  falcosecurity/event-generator suite test \
    --http-server-address 0.0.0.0:8080 < ./samples/expected_outcome.yaml
```

Mount a host directory of YAML files into the container and load them with `--description-dir`:

```shell
docker run --rm --privileged \
  -p 127.0.0.1:8080:8080 \
  -v "/path/to/my_samples:/my_samples:ro" \
  falcosecurity/event-generator suite test \
    --description-dir /my_samples \
    --http-server-address 0.0.0.0:8080
```

If the YAML description declares a `context.container` (so the test process chain runs inside a nested container), the
event-generator must reach the host's Docker daemon to spawn that container. Mount the host's Docker socket into the
event-generator container at the default path of `--container-runtime-unix-socket` (`unix:///run/docker.sock`):

```shell
docker run --rm -i --privileged \
  -p 127.0.0.1:8080:8080 \
  -v /var/run/docker.sock:/run/docker.sock \
  falcosecurity/event-generator suite test \
    --http-server-address 0.0.0.0:8080 < ./my_sample.yaml
```

Run with mTLS between Falco and the event-generator, mounting the certificate material into the container:

```shell
docker run --rm -i --privileged \
  -p 127.0.0.1:8080:8080 \
  -v "/etc/falco/certs:/certs:ro" \
  falcosecurity/event-generator suite test \
    --http-server-address 0.0.0.0:8080 \
    --http-server-security-mode mtls \
    --http-server-cert /certs/server.crt \
    --http-server-key /certs/server.key \
    --http-client-ca /certs/ca.crt < ./samples/expected_outcome.yaml
```

See [Falco configuration](#falco-configuration) for the matching Falco-side options.

### Options

```
      --container-base-image string                               The event-generator base image to generate new containers (default "docker.io/falcosecurity/event-generator:latest")
      --container-image-pull-policy container-image-pull-policy   The container image pull policy; can be 'always', 'never' or 'ifnotpresent' (default always)
      --container-runtime-unix-socket string                      The unix socket path of the local container runtime (default "unix:///run/docker.sock")
      --description string                                        The YAML-formatted tests description string specifying the tests to be run
  -d, --description-dir strings                                   The pathnames of directories containing tests description YAML files specifying the tests to be run. Sub-directories of the provided pathnames are not recursively loaded. Only files with YAML extensions are loaded. Multiple pathnames can be specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated in order of appearance
  -f, --description-file strings                                  The pathnames of tests description YAML files specifying the tests to be run. Multiple pathnames can be specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated in order of appearance
  -h, --help                                                      help for test
      --http-client-ca string                                     The path of the CA root certificate used for Falco HTTP client's certificate validation (to be used together with --http-server-security-mode=mtls) (default "/etc/falco/certs/ca.crt")
      --http-server-address string                                The address the alert retriever HTTP server must be bound to (default "localhost:8080")
      --http-server-cert string                                   The path of the server certificate to be used for TLS against the Falco HTTP client (to be used together with --http-server-security-mode=(tls|mtls)) (default "/etc/falco/certs/server.crt")
      --http-server-key string                                    The path of the server private key to be used for TLS against the Falco HTTP client (to be used together with --http-server-security-mode=(tls|mtls)) (default "/etc/falco/certs/server.key")
      --http-server-security-mode http-server-security-mode       The security mode the alert retriever HTTP server must use; can be 'insecure', 'tls' or 'mtls' (default insecure)
      --report-format report-format                               The format of the test suites report; can be 'text', 'json' or 'yaml' (default text)
      --skip-outcome-verification                                 Skip verification of the expected outcome. If this option is enabled, http- flags are ignored
  -t, --timeout duration                                          The maximal duration of the tests. If running tests lasts more than the provided timeout, the execution of all pending tasks is canceled (default 1m0s)
```

The container-related flags only come into play if at least one test in the description declares a `context.container`
section. In that case, the local container runtime referenced by `--container-runtime-unix-socket` (a Docker-compatible
daemon, see PR [#282](https://github.com/falcosecurity/event-generator/pull/282)) is used to pull the image specified
by `--container-base-image`, subject to the policy of `--container-image-pull-policy`. If the test declares an
`image` name in `context.container` that differs from the base image name, the pulled image is given that name as an
additional Docker tag. A container is then created from that image and runs the entire test process chain inside it.
The extra tag, if one was added, is removed when the test ends.

### Options inherited from parent commands

```
  -c, --config string      Config file path (default $HOME/.falco-event-generator.yaml if exists)
      --logformat string   available formats: "text" or "json" (default "text")
  -l, --loglevel string    Log level (default "info")
```

### SEE ALSO

* [event-generator suite](event-generator_suite.md)	 - Manage test suites described via YAML files
* [event-generator suite run](event-generator_suite_run.md)	 - Run test(s) specified via a YAML description
* [YAML description reference](event-generator_suite_yaml.md)	 - The YAML description language consumed by this command
