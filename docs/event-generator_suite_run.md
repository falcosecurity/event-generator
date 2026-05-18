## event-generator suite run

Run test(s) specified via a YAML description

### Synopsis

Run test(s) specified via a YAML description.

This command reads one or more YAML tests descriptions, builds the process chain each test asks for, creates the
declared resources, runs the declared steps, and reports completion. It does *not* connect to Falco and does *not*
verify any expected outcome: it just performs the described suspicious actions. To run the same description and verify
the outcomes against a running Falco instance, use [`event-generator suite test`](event-generator_suite_test.md)
instead.

Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.

```
event-generator suite run [flags]
```

### Description

The shape of the YAML is documented in full in [the YAML description reference](event-generator_suite_yaml.md). The
following snippet is the minimal valid description, to make this page self-contained:

```yaml
tests:
  - name: test_steps_syscall_dup
    description: "Testing dup system call"
    runner: HostRunner
    steps:
      - type: syscall
        name: d1
        syscall: dup
        args:
          oldFd: 1
```

Notice that the `rule` field is *not* required when using `run`. The rule name is only required by
[`event-generator suite test`](event-generator_suite_test.md), which uses it to match alerts back to the originating
test. Tests without a `rule` field can be loaded and executed by `run` without restrictions; they are grouped under a
single, anonymous test suite identified by the empty string.

Demonstrative descriptions covering most features (multiple system calls, the `clientServer`/`fd`/`process` resources,
process-chain context, containerised context, templates and cases, the `before`/`after` scripts) are available under
the [`samples/`](../samples) folder.

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

Run the tests described in a single YAML file:

```shell
sudo event-generator suite run --description-file ./samples/steps_syscall.yaml
```

Run all the tests described in every `*.yaml` file inside a directory (sub-directories are not loaded recursively):

```shell
sudo event-generator suite run --description-dir ./samples
```

Load tests from two files and one directory, in order of appearance:

```shell
sudo event-generator suite run \
  --description-file ./samples/steps_syscall.yaml \
  --description-file ./samples/scripts.yaml \
  --description-dir /path/to/other/samples
```

Pipe a description in via standard input, handy for one-off invocations:

```shell
cat ./samples/steps_syscall.yaml | sudo event-generator suite run
```

### Running in a container

The event-generator is distributed as the
[`falcosecurity/event-generator`](https://hub.docker.com/r/falcosecurity/event-generator) Docker image, so `suite run`
can be invoked inside a container instead of installing the binary on the host. The command could perform complex
actions that require a wide range of capabilities, so the container must be started with `--privileged`.

Feed the description through standard input:

```shell
docker run --rm -i --privileged \
  falcosecurity/event-generator suite run < ./samples/steps_syscall.yaml
```

Mount a host directory of YAML files into the container and load them with `--description-dir`:

```shell
docker run --rm --privileged \
  -v "$PWD/samples:/samples:ro" \
  falcosecurity/event-generator suite run --description-dir /samples
```

If the YAML description declares a `context.container` (so the test process chain runs inside a nested container), the
event-generator must reach the host's Docker daemon to spawn that container. Mount the host's Docker socket into the
event-generator container at the default path of `--container-runtime-unix-socket` (`unix:///run/docker.sock`):

```shell
docker run --rm --privileged \
  -v /var/run/docker.sock:/run/docker.sock \
  -v "$PWD/samples:/samples:ro" \
  falcosecurity/event-generator suite run --description-dir /samples
```

### Options

```
      --container-base-image string                               The event-generator base image to generate new containers (default "docker.io/falcosecurity/event-generator:latest")
      --container-image-pull-policy container-image-pull-policy   The container image pull policy; can be 'always', 'never' or 'ifnotpresent' (default always)
      --container-runtime-unix-socket string                      The unix socket path of the local container runtime (default "unix:///run/docker.sock")
      --description string                                        The YAML-formatted tests description string specifying the tests to be run
  -d, --description-dir strings                                   The pathnames of directories containing tests description YAML files specifying the tests to be run. Sub-directories of the provided pathnames are not recursively loaded. Only files with YAML extensions are loaded. Multiple pathnames can be specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated in order of appearance
  -f, --description-file strings                                  The pathnames of tests description YAML files specifying the tests to be run. Multiple pathnames can be specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated in order of appearance
  -h, --help                                                      help for run
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
* [event-generator suite test](event-generator_suite_test.md)	 - Run test(s) specified via a YAML description and verify that they produce the expected outcomes
* [YAML description reference](event-generator_suite_yaml.md)	 - The YAML description language consumed by this command
