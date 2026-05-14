## YAML description reference

This page documents the YAML language consumed by [`event-generator suite run`](event-generator_suite_run.md) and
[`event-generator suite test`](event-generator_suite_test.md). For an interactive, schema-driven view of the same
material, use [`event-generator suite explain`](event-generator_suite_explain.md).

The language is layered. The simplest description specifies a single test that performs a single system call; from
there, the user can incrementally add a process chain, a containerised context, resources that expose bindable fields,
template parameters that generate multiple tests from a single block, and an expected outcome that is matched against
Falco alerts. This page is organized in the same order: each section assumes only what the previous sections have
introduced.

A minimal valid description is like the following:

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

This declares one test, called `test_steps_syscall_dup`, that runs the `dup` system call on file descriptor `1`. The test
is not associated with any rule and therefore can be loaded by `run`, but not by `test`.

A topic-focused sample is available for each main feature documented below; see the [`samples/`](../samples) folder
and its [README](../samples/README.md) for the full corpus.

### Document root

The document root is an object with a single property:

| Property | Required | Description |
| --- | --- | --- |
| `tests` | yes | A non-empty array of test descriptions. Each entry is documented in [Test fields](#test-fields). |

### Test fields

Every entry in `tests` is an object with the following properties.

| Property | Required | Type | Description |
| --- | --- | --- | --- |
| `name` | yes | string | The test name. It must be unique across all descriptions loaded in the same invocation. |
| `runner` | yes | string | The type of test runner. Currently the only supported value is `HostRunner`. |
| `rule` | for `test` | string | The name of the Falco rule that this test is expected to trigger. Required when running the test through [`event-generator suite test`](event-generator_suite_test.md), and used to group tests into suites and to match alerts back to the originating test. Optional under [`event-generator suite run`](event-generator_suite_run.md): tests without a rule are grouped under a single anonymous suite identified by the empty string. |
| `description` | no | string | A free-form human description. Surfaced in reports and logs. |
| `context` | no | object | The execution context. Specifies a custom process chain and, optionally, a container to host that chain. See [Test context](#test-context). |
| `before` | no | string | A bash script that is run before the resources are created. Useful for one-off setup steps that do not deserve their own resource type. See [`samples/scripts.yaml`](../samples/scripts.yaml). |
| `after` | no | string | A bash script that is run after the steps complete, regardless of success. Useful for one-off cleanup. See [`samples/scripts.yaml`](../samples/scripts.yaml). |
| `resources` | no | array | The list of test resources. Resources are created in order of appearance and the values they expose can be bound to step arguments. See [Resources](#resources). |
| `steps` | no | array | The list of test steps. Steps are executed in order of appearance, after every resource has been created. See [Steps](#steps). |
| `expectedOutcome` | no | object | The Falco alert that the test is expected to produce. Only taken into account by [`event-generator suite test`](event-generator_suite_test.md). See [Expected outcome](#expected-outcome). |
| `cases` | no | array | A list of test case specifications. When present, the test is treated as a template and one concrete test is generated per case. See [Templates and cases](#templates-and-cases). |

The execution order, for a single test, is:

1. Build the process chain declared in `context.processes` (inside the container declared in `context.container`, if
   requested).
2. Run the `before` bash script on the leaf process.
3. Create the resources in `resources`, in order.
4. Execute the steps in `steps`, in order.
5. Run the `after` bash script on the leaf process.
6. (Only under `test`) wait for matching Falco alerts and produce the test report.

### Test context

The `context` object configures the process chain that runs the test. It has two optional properties: `processes`,
which describes a chain of one or more processes, and `container`, which wraps the chain inside a container.

#### Process chain

```yaml
context:
  processes:
    - args: "arg1 arg2"
      name: "proc0"
      exe: "arg0"
      user: user1
    - user: user2
    - user: root
      capabilities: "cap_net_admin,cap_net_bind_service,cap_chown=ep"
```

Each entry of `processes` describes one process in a chain in which each process is spawned by the previous one. The
last entry is the *leaf* process, and it is the only one that is monitored: the actual resources and steps run inside
the leaf. All preceding entries exist solely to give the leaf a controlled set of ancestors (for instance, to satisfy
rules that look at `proc.aname` or `proc.ppid`).

Each process context supports the following properties (all optional):

| Property | Type | Description |
| --- | --- | --- |
| `exePath` | string | The executable path. Defaults to a randomly generated path under `/tmp`. The directory hierarchy leading to `exePath` is created on the fly when missing and removed when the process resource is released (see PR [#278](https://github.com/falcosecurity/event-generator/pull/278)). |
| `args` | string | A space-separated list of command-line arguments. If a single argument contains spaces, the whole argument must be quoted. Defaults to the empty string. |
| `exe` | string | The argument in position 0 (`argv[0]`). Defaults to `name` if specified, otherwise to `filepath.Base(exePath)`. |
| `name` | string | The process name as visible to the kernel. Defaults to `filepath.Base(exePath)`. |
| `env` | map of strings | Additional environment variables, on top of the defaults inherited from the parent process. Each key is the variable name and the corresponding value is the variable value. |
| `user` | string | The name of the user that runs the process. Defaults to the current user. If the user does not exist on the system, it is created before the test and deleted after the test, so the description does not require pre-existing accounts. |
| `capabilities` | string | The capability set assigned to the process. The syntax follows `cap_from_text(3)`. Defaults to `all=iep` (full capability set, inheritable, effective, permitted). |

Capabilities can be set **only on the leaf process**. Specifying `capabilities` on a non-leaf entry is rejected by the
description loader with an explicit error: the chain validation enforces that constraint before any action is run.

If `context.processes` is omitted entirely (and no `context.container` is declared either), the loader injects a single
default process so that there is always at least one process in the chain. This is why descriptions that do not care
about the chain (such as the minimal `dup` example at the top of this page) work without an explicit `context`.

See [`samples/context_processes.yaml`](../samples/context_processes.yaml) for a runnable example.

#### Container

```yaml
context:
  container:
    image: image-name
    name: container-name
    env:
      MY_VAR: foo
```

When `context.container` is present, the entire process chain is run inside a container, instead of directly on the
host. The image used to spawn the container is the one declared by `--container-base-image` (default
`docker.io/falcosecurity/event-generator:latest`): the runtime pulls it according to `--container-image-pull-policy`,
and if the test's `image` field is different from the base image name the pulled image is given that name as an
additional Docker tag. The running container is named after `name`. The container daemon is reached over the Unix
socket specified by `--container-runtime-unix-socket` (a Docker-compatible daemon, see PR
[#282](https://github.com/falcosecurity/event-generator/pull/282)).

| Property | Type | Description |
| --- | --- | --- |
| `image` | string | The tag to apply to the base image before spawning the container. Defaults to the base image name. |
| `name` | string | The name of the running container. Defaults to `event-generator`. |
| `env` | map of strings | Additional environment variables to inject, on top of the defaults the container needs to find the description and the test UID. Each key is the variable name and the corresponding value is the variable value. |

See [`samples/context_container.yaml`](../samples/context_container.yaml) for a runnable example.

### Resources

A resource creates one or more system resources before the steps run, and exposes some of their fields so that steps
can refer to them via [field bindings](#field-bindings). Resources are created in order of appearance and torn down
after the test finishes.

Every resource has a `type` and a `name`. The name must be unique across all resources and steps of the same test (see
PR [#262](https://github.com/falcosecurity/event-generator/pull/262)); steps reference resources by name when binding
to their exposed fields.

Three resource types are currently supported:

* `clientServer` (see [clientServer](#clientserver-resource))
* `fd` (see [fd](#fd-resource), with eight subtypes)
* `process` (see [process](#process-resource), see PR
  [#241](https://github.com/falcosecurity/event-generator/pull/241))

#### `clientServer` resource

```yaml
resources:
  - type: clientServer
    name: cs1
    l4Proto: tcp4
    address: 11.0.0.1:80
```

Sets up a client and a server, tunes the underlying network infrastructure (loopback addresses, ephemeral routes,
sockets) so that they can talk to each other, and exposes both endpoints. For connection-oriented protocols, the client
is automatically connected to the server.

| Property | Type | Description |
| --- | --- | --- |
| `l4Proto` | enum | One of `udp4`, `udp6`, `tcp4`, `tcp6`, `unix`. |
| `address` | string | The endpoint exposed by the server, as accepted by `net.SplitHostPort`, or the empty string when `l4Proto` is `unix`. |

Exposed fields:

| Path | Description |
| --- | --- |
| `<name>.client.fd` | The client file descriptor. |
| `<name>.server.fd` | The server file descriptor. |

See [`samples/resources_clientserver.yaml`](../samples/resources_clientserver.yaml) for a runnable example covering
every supported transport protocol.

#### `fd` resource

```yaml
resources:
  - type: fd
    name: f1
    subtype: file
    filePath: /tmp/foo.txt
```

Sets up one or more file descriptors. The actual shape depends on `subtype`:

| Subtype | Extra fields | Exposed fields |
| --- | --- | --- |
| `file` | `filePath` (required, string) | `<name>.fd` |
| `directory` | `dirPath` (required, string) | `<name>.fd` |
| `pipe` | none | `<name>.readFd`, `<name>.writeFd` |
| `event` | none | `<name>.fd` |
| `signalfd` | none | `<name>.fd` |
| `eventpoll` | none | `<name>.fd` |
| `inotify` | none | `<name>.fd` |
| `memfd` | `fileName` (required, string) | `<name>.fd` |

For the `file` and `directory` subtypes, any missing directory in the supplied path is created on the fly and removed
when the resource is released (see PR [#279](https://github.com/falcosecurity/event-generator/pull/279)). This means
that `dirPath: /tmp/foo/bar` works without a pre-existing `/tmp/foo/` directory.

See [`samples/resources_fd.yaml`](../samples/resources_fd.yaml) for a runnable example covering every supported subtype.

#### `process` resource

```yaml
resources:
  - type: process
    name: p1
```

Spawns a process and exposes its PID. This is the resource that enables tests for rules involving process
manipulation, such as `kill` or `ptrace`. The properties accepted are a subset of those accepted by
`context.processes` entries (`exePath`, `args`, `exe`, `procName`, `env`).

Exposed fields:

| Path | Description |
| --- | --- |
| `<name>.pid` | The process identifier. |

See [`samples/resources_process.yaml`](../samples/resources_process.yaml) for a runnable example.

### Steps

A step performs one action in the context of a test. Currently the only supported step type is `syscall`. Every step
has a `type` and a `name`; the name must be unique across resources and steps in the same test (see PR
[#262](https://github.com/falcosecurity/event-generator/pull/262)) and is used to reference the step's exposed values
from later steps via [field bindings](#field-bindings).

#### `syscall` step

```yaml
steps:
  - type: syscall
    name: dup1
    syscall: dup2
    args:
      oldFd: "${cs1.client.fd}"
      newFd: 0
```

A `syscall` step runs the named system call with the supplied arguments. After the call has been issued, the step
exposes both its arguments and (for most syscalls) the return value for [binding](#field-bindings) by other steps.

The supported system calls, their arguments and their exposed fields are listed below. Arguments marked `(o)` are
optional. Exposed fields marked `†` are `bindOnly`: their value can be provided to the step only via a binding
expression (a literal value is rejected). Numeric arguments can be specified either as integers or as strings of
`|`-separated symbolic constants, which is the form most readable for flag arguments. For instance
`flags: "O_CREAT|O_CLOEXEC|O_RDWR"` is equivalent to the integer that would be produced by OR-ing the same flags in C.

| `syscall` | Arguments | Exposed fields |
| --- | --- | --- |
| `write` | `fd`, `buffer`(o), `len`(o) | `fd`, `buffer`, `len`, `ret` |
| `read` | `fd`, `buffer`(o), `len`(o) | `fd`, `buffer`, `len`, `ret` |
| `open` | `pathname`, `flags`, `mode`(o) | `pathname`, `flags`, `mode`, `ret` |
| `openat` | `dirFd`, `pathname`, `flags`, `mode`(o) | `dirFd`†, `pathname`, `flags`, `mode`, `ret` |
| `openat2` | `dirFd`, `pathname`, `how`(o) | `dirFd`†, `pathname`, `how.flags`, `how.mode`, `how.resolve`, `ret` |
| `symlink` | `target`, `linkPath` | `target`, `linkPath` |
| `symlinkat` | `target`, `newDirFd`, `linkPath` | `target`, `newDirFd`†, `linkPath` |
| `link` | `oldPath`, `newPath` | `oldPath`, `newPath` |
| `linkat` | `oldDirFd`, `oldPath`, `newDirFd`, `newPath`, `flags`(o) | `oldDirFd`†, `oldPath`, `newDirFd`†, `newPath`, `flags` |
| `init_module` | `moduleImage`, `paramValues`(o) | `moduleImage`, `paramValues` |
| `finit_module` | `fd`, `paramValues`(o), `flags`(o) | `fd`†, `paramValues`, `flags` |
| `dup` | `oldFd` | `oldFd`, `ret` |
| `dup2` | `oldFd`, `newFd` | `oldFd`, `newFd`, `ret` |
| `dup3` | `oldFd`, `newFd`, `flags`(o) | `oldFd`, `newFd`, `flags`, `ret` |
| `connect` | `fd`, `address` | `fd`, `address` |
| `socket` | `domain`, `type`, `protocol` | `domain`, `type`, `protocol`, `ret` |
| `sendto` | `fd`, `buf`, `flags`, `destAddr`, `len`(o) | `fd`†, `buf`, `len`, `flags`, `destAddr` |
| `kill` | `pid`, `sig` | `pid`†, `sig` |

For the authoritative, per-syscall list of arguments and their exposed fields, run:

```shell
event-generator suite explain tests.steps{type=syscall}{syscall=<SYSCALL>}
```

### Field bindings

A *field binding* lets a step's argument refer to a value exposed by a preceding resource or step, instead of
hard-coding it. The syntax is:

```
${<resourceOrStepName>.<pathToExposedField>}
```

For example, after declaring a `clientServer` resource named `cs1`, the client file descriptor can be passed as the
old fd of a `dup2` call without knowing the actual integer:

```yaml
resources:
  - type: clientServer
    name: cs1
    l4Proto: tcp4
    address: 11.0.0.1:80
steps:
  - type: syscall
    name: dup1
    syscall: dup2
    args:
      oldFd: "${cs1.client.fd}"
      newFd: 0
```

Bindings are resolved at runtime, after the producing resource or step has run. A binding to a value not yet produced
is rejected at load time, so forward references are impossible.

### Templates and cases

A test that declares a `cases` array is a *template*: the actual concrete tests are generated by substituting template
parameters with the values provided in the cases. A template parameter is referenced in any string value in the
description with the syntax `%{item.<keyName>}`. The cases array provides one or more case specifications, each with a
`strategy`:

* `vector`: each key in `values` maps to a single value. One concrete test is generated per case.
* `matrix`: each key in `values` maps to a list of values. The combinations of all lists are used to generate one
  concrete test per combination, the count being the product of the lists' cardinalities.

A template is not instantiated if it does not declare any case. Every case specification within the same template must
declare the same set of value keys, so that every concrete test has a value for every placeholder.

The following description (taken from PR [#266](https://github.com/falcosecurity/event-generator/pull/266)) declares a
single template that expands to thirteen concrete tests: one from the vector case and twelve from the matrix case
(`3 * 2 * 1 * 2`):

```yaml
tests:
  - name: template_feat_test
    description: "Testing the test template feature"
    runner: HostRunner
    resources:
      - type: clientServer
        name: cs1
        l4Proto: "%{ item.l4Proto }"
        address: "%{ item.address }"
    steps:
      - type: syscall
        name: d1
        syscall: "%{ item.syscall }"
        args:
          oldFd: "${ cs1.client.fd }"
          newFd: "%{ item.newFd }"
    cases:
      - strategy: vector
        values:
          newFd: 0
          l4Proto: tcp4
          syscall: dup2
          address: "10.0.0.1:4000"
      - strategy: matrix
        values:
          newFd: [ 11, 12, 13 ]
          l4Proto: [ "tcp4", "udp4" ]
          address: [ "10.0.0.1:4000" ]
          syscall: [ "dup2", "dup3" ]
```

To keep names unique within the description, the loader suffixes every generated test's `name` with
`_testCase#<index>`. The index is zero-based and counts across every case the template expands to, in the order the
`cases` array would produce them: each `vector` spec contributes one case, each `matrix` spec contributes its
combinations, and indices accumulate from one spec to the next. The template above therefore produces tests named
`template_feat_test_testCase#0` (the vector case) through `template_feat_test_testCase#12` (the last matrix
combination). Only `name` is mangled; the `rule` field is left untouched, so all generated tests still belong to the
same test suite.

Each generated test carries the information about its originating case, so reports can tell which value combination
produced which result (see PR [#291](https://github.com/falcosecurity/event-generator/pull/291)).

See [`samples/templates.yaml`](../samples/templates.yaml) for a runnable example.

### Expected outcome

```yaml
expectedOutcome:
  source: "syscall"
  priority: "WARNING"
  outputFields:
    proc.name: "httpd"
```

The `expectedOutcome` section declares the Falco alert that the test is expected to produce. Only
[`event-generator suite test`](event-generator_suite_test.md) consumes it: the `run` command ignores it. The matching
is lenient: a Falco alert matches the expected outcome if it carries the right rule name (taken from the test's `rule`
field) and matches every key explicitly declared under `expectedOutcome`. Fields that are not declared are not matched
against.

| Property | Type | Description |
| --- | --- | --- |
| `source` | string | The Falco event source (for example `syscall`). |
| `hostname` | string | The Falco event hostname. |
| `priority` | string | The Falco event priority (for example `WARNING`). |
| `outputFields` | map of strings | Output fields attached to the Falco event. Each entry is matched as a string equality against the corresponding field in the alert. |

A common idiom in the samples is the empty `expectedOutcome: {}`. It matches any alert produced for the test's rule, so
it is the lightest form of verification: useful when the test is supposed to make the rule fire and the user does not
care about the details.

See [`samples/expected_outcome.yaml`](../samples/expected_outcome.yaml) for a runnable example demonstrating both the
strict and the loose forms.

### Notable validation rules

The following rules are enforced by the loader before any action is run. Failing any of them produces an explicit error
naming the offending element.

* The name of every test must be present.
* The runner of every test must be present and must be one of the supported runners (currently only `HostRunner`).
* Names of resources and steps within the same test must be unique.
* Capabilities can only be specified on the leaf process of a process chain.
* Under [`event-generator suite test`](event-generator_suite_test.md), every test must specify a non-empty `rule`.
* Field bindings must reference an existing resource or step, and that resource or step must appear before the binding
  is consumed.
* No `env` block (under `context.container`, `context.processes[]`, or `resources[type=process]`) may declare a key that
  starts with `FALCO_EVENT_GENERATOR_` or equals `SUITE`. The event-generator uses those names to propagate the test
  description, test ID, baggage and the recursive sub-command marker to child processes and containers; a user-supplied
  value would shadow them and silently break test ID propagation.

### Where to look next

* Run [`event-generator suite explain`](event-generator_suite_explain.md) interactively to inspect any portion of the
  language, against the exact version of the binary in use.
* Read the [`samples/`](../samples) folder for working descriptions that exercise most of the features documented
  above.
