# Test suite samples collection

This directory contains test suites description files that can be provided to the `event-generator suite` sub-commands.
Each file focuses on a single topic of the YAML description language. Overlap between samples is intentionally
minimised.

Notice that some of these files can be used with `event-generator suite run`, but not with `event-generator suite test`.

| File | Topic | Usable with `test`? |
| --- | --- | --- |
| [steps_syscall.yaml](./steps_syscall.yaml) | One example per supported system call, exercised against the corresponding `syscall` step. | No |
| [context_processes.yaml](./context_processes.yaml) | The `context.processes` chain: ancestors, users, capabilities on the leaf. | No |
| [context_container.yaml](./context_container.yaml) | The `context.container` block: running the test process chain inside a container. | No |
| [resources_clientserver.yaml](./resources_clientserver.yaml) | The `clientServer` resource with every supported transport protocol (`tcp4`, `tcp6`, `udp4`, `udp6`, `unix`) and binding to its exposed `client.fd` / `server.fd`. | No |
| [resources_fd.yaml](./resources_fd.yaml) | The `fd` resource with every supported subtype (`file`, `directory`, `pipe`, `event`, `signalfd`, `eventpoll`, `inotify`, `memfd`). | No |
| [resources_process.yaml](./resources_process.yaml) | The `process` resource and binding to its exposed `pid`. | No |
| [scripts.yaml](./scripts.yaml) | The `before` and `after` bash scripts that run around the test steps. | No |
| [templates.yaml](./templates.yaml) | Test case templating via the `cases` array (`vector` and `matrix` strategies). | No |
| [expected_outcome.yaml](./expected_outcome.yaml) | The `expectedOutcome` block consumed by `event-generator suite test`, in strict and loose forms. | Yes |
