# The events registry

This package is a place for registering and exposing actions which trigger security events. 
It implements a very *minimalistic framework* by using several conventions (see below).

## Conventions

An *action* is a `func` that implements `events.Action` interface, and when called it should trigger an event that can be caught by at least one Falco rule. The fully qualified name of an *action* is in the form `<package>.<FuncName>` (eg.`syscall.WriteBelowEtc`). Finally, to implement an action, you must meet the following conventions.

### Choose a package

- The package name should reflect the data source name of the ruleset (ie. `syscall`).
- Each *action* must be put in a subpackage of `events` that matches the ruleset context.
- The `helper` subpackage is intended for actions that do not match a rule but can still be useful for implementing other actions.
- Before adding a new subpackage, propose your motivations to the maintainers.

#### Functions visibility

Only `func`s that implement the `events.Action` interface must be exported by a package. Other utility functions can be included, if needed, stating they are not exported names (a notable example is [syscall/utils_linux.go](https://github.com/falcosecurity/event-generator/blob/main/events/syscall/utils_linux.go)).

### Naming

- Use the name of the rule the action is intended for, remove all non-alphanumeric characters (eg. `s/[^([:alpha:]|[:digit:]]//g`), and convert it to:
    - *CamelCase* for function name (eg. `WriteBelowEtc`),
    - *underscore_case* for file name (eg. `write_below_etc.go`), alternativelly *dash-case* is acceptable to for file types other than `.go` (eg. `create-privileged-pod.yaml`).
- The resulting action name must match the name of the rule stripped of all non-alphanumeric characters when comparing those strings in a case insensitive manner.

### Registration

Each action must be registered by calling `events.Register()` or `events.RegisterWithName()` at initialization time, the first one will automatically extracts the name from the `func`'s name. For example:

```golang
var _ = events.Register(SystemUserInteractive)
```

Rules disabled by default or not included in the *stable* ruleset (if the [Rules Maturity Framework applies) must be skipped by default. For example:

```golang
var _ = events.Register(
	WriteBelowEtc,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)
```

### Handling Unsupported Contexts/Prerequisites

When developing actions for the event-generator, it's essential to consider whether the action is applicable to the current execution context. For example, certain actions might be intended to run exclusively within containers or specific environments. Actions that require a specific context or prerequisite to execute successfully should skip the action by return events.ErrSkipped when the necessary conditions are not met For example:

```golang
func UserMgmtBinaries(h events.Helper) error { 
 	if h.InContainer() { 
 		return &events.ErrSkipped{ 
 			Reason: "'User mgmt binaries' is excluded in containers", 
 		} 
 	} 
	return h.SpawnAsWithSymlink("vipw", "helper.ExecLs") 
} 
```

### Behavior
Running an *action* should be an idempotent operation in the sense that it should not have additional effects if it is called more than once.
For this reason, *actions* should revert any operation that changed the state of the system (eg. if a file is created, then it has to be removed). For example:

```golang
func WriteBelowEtc(h events.Helper) error {
	const filename = "/etc/created-by-event-generator"
	h.Log().Infof("writing to %s", filename)
	defer os.Remove(filename) // clean up here!!!
	return os.WriteFile(filename, nil, os.FileMode(0755))
}
```

## The k8saudit YAML loader

The `k8saudit` collection includes a facilitator for implementing *actions* that ones of just need to create K8s resources.

Basically, all files within the [./k8saudit/yaml/](https://github.com/falcosecurity/event-generator/tree/main/events/k8saudit/yaml) folder will be embedded into the binary at build time, then [yaml_loader.go](https://github.com/falcosecurity/event-generator/blob/main/events/k8saudit/yaml_loader.go) will automatically create and register an *action* for each of those at initialization time.


## Usage

Although the easiest way to use the registry is by using the provided CLI, it can be also used as a standalone package:

```golang
import (
	// register event collections you what to use
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"

	"github.com/falcosecurity/event-generator/events"
)
```

Then you can retrieve actions by one of:

```golang

// return all registered actions
events.All()


// return all registered actions starting with syscall.Write
reg, _ := regexp.Compile(`syscall.Write`)
events.ByRegexp(reg)

// return all registered actions within the k8saudit collection
events.ByPackage("k8saudit")
```

Finally, to call an *action* you need a runner. The default runner implementation is [here](https://github.com/falcosecurity/event-generator/tree/master/pkg/runner).


