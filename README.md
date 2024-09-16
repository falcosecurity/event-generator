
# event-generator
[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating)

[![Release](https://img.shields.io/github/release/falcosecurity/event-generator.svg?style=flat-square)](https://github.com/falcosecurity/event-generator/releases/latest)
[![License](https://img.shields.io/github/license/falcosecurity/event-generator?style=flat-square)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/falcosecurity/event-generator?style=flat-square)](https://goreportcard.com/report/github.com/falcosecurity/event-generator)
[![Docker pulls](https://img.shields.io/docker/pulls/falcosecurity/event-generator?style=flat-square)](https://hub.docker.com/r/falcosecurity/event-generator)
![Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64-blueviolet?style=flat-square)

Generate a variety of suspect actions that are detected by Falco rulesets.

**Warning** — We strongly recommend that you run the program within Docker (see below), since some commands might alter your system. 
    For example, some actions modify files and directories below /bin, /etc, /dev, etc.
    Make sure you fully understand what is the purpose of this tool before running any action.

**Notice** — From version `v0.11.0` the `event-generator` requires Falco 0.37.0 or newer. Previous versions of the `event-generator` might be compatible with older versions of Falco, however, we do not guarantee it.

## Usage

The full command line documentation is [here](./docs/event-generator.md).

### List actions

```shell
$ event-generator list --all

helper.ExecLs
helper.NetworkActivity
helper.RunShell
k8saudit.ClusterRoleWithPodExecCreated
k8saudit.ClusterRoleWithWildcardCreated
k8saudit.ClusterRoleWithWritePrivilegesCreated
k8saudit.CreateDisallowedPod
k8saudit.CreateHostNetworkPod
k8saudit.CreateModifyConfigmapWithPrivateCredentials
k8saudit.CreateNodePortService
k8saudit.CreatePrivilegedPod
k8saudit.CreateSensitiveMountPod
k8saudit.K8SConfigMapCreated
k8saudit.K8SDeploymentCreated
k8saudit.K8SServiceCreated
k8saudit.K8SServiceaccountCreated
syscall.ChangeThreadNamespace
syscall.CreateFilesBelowDev
syscall.CreateSymlinkOverSensitiveFiles
syscall.DbProgramSpawnedProcess
syscall.DirectoryTraversalMonitoredFileRead
syscall.MkdirBinaryDirs
syscall.ModifyBinaryDirs
syscall.NonSudoSetuid
syscall.ReadSensitiveFileTrustedAfterStartup
syscall.ReadSensitiveFileUntrusted
syscall.RunShellUntrusted
syscall.ScheduleCronJobs
syscall.SearchPrivateKeysOrPasswords
syscall.SystemProcsNetworkActivity
syscall.SystemUserInteractive
syscall.UserMgmtBinaries
syscall.WriteBelowBinaryDir
syscall.WriteBelowEtc
syscall.WriteBelowRpmDatabase
```

### Run actions
```
event-generator run [regexp]
```
Without arguments, it runs all actions; otherwise, only those actions match the given regular expression.

For example, to run only those actions containing the word `Files` in their name:

```shell
$ sudo event-generator run syscall\.\*Files\.\*

INFO sleep for 100ms                               action=syscall.ReadSensitiveFileUntrusted
INFO action executed                               action=syscall.ReadSensitiveFileUntrusted
INFO sleep for 100ms                               action=syscall.CreateSymlinkOverSensitiveFiles
INFO action executed                               action=syscall.CreateSymlinkOverSensitiveFiles
INFO sleep for 100ms                               action=syscall.DirectoryTraversalMonitoredFileRead
INFO action executed                               action=syscall.DirectoryTraversalMonitoredFileRead
INFO sleep for 100ms                               action=syscall.ReadSensitiveFileTrustedAfterStartup
INFO spawn as "httpd"                              action=syscall.ReadSensitiveFileTrustedAfterStartup args="^syscall.ReadSensitiveFileUntrusted$ --sleep 6s"
INFO sleep for 6s                                  action=syscall.ReadSensitiveFileUntrusted as=httpd
INFO action executed                               action=syscall.ReadSensitiveFileUntrusted as=httpd
```

Useful options:
- `--loop` to run actions in a loop
- `--sleep` to set the length of time to wait before running an action (default to `100ms`)

Also, note that not all actions are enabled by default. To run all actions, use the `--all` option.

Further options are documented [here](./docs/event-generator_run.md).


#### With Docker

Run all events with the Docker image locally:

```shell
docker run -it --rm falcosecurity/event-generator run
```


#### With Kubernetes

It can be deployed in a Kubernetes cluster using the event-generator [helm chart](https://github.com/falcosecurity/charts/tree/master/charts/event-generator).
Before installing the chart, add the `falcosecurity` charts repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Run all events once using a Kubernetes job:

```shell
helm install event-generator falcosecurity/event-generator \
  --namespace event-generator \
  --create-namespace \
  --set config.loop=false \
  --set config.actions=""
```

Run all events in a loop using a Kubernetes deployment:

```bash
helm install event-generator falcosecurity/event-generator \
  --namespace event-generator \
  --create-namespace \
  --set config.actions=""
```


**N.B.**
The above commands apply to the `event-generator` namespace. Use a different name to use a different namespace. It will generate events in the same namespace.

## Collections

### Generate System Call activity
The `syscall` collection performs a variety of suspect actions detected by the [default Falco ruleset](https://github.com/falcosecurity/rules/tree/main/rules).

```shell
$ docker run -it --rm falcosecurity/event-generator run syscall --loop
```

The above command loops forever, incessantly generating a sample event every 100 miliseconds. 


### Generate activity for the k8s audit rules
The `k8saudit` collection generates activity that matches the [k8s audit event ruleset](https://github.com/falcosecurity/plugins/blob/master/plugins/k8saudit/rules/k8s_audit_rules.yaml).

Note that all `k8saudit` are disabled by default. To enable them, use the `--all` option.

```shell
$ event-generator run k8saudit --all --loop --namespace `falco-eg-sandbox`
```
> N.B.: the namespace must exist already.

The above command loops forever, creating resources in the `falco-eg-sandbox` namespace and deleting the after each iteration.

**N.B.**
- the namespace must already exist
- to produce any effect the Kubernetes audit log must be enabled, see [here](https://falco.org/docs/event-sources/kubernetes-audit/)


## Test rules

Since `v0.4.0`, this tool introduces a convenient integration test suite for Falco rules. The `event-generator test` command can run actions and test them against a running Falco instance.

> This feature requires Falco 0.24.0 or newer. Before using the command below, you need [Falco installed](https://falco.org/docs/installation/) and running with the [gRPC Output](https://falco.org/docs/grpc/) enabled.

#### Test locally (`syscall` only)

Run the following command to test `syscall` actions on a local Falco instance (connects via Unix socket to `/run/falco/falco.sock` by default):

```shell
sudo ./event-generator test syscall
```

#### Test on Kubernetes

Before running the following commands make sure you have added the `falcosecurity` charts repository as explained [here](#with-kubernetes).

Test all events once using a Kubernetes job:

```shell
helm install event-generator falcosecurity/event-generator \
  --namespace event-generator \
  --create-namespace \
  --set config.command=test \
  --set config.loop=false \
  --set config.actions=""
```

Test all events in a loop using a Kubernetes deployment:

```bash
helm install event-generator falcosecurity/event-generator \
  --namespace event-generator \
  --create-namespace \
  --set config.command=test \
  --set config.actions=""
```

Note that to test `k8saudit` events, you need _Kubernetes Audit Log_ functionality enabled in Kubernetes and the [k8saudit plugin](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) in Falco.

## Benchmark

Since `v0.5.0`, the `event-generator` can also be used for benchmarking a running instance of Falco. The command `event-generator bench` generates a high number of Event Per Second (EPS) to show you events throughput allowed by your Falco installation.

Be aware that before Falco 0.37 a rate-limiter for notifications that affects the gRPC Outputs APIs was present. You probably need to increase the `outputs.rate` and `outputs.max_burst` values [within the Falco configuration](https://github.com/falcosecurity/falco/blob/e2bf87d207a32401da271835e15dadf957f68e8c/falco.yaml#L90-L104), otherwise EPS will be rate-limited by the throttling mechanism. 

### Run a benchmark

Before starting a benchmark, the most important thing to understand is that the `--sleep` option controls the number of EPS (default to `250ms`): reducing this value will increase the EPS. Furthermore, if the `--loop` option is set, the sleeping duration is automatically halved on each round. The `--pid` option can be used to monitor the Falco process. 

> You can find more details about the command-line usage [here](docs/event-generator_bench.md).

Please, keep in mind that not all actions can be used for benchmarking since some of them take too long to generate a high number of EPS. For example, `k8saudit` actions are not supposed to work, since those actions need some time to create Kubernetes resources. Also, some `syscall` actions sleep for a while (like the [syscall.ReadSensitiveFileUntrusted](https://github.com/falcosecurity/event-generator/blob/7bf714aab8da5a3f6d930225f04852e97d682dac/events/syscall/read_sensitive_file_trusted_after_startup.go#L10)) thus cannot be used.

**Benchmark example**

A common way for benchmarking a local Falco instance is by running the following command (that connects via Unix socket to `/run/falco/falco.sock` by default):

```shell
sudo event-generator bench "ChangeThreadNamespace|ReadSensitiveFileUntrusted" --all --loop --sleep 10ms --pid $(pidof -s falco)
```

## FAQ

### What sample events can this tool generate?
See the [events registry](https://github.com/falcosecurity/event-generator/tree/main/events).

### Can I contribute by adding new events?
Sure! 

Check out the [events registry](https://github.com/falcosecurity/event-generator/tree/main/events) conventions, then feel free to open a PR!

Your contribution is highly appreciated.

### Can I use this project as a library?
This project provides three main packages that can be imported and used separately:

- `/cmd` contains the CLI implementation
- `/events` contains the events registry
- `/pkg/runner` contains the actions runner implementations

Feel free to use them as you like on your projects.

## Acknowledgments

Special thanks to Mark Stemm (**@mstemm**) — the author of the [first event generator](https://github.com/falcosecurity/falco/tree/2126616529e7015ff88653b7491dc1937d7e54e5/docker/event-generator).
