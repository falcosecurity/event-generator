## event-generator bench

Benchmark for Falco

### Synopsis

Benchmark a running Falco instance.

This command generates a high number of Event Per Second (EPS), to test the events throughput allowed by Falco.
The number of EPS is controlled by the "--sleep" option: reduce the sleeping duration to increase the EPS.
If the "--loop" option is set, the sleeping duration is halved on each round.
The "--pid" option can be used to monitor the Falco process. 
	
N.B.:
	- the Falco gRPC Output must be enabled to use this command
	- "outputs.rate" and "outputs.max_burst" values within the Falco configuration must be increased,
	  otherwise EPS will be rate-limited by the throttling mechanism
	- since not all actions can be used for benchmarking, 
	  only those actions matching the given regular expression are used

One commmon way to use this command is as following:

	event-generator bench "ChangeThreadNamespace|ReadSensitiveFileUntrusted" --loop --sleep 10ms --pid $(pidof -s falco) 



Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.


```
event-generator bench [regexp] [flags]
```

### Options

```
      --all                            Run all actions, including those disabled by default
      --as string                      Username to impersonate for the operation
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --cache-dir string               Default HTTP cache directory (default "$HOME/.kube/http-cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
      --grpc-ca string                 CA root file path for connecting to a Falco gRPC server (default "/etc/falco/certs/ca.crt")
      --grpc-cert string               Cert file path for connecting to a Falco gRPC server (default "/etc/falco/certs/client.crt")
      --grpc-hostname string           Hostname for connecting to a Falco gRPC server (default "localhost")
      --grpc-key string                Key file path for connecting to a Falco gRPC server (default "/etc/falco/certs/client.key")
      --grpc-port uint16               Port for connecting to a Falco gRPC server (default 5060)
      --grpc-unix-socket string        Unix socket path for connecting to a Falco gRPC server (default "unix:///var/run/falco.sock")
  -h, --help                           help for bench
      --humanize                       Humanize values when printing statistics (default true)
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
      --loop                           Run in a loop
      --match-server-version           Require server version to match client version
  -n, --namespace string               If present, the namespace scope for this CLI request (default "default")
      --pid int                        A process PID to monitor while benchmarking (e.g. the falco process)
      --polling-interval duration      Duration of gRPC APIs polling timeout (default 100ms)
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
      --round-duration duration        Duration of a benchmark round (default 5s)
  -s, --server string                  The address and port of the Kubernetes API server
      --sleep duration                 The length of time to wait before running an action. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means no sleep. (default 100ms)
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
```

### Options inherited from parent commands

```
  -c, --config string      Config file path (default $HOME/.falco-event-generator.yaml if exists)
      --logformat string   available formats: "text" or "json" (default "text")
  -l, --loglevel string    Log level (default "info")
```

### SEE ALSO

* [event-generator](event-generator.md)	 - A command line tool to perform a variety of suspect actions.

