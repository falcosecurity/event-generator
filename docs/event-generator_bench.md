## event-generator bench

Benchmark for Falco

### Synopsis

Benchmark a running Falco instance.

This command generates a high number of Event Per Second (EPS), to test the events throughput allowed by Falco.
The number of EPS is controlled by the "--sleep" option: reduce the sleeping duration to increase the EPS.
If the "--loop" option is set, the sleeping duration is halved on each round.
The "--pid" option can be used to monitor the Falco process.

N.B.:

- the Falco HTTP Output must be enabled to use this command
- "outputs.rate" and "outputs.max_burst" values within the Falco configuration must be increased,
  otherwise EPS will be rate-limited by the throttling mechanism
- since not all actions can be used for benchmarking,
  only those actions matching the given regular expression are used

One commmon way to use this command is as following:

	event-generator bench "ChangeThreadNamespace|ReadSensitiveFileUntrusted" --all --loop --sleep 10ms --pid $(pidof -s falco)

Warning:
This command might alter your system. For example, some actions modify files and directories below
/bin, /etc, /dev, etc.
Make sure you fully understand what is the purpose of this tool before running any action.

```
event-generator bench [regexp] [flags]
```

### Options

```
      --all                                                   Run all actions, including those disabled by default
      --as string                                             Username to impersonate for the operation. User could be a regular user or a service account in a namespace.
      --as-group stringArray                                  Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --as-uid string                                         UID to impersonate for the operation.
      --cache-dir string                                      Default cache directory (default "/root/.kube/cache")
      --certificate-authority string                          Path to a cert file for the certificate authority
      --client-certificate string                             Path to a client certificate file for TLS
      --client-key string                                     Path to a client key file for TLS
      --cluster string                                        The name of the kubeconfig cluster to use
      --context string                                        The name of the kubeconfig context to use
      --disable-compression                                   If true, opt-out of response compression for all requests to the server
      --dry-run                                               Do not expose an HTTP server for Falco HTTP Output
  -h, --help                                                  help for bench
      --http-client-ca string                                 The path of the CA root certificate used for Falco HTTP client's certificate validation (to be used together with --http-server-security-mode=mtls) (default "/etc/falco/certs/ca.crt")
      --http-server-address string                            The address the alert retriever HTTP server must be bound to (default "localhost:8080")
      --http-server-cert string                               The path of the server certificate to be used for TLS against the Falco HTTP client (to be used together with --http-server-security-mode=(tls|mtls)) (default "/etc/falco/certs/server.crt")
      --http-server-key string                                The path of the server private key to be used for TLS against the Falco HTTP client (to be used together with --http-server-security-mode=(tls|mtls)) (default "/etc/falco/certs/server.key")
      --http-server-security-mode http-server-security-mode   The security mode the alert retriever HTTP server must use; can be 'insecure', 'tls' or 'mtls' (default insecure)
      --humanize                                              Humanize values when printing statistics (default true)
      --insecure-skip-tls-verify                              If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string                                     Path to the kubeconfig file to use for CLI requests.
      --loop                                                  Run in a loop
      --match-server-version                                  Require server version to match client version
  -n, --namespace string                                      If present, the namespace scope for this CLI request (default "default")
      --pid int                                               A process PID to monitor while benchmarking (e.g. the falco process)
      --request-timeout string                                The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
      --round-duration duration                               Duration of a benchmark round (default 5s)
  -s, --server string                                         The address and port of the Kubernetes API server
      --sleep duration                                        The length of time to wait before running an action. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means no sleep. (default 100ms)
      --tls-server-name string                                Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
      --token string                                          Bearer token for authentication to the API server
      --user string                                           The name of the kubeconfig user to use
```

### Options inherited from parent commands

```
  -c, --config string      Config file path (default $HOME/.falco-event-generator.yaml if exists)
      --logformat string   available formats: "text" or "json" (default "text")
  -l, --loglevel string    Log level (default "info")
```

### SEE ALSO

* [event-generator](event-generator.md)     - A command line tool to perform a variety of suspect actions.

