## event-generator test

Run and test actions

### Synopsis

Performs a variety of suspect actions and test them against a running Falco instance.

Note that the Falco gRPC Output must be enabled to use this command.
Without arguments it tests all actions, otherwise only those actions matching the given regular expression.


Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.


```
event-generator test [regexp] [flags]
```

### Options

```
      --all                            Run all actions, including those disabled by default
      --as string                      Username to impersonate for the operation. User could be a regular user or a service account in a namespace.
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --as-uid string                  UID to impersonate for the operation.
      --cache-dir string               Default cache directory (default "$HOME/.kube/http-cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
      --disable-compression            If true, opt-out of response compression for all requests to the server
      --grpc-ca string                 CA root file path for connecting to a Falco gRPC server (default "/etc/falco/certs/ca.crt")
      --grpc-cert string               Cert file path for connecting to a Falco gRPC server (default "/etc/falco/certs/client.crt")
      --grpc-hostname string           Hostname for connecting to a Falco gRPC server (default "localhost")
      --grpc-key string                Key file path for connecting to a Falco gRPC server (default "/etc/falco/certs/client.key")
      --grpc-port uint16               Port for connecting to a Falco gRPC server (default 5060)
      --grpc-unix-socket string        Unix socket path for connecting to a Falco gRPC server (default "unix:///run/falco/falco.sock")
  -h, --help                           help for test
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
      --loop                           Run in a loop
      --match-server-version           Require server version to match client version
  -n, --namespace string               If present, the namespace scope for this CLI request (default "default")
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
  -s, --server string                  The address and port of the Kubernetes API server
      --sleep duration                 The length of time to wait before running an action. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means no sleep. (default 100ms)
      --test-timeout duration          Test duration timeout (default 1m0s)
      --tls-server-name string         Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
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

