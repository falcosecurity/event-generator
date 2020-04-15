## event-generator run

Run actions

### Synopsis

Performs a variety of suspect actions.
Without arguments it runs all actions, otherwise only those actions matching the given regular expression.

Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.


```
event-generator run [regexp] [flags]
```

### Options

```
      --as string                      Username to impersonate for the operation
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --cache-dir string               Default HTTP cache directory (default "$HOME/.kube/http-cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
  -h, --help                           help for run
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
      --match-server-version           Require server version to match client version
  -n, --namespace string               If present, the namespace scope for this CLI request (default "default")
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
  -s, --server string                  The address and port of the Kubernetes API server
      --sleep duration                 time to sleep prior to trigger an action
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
```

### Options inherited from parent commands

```
  -c, --config string     config file path (default $HOME/.falco-event-generator.yaml if exists)
  -l, --loglevel string   log level (default "info")
```

### SEE ALSO

* [event-generator](event-generator.md)	 - A command line tool to perform a variety of suspect actions.

