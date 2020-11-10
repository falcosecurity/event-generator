## event-generator list

List available actions

### Synopsis

Without arguments it lists all actions, otherwise only those actions matching the given regular expression.


```
event-generator list [regexp] [flags]
```

### Options

```
  -h, --help   help for list
```

### Options inherited from parent commands

```
  -c, --config string      Config file path (default $HOME/.falco-event-generator.yaml if exists)
      --logformat string   available formats: "text" or "json" (default "text")
  -l, --loglevel string    Log level (default "info")
```

### SEE ALSO

* [event-generator](event-generator.md)	 - A command line tool to perform a variety of suspect actions.

