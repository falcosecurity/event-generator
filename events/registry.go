package events

import (
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

var registry = make(map[string]Action, 0)

func Register(f Action) map[string]Action {
	n := getFuncName(f)
	checkName(n)
	return RegisterWithName(f, n)
}

func RegisterWithName(f Action, name string) map[string]Action {
	checkName(name)
	registry[name] = f
	return registry
}

func checkName(n string) {
	if n == "" { // todo(leogr): check name format too
		panic("event name cannot be empty")
	}
	if _, ok := registry[n]; ok {
		panic("event name already registered: " + n)
	}
}

func getFuncName(f interface{}) string {
	pc := reflect.ValueOf(f).Pointer()
	rf := runtime.FuncForPC(pc)
	parts := strings.Split(rf.Name(), "/")
	return parts[len(parts)-1]
}

func All() map[string]Action {
	return registry
}

func ByRegexp(r *regexp.Regexp) map[string]Action {
	ret := make(map[string]Action, 0)
	for n, f := range registry {
		if r.MatchString(n) {
			ret[n] = f
		}
	}
	return ret
}

func ByPackage(packageName string) map[string]Action {
	ret := make(map[string]Action, 0)
	for n, f := range registry {
		parts := strings.Split(n, ".")
		if len(parts) > 0 && parts[0] == packageName {
			ret[n] = f
		}
	}
	return ret
}
