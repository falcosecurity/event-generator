package events

import (
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

var registry = make(map[string]Action, 0)

func Register(f Action) map[string]Action {
	registry[getFuncName(f)] = f
	return registry
}

func RegisterWithName(f Action, name string) map[string]Action {
	registry[name] = f
	return registry
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
