package k8saudit

// disabled items will be registered with events.WithDisabled() option
var disabled = map[string]bool{
	"create-disallowed-pod.yaml": true,
}
