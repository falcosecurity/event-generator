package helper

import (
	"net"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(NetworkActivity)

// NetworkActivity tries to connect to an andress.
func NetworkActivity(h events.Helper) error {
	conn, err := net.Dial("udp", "10.2.3.4:8192")
	defer conn.Close()
	return err
}
