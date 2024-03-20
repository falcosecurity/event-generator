package syscall

import (
    "os/exec"

    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(InterpretedProcsInboundNetworkActivity)

func InterpretedProcsInboundNetworkActivity(h events.Helper) error {
    // Python script to perform inbound network activity
    pythonScript := `
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 8000))
server_socket.listen(1)

print("Server is listening on port 8000")

client_socket, addr = server_socket.accept()
print(f"Received connection from {addr}")

data = client_socket.recv(1024)
print(f"Received data: {data.decode()}")

client_socket.close()
server_socket.close()
`

    cmd := exec.Command("python3", "-c", pythonScript)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return err
    }

    h.Log().Infof("Interpreted program received/listened for network traffic")
    h.Log().Infof("Python script output:\n%s", output)

    return nil
}