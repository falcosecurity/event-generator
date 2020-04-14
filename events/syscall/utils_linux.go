// +build linux

package syscall

import (
	"os/exec"
	"os/user"
	"strconv"
	sys "syscall"

	"github.com/falcosecurity/event-generator/events"
)

func becameUser(h events.Helper, username string) error {
	h.Log().WithField("user", username).
		Info("became user")

	u, err := user.Lookup(username)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	return sys.Setuid(uid)
}

func runAsUser(h events.Helper, username string, cmdName string, cmdArgs ...string) error {
	h.Log().WithField("user", username).
		WithField("cmdName", cmdName).
		WithField("cmdArgs", cmdArgs).
		Info("run command as another user")

	u, err := user.Lookup(username)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &sys.SysProcAttr{}
	cmd.SysProcAttr.Credential = &sys.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}
	return cmd.Run()
}
