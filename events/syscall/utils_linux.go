// +build linux

package syscall

import (
	"os/exec"
	"os/user"
	"strconv"
	sys "syscall"

	"github.com/falcosecurity/event-generator/events"
	"golang.org/x/sys/unix"
)

// becameUser calls looks up the username UID then calls "setuid" syscall.
//
// IMPORTANT NOTE: the behavior is unpredicatable when used with goroutes.
// On linux, setuid only affects the current thread, not the process.
// Thus, becameUser may or not affect other goroutines.
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

	h.Log().WithField("uid", sys.Getuid()).
		WithField("euid", sys.Geteuid()).Debug("pre setuid")

	uuid := uint(uid)
	_, _, errno := unix.RawSyscall(unix.SYS_SETUID, uintptr(uuid), 0, 0)

	h.Log().WithError(errno).
		WithField("uid", sys.Getuid()).
		WithField("euid", sys.Geteuid()).Debug("post setuid")

	if errno != 0 {
		return errno
	}
	return nil
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
