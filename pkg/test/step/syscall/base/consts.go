package base

import "golang.org/x/sys/unix"

var openFlags = map[string]int{
	"O_ACCMODE":   unix.O_ACCMODE,
	"O_RDONLY":    unix.O_RDONLY,
	"O_WRONLY":    unix.O_WRONLY,
	"O_RDWR":      unix.O_RDWR,
	"O_APPEND":    unix.O_APPEND,
	"O_ASYNC":     unix.O_ASYNC,
	"O_CLOEXEC":   unix.O_CLOEXEC,
	"O_CREAT":     unix.O_CREAT,
	"O_DIRECT":    unix.O_DIRECT,
	"O_DIRECTORY": unix.O_DIRECTORY,
	"O_DSYNC":     unix.O_DSYNC,
	"O_EXCL":      unix.O_EXCL,
	"O_FSYNC":     unix.O_FSYNC,
	"O_LARGEFILE": unix.O_LARGEFILE,
	"O_NDELAY":    unix.O_NDELAY,
	"O_NOATIME":   unix.O_NOATIME,
	"O_NOCTTY":    unix.O_NOCTTY,
	"O_NOFOLLOW":  unix.O_NOFOLLOW,
	"O_NONBLOCK":  unix.O_NONBLOCK,
	"O_PATH":      unix.O_PATH,
	"O_RSYNC":     unix.O_RSYNC,
	"O_SYNC":      unix.O_SYNC,
	"O_TMPFILE":   unix.O_TMPFILE,
	"O_TRUNC":     unix.O_TRUNC,
}

var openModes = map[string]int{
	"S_IRWXU": unix.S_IRWXU, // user has read, write, and execute permission
	"S_IRUSR": unix.S_IRUSR, // user has read permission
	"S_IWUSR": unix.S_IWUSR, // user has write permission
	"S_IXUSR": unix.S_IXUSR, // user has execute permission
	"S_IRWXG": unix.S_IRWXG, // group has read, write, and execute permission
	"S_IRGRP": unix.S_IRGRP, // group has read permission
	"S_IWGRP": unix.S_IWGRP, // group has write permission
	"S_IXGRP": unix.S_IXGRP, // group has execute permission
	"S_IRWXO": unix.S_IRWXO, // others have read, write, and execute permission
	"S_IROTH": unix.S_IROTH, // others have read permission
	"S_IWOTH": unix.S_IWOTH, // others have write permission
	"S_IXOTH": unix.S_IXOTH, // others have execute permission
	"S_ISUID": unix.S_ISUID, // set-user-ID bit
	"S_ISGID": unix.S_ISGID, // set-group-ID bit (see inode(7)).
	"S_ISVTX": unix.S_ISVTX, // sticky bit (see inode(7)).
}
