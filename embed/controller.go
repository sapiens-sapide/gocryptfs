package embed

import (
	"github.com/sapiens-sapide/gocryptfs/internal/syscallcompat"
	"github.com/sapiens-sapide/gocryptfs/internal/tlog"
	"os"
)

// redirectStdFds redirects stderr to provided fd and stdout and stdin to /dev/null
func redirectStdFds(errFd *os.File) {
	var err error
	// Redirect stderr to errFd
	syscallcompat.Dup3(int(errFd.Fd()), 2, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stderr dup error: %v\n", err)
	}
	// Our stout and stderr point to "pw". We can close the extra copy.
	// Redirect stdin and stdout to /dev/null
	nullFd, err := os.Open("/dev/null")
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not open /dev/null: %v\n", err)
		return
	}
	err = syscallcompat.Dup3(int(nullFd.Fd()), 1, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stdout dup error: %v\n", err)
	}
	err = syscallcompat.Dup3(int(nullFd.Fd()), 0, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stdin dup error: %v\n", err)
	}

	nullFd.Close()
}
