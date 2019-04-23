package embed

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sapiens-sapide/gocryptfs/internal/configfile"
	"github.com/sapiens-sapide/gocryptfs/internal/cryptocore"
	"github.com/sapiens-sapide/gocryptfs/internal/exitcodes"
	"github.com/sapiens-sapide/gocryptfs/internal/nametransform"
	"github.com/sapiens-sapide/gocryptfs/internal/readpassword"
	"github.com/sapiens-sapide/gocryptfs/internal/syscallcompat"
	"github.com/sapiens-sapide/gocryptfs/internal/tlog"
)
// TODO
var GitVersion = "[GitVersion not set - please compile using ./build.bash]"

// isDirEmpty checks if "dir" exists and is an empty directory.
// Returns an *os.PathError if Stat() on the path fails.
func isDirEmpty(dir string) error {
	err := isDir(dir)
	if err != nil {
		return err
	}
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	return fmt.Errorf("directory %s not empty", dir)
}

// isDir checks if "dir" exists and is a directory.
func isDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// initDir prepares a directory for use as a
// gocryptfs storage directory.
// This means creating the gocryptfs.conf and gocryptfs.diriv
// files in an empty directory.
func initDir() {
	var err error
	if options.reverse {
		_, err = os.Stat(options.config)
		if err == nil {
			tlog.Fatal.Printf("Config file %q already exists", options.config)
			os.Exit(exitcodes.Init)
		}
	} else {
		err = isDirEmpty(options.cipherdir)
		if err != nil {
			tlog.Fatal.Printf("Invalid cipherdir: %v", err)
			os.Exit(exitcodes.Init)
		}
	}
	// Choose password for config file
	if options.extpass.Empty() {
		tlog.Info.Printf("Choose a password for protecting your files.")
	}
	{
		var password []byte
		var trezorPayload []byte
		if options.trezor {
			trezorPayload = cryptocore.RandBytes(readpassword.TrezorPayloadLen)
			// Get binary data from from Trezor
			password = readpassword.Trezor(trezorPayload)
		} else {
			// Normal password entry
			password = readpassword.Twice([]string(options.extpass), options.passfile)
		}
		creator := tlog.ProgramName + " " + GitVersion
		err = configfile.Create(options.config, password, options.plaintextnames,
			options.scryptn, creator, options.aessiv, options.devrandom, trezorPayload)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.WriteConf)
		}
		for i := range password {
			password[i] = 0
		}
		// password runs out of scope here
	}
	// Forward mode with filename encryption enabled needs a gocryptfs.diriv file
	// in the root dir
	if !options.plaintextnames && !options.reverse {
		// Open cipherdir (following symlinks)
		dirfd, err := syscall.Open(options.cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err == nil {
			err = nametransform.WriteDirIVAt(dirfd)
			syscall.Close(dirfd)
		}
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.Init)
		}
	}
	mountArgs := ""
	fsName := "gocryptfs"
	if options.reverse {
		mountArgs = " -reverse"
		fsName = "gocryptfs-reverse"
	}
	tlog.Info.Printf(tlog.ColorGreen+"The %s filesystem has been created successfully."+tlog.ColorReset,
		fsName)
	wd, _ := os.Getwd()
	friendlyPath, _ := filepath.Rel(wd, options.cipherdir)
	if strings.HasPrefix(friendlyPath, "../") {
		// A relative path that starts with "../" is pretty unfriendly, just
		// keep the absolute path.
		friendlyPath = options.cipherdir
	}
	if strings.Contains(friendlyPath, " ") {
		friendlyPath = "\"" + friendlyPath + "\""
	}
	tlog.Info.Printf(tlog.ColorGrey+"You can now mount it using: %s%s %s MOUNTPOINT"+tlog.ColorReset,
		tlog.ProgramName, mountArgs, friendlyPath)
}
