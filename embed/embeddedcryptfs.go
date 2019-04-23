// Package embed provides interfaces to embed gocryptfs in an application
package embed

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/sapiens-sapide/gocryptfs/internal/configfile"
	"github.com/sapiens-sapide/gocryptfs/internal/contentenc"
	"github.com/sapiens-sapide/gocryptfs/internal/cryptocore"
	"github.com/sapiens-sapide/gocryptfs/internal/ctlsock"
	"github.com/sapiens-sapide/gocryptfs/internal/exitcodes"
	"github.com/sapiens-sapide/gocryptfs/internal/fusefrontend"
	"github.com/sapiens-sapide/gocryptfs/internal/fusefrontend_reverse"
	"github.com/sapiens-sapide/gocryptfs/internal/nametransform"
	"github.com/sapiens-sapide/gocryptfs/internal/openfiletable"
	"github.com/sapiens-sapide/gocryptfs/internal/tlog"
)

var options *gocryptfsOptions

type EmbedOptions struct {
	CipherDir  string
	MasterKey  string // 32 bytes hex encoded if no password provided
	MountPoint string
	Password   *string
}

// should return an error and a chan to control ?
func MountCryptFS(opts EmbedOptions, errFd *os.File, controller chan string) error {
	err := setDefaults(opts)
	if err != nil {
		return err
	}
	errChan := make(chan error)
	go doMount(opts.Password, errChan, errFd, controller)
	return <-errChan
}

type multipleStrings []string

func (s *multipleStrings) Empty() bool {
	s2 := []string(*s)
	return len(s2) == 0
}

func setDefaults(opts EmbedOptions) error {
	var err error
	options = new(gocryptfsOptions)

	// Check that CIPHERDIR exists
	options.cipherdir, _ = filepath.Abs(opts.CipherDir)
	err = isDir(options.cipherdir)
	if err != nil {
		return fmt.Errorf("Invalid cipherdir: %v", err)
	}

	// cipherdir config
	options.config = filepath.Join(options.cipherdir, configfile.ConfDefaultName)

	options.mountpoint, err = filepath.Abs(opts.MountPoint)
	if err != nil {
		return fmt.Errorf("Invalid mountpoint: %v", err)
	}

	options.masterkey = opts.MasterKey

	// by default we do not want a useless plain directory mounted too long
	// TODO : hack expiration handling
	options.idle = 1 * time.Minute
	return nil
}

type gocryptfsOptions struct {
	debug, init, zerokey, fusedebug, openssl, passwd, fg, version,
	plaintextnames, quiet, nosyslog, wpanic,
	longnames, allow_other, reverse, aessiv, nonempty, raw64,
	noprealloc, speed, hkdf, serialize_reads, forcedecode, hh, info,
	sharedstorage, devrandom, fsck, trezor bool
	// Mount options with opposites
	dev, nodev, suid, nosuid, exec, noexec, rw, ro bool
	masterkey, mountpoint, cipherdir, cpuprofile,
	memprofile, ko, passfile, ctlsock, fsname, force_owner, trace string
	// -extpass can be passed multiple times
	extpass multipleStrings
	// For reverse mode, several ways to specify exclusions. All can be specified multiple times.
	exclude, excludeWildcard, excludeFrom multipleStrings
	// Configuration file name override
	config             string
	notifypid, scryptn int
	// Idle time before autounmount
	idle time.Duration
	// Helper variables that are NOT cli options all start with an underscore
	// _configCustom is true when the user sets a custom config file name.
	_configCustom bool
	// _ctlsockFd stores the control socket file descriptor (ctlsock stores the path)
	_ctlsockFd net.Listener
	// _forceOwner is, if non-nil, a parsed, validated Owner (as opposed to the string above)
	_forceOwner *fuse.Owner
}

// doMount mounts an encrypted directory.
func doMount(password *string, errChan chan error, errFd *os.File, controller chan string) {
	// Check mountpoint
	var err error

	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if options.cipherdir == options.mountpoint || strings.HasPrefix(options.cipherdir, options.mountpoint+"/") {
		errChan <- fmt.Errorf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			options.mountpoint, options.cipherdir)
		close(errChan)
		return
	}
	// Reverse-mounting "/foo" at "/foo/mnt" means we would be recursively
	// encrypting ourselves.
	if strings.HasPrefix(options.mountpoint, options.cipherdir+"/") {
		errChan <- fmt.Errorf("Mountpoint %q is contained in cipherdir %q, this is not supported",
			options.mountpoint, options.cipherdir)
		close(errChan)
		return
	}
	if options.nonempty {
		err = isDir(options.mountpoint)
	} else {
		err = isDirEmpty(options.mountpoint)
		// OSXFuse will create the mountpoint for us ( https://github.com/rfjakob/gocryptfs/issues/194 )
		if runtime.GOOS == "darwin" && os.IsNotExist(err) {
			tlog.Info.Printf("Mountpoint %q does not exist, but should be created by OSXFuse",
				options.mountpoint)
			err = nil
		}
	}
	if err != nil {
		errChan <- fmt.Errorf("Invalid mountpoint: %v", err)
		close(errChan)
		return
	}
	// Open control socket early so we can error out before asking the user
	// for the password
	if options.ctlsock != "" {
		// We must use an absolute path because we cd to / when daemonizing.
		// This messes up the delete-on-close logic in the unix socket object.
		options.ctlsock, _ = filepath.Abs(options.ctlsock)
		var sock net.Listener
		sock, err = net.Listen("unix", options.ctlsock)
		if err != nil {
			errChan <- fmt.Errorf("ctlsock: %v", err)
			close(errChan)
			return
		}
		options._ctlsockFd = sock
		// Close also deletes the socket file
		defer func() {
			err = sock.Close()
			if err != nil {
				tlog.Warn.Printf("ctlsock close: %v", err)
			}
		}()
	}
	// Initialize gocryptfs (read config file, ask for password, ...)
	fs, wipeKeys := initFuseFrontend(password)
	// Initialize go-fuse FUSE server
	srv := initGoFuse(fs)
	// Try to wipe secret keys from memory after unmount
	defer wipeKeys()

	tlog.Info.Println(tlog.ColorGreen + "Filesystem mounted and ready." + tlog.ColorReset)

	redirectStdFds(errFd)
	// Increase the open file limit to 4096. This is not essential, so do it after
	// we have switched to syslog and don't bother the user with warnings.
	setOpenFileLimit()
	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, options.mountpoint)
	// listen to orders send by caller
	handleController(controller, srv, options.mountpoint)
	// Return memory that was allocated for scrypt (64M by default!) and other
	// stuff that is no longer needed to the OS
	debug.FreeOSMemory()
	// Set up autounmount, if requested.
	if options.idle > 0 && !options.reverse {
		// Not being in reverse mode means we always have a forward file system.
		fwdFs := fs.(*fusefrontend.FS)
		go idleMonitor(options.idle, fwdFs, srv, options.mountpoint)
	}
	// no error until here, signal caller
	errChan <- nil
	close(errChan)

	// Jump into server loop. Returns when it gets an umount request
	srv.Serve()
}

// Based on the EncFS idle monitor:
// https://github.com/vgough/encfs/blob/1974b417af189a41ffae4c6feb011d2a0498e437/encfs/main.cpp#L851
// idleMonitor is a function to be run as a thread that checks for
// filesystem idleness and unmounts if we've been idle for long enough.
const checksDuringTimeoutPeriod = 4

func idleMonitor(idleTimeout time.Duration, fs *fusefrontend.FS, srv *fuse.Server, mountpoint string) {
	sleepTimeBetweenChecks := contentenc.MinUint64(
		uint64(idleTimeout/checksDuringTimeoutPeriod),
		uint64(2*time.Minute))
	timeoutCycles := int(math.Ceil(float64(idleTimeout) / float64(sleepTimeBetweenChecks)))
	idleCount := 0
	for {
		// Atomically check whether the access flag is set and reset it to 0 if so.
		recentAccess := atomic.CompareAndSwapUint32(&fs.AccessedSinceLastCheck, 1, 0)
		// Any form of current or recent access resets the idle counter.
		openFileCount := openfiletable.CountOpenFiles()
		if recentAccess || openFileCount > 0 {
			idleCount = 0
		} else {
			idleCount++
		}
		tlog.Debug.Printf(
			"Checking for idle (recentAccess = %t, open = %d): %s",
			recentAccess, openFileCount, time.Now().String())
		if idleCount > 0 && idleCount%timeoutCycles == 0 {
			tlog.Info.Printf("Filesystem idle; unmounting: %s", mountpoint)
			unmount(srv, mountpoint)
		}
		time.Sleep(time.Duration(sleepTimeBetweenChecks))
	}
}

// setOpenFileLimit tries to increase the open file limit to 4096 (the default hard
// limit on Linux).
func setOpenFileLimit() {
	var lim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	if err != nil {
		tlog.Warn.Printf("Getting RLIMIT_NOFILE failed: %v", err)
		return
	}
	if lim.Cur >= 4096 {
		return
	}
	lim.Cur = 4096
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	if err != nil {
		tlog.Warn.Printf("Setting RLIMIT_NOFILE to %+v failed: %v", lim, err)
		//         %+v output: "{Cur:4097 Max:4096}" ^
	}
}

// ctlsockFs satisfies both the pathfs.FileSystem and the ctlsock.Interface
// interfaces
type ctlsockFs interface {
	pathfs.FileSystem
	ctlsock.Interface
}

// initFuseFrontend - initialize gocryptfs/fusefrontend
// Calls os.Exit on errors
func initFuseFrontend(password *string) (pfs pathfs.FileSystem, wipeKeys func()) {
	masterkey, confFile := getMasterKey(password)
	// Reconciliate CLI and config file arguments into a fusefrontend.Args struct
	// that is passed to the filesystem implementation
	cryptoBackend := cryptocore.BackendGoGCM
	if options.openssl {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	if options.aessiv {
		cryptoBackend = cryptocore.BackendAESSIV
	}
	// forceOwner implies allow_other, as documented.
	// Set this early, so options.allow_other can be relied on below this point.
	if options._forceOwner != nil {
		options.allow_other = true
	}
	frontendArgs := fusefrontend.Args{
		Cipherdir:       options.cipherdir,
		PlaintextNames:  options.plaintextnames,
		LongNames:       options.longnames,
		ConfigCustom:    options._configCustom,
		NoPrealloc:      options.noprealloc,
		SerializeReads:  options.serialize_reads,
		ForceDecode:     options.forcedecode,
		ForceOwner:      options._forceOwner,
		Exclude:         options.exclude,
		ExcludeWildcard: options.excludeWildcard,
		ExcludeFrom:     options.excludeFrom,
	}
	// confFile is nil when "-zerokey" or "-masterkey" was used
	if confFile != nil {
		// Settings from the config file override command line args
		frontendArgs.PlaintextNames = confFile.IsFeatureFlagSet(configfile.FlagPlaintextNames)
		options.raw64 = confFile.IsFeatureFlagSet(configfile.FlagRaw64)
		options.hkdf = confFile.IsFeatureFlagSet(configfile.FlagHKDF)
		if confFile.IsFeatureFlagSet(configfile.FlagAESSIV) {
			cryptoBackend = cryptocore.BackendAESSIV
		} else if options.reverse {
			tlog.Fatal.Printf("AES-SIV is required by reverse mode, but not enabled in the config file")
			os.Exit(exitcodes.Usage)
		}
	}
	// If allow_other is set and we run as root, try to give newly created files to
	// the right user.
	if options.allow_other && os.Getuid() == 0 {
		frontendArgs.PreserveOwner = true
	}
	jsonBytes, _ := json.MarshalIndent(frontendArgs, "", "\t")
	tlog.Debug.Printf("frontendArgs: %s", string(jsonBytes))

	// Init crypto backend
	cCore := cryptocore.New(masterkey, cryptoBackend, contentenc.DefaultIVBits, options.hkdf, options.forcedecode)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS, options.forcedecode)
	nameTransform := nametransform.New(cCore.EMECipher, frontendArgs.LongNames, options.raw64)
	// After the crypto backend is initialized,
	// we can purge the master key from memory.
	for i := range masterkey {
		masterkey[i] = 0
	}
	masterkey = nil
	// Spawn fusefrontend
	var fs ctlsockFs
	if options.reverse {
		if cryptoBackend != cryptocore.BackendAESSIV {
			log.Panic("reverse mode must use AES-SIV, everything else is insecure")
		}
		fs = fusefrontend_reverse.NewFS(frontendArgs, cEnc, nameTransform)

	} else {
		fs = fusefrontend.NewFS(frontendArgs, cEnc, nameTransform)
	}
	// We have opened the socket early so that we cannot fail here after
	// asking the user for the password
	if options._ctlsockFd != nil {
		go ctlsock.Serve(options._ctlsockFd, fs)
	}
	return fs, func() { cCore.Wipe() }
}

func initGoFuse(fs pathfs.FileSystem) *fuse.Server {
	// pathFsOpts are passed into go-fuse/pathfs
	pathFsOpts := &pathfs.PathNodeFsOptions{ClientInodes: true}
	if options.sharedstorage {
		// shared storage mode disables hard link tracking as the backing inode
		// numbers may change behind our back:
		// https://github.com/rfjakob/gocryptfs/issues/156
		pathFsOpts.ClientInodes = false
	}
	if options.reverse {
		// Reverse mode is read-only, so we don't need a working link().
		// Disable hard link tracking to avoid strange breakage on duplicate
		// inode numbers ( https://github.com/rfjakob/gocryptfs/issues/149 ).
		pathFsOpts.ClientInodes = false
	}
	pathFs := pathfs.NewPathNodeFs(fs, pathFsOpts)
	var fuseOpts *nodefs.Options
	if options.sharedstorage {
		// sharedstorage mode sets all cache timeouts to zero so changes to the
		// backing shared storage show up immediately.
		fuseOpts = &nodefs.Options{}
	} else {
		fuseOpts = &nodefs.Options{
			// These options are to be compatible with libfuse defaults,
			// making benchmarking easier.
			NegativeTimeout: time.Second,
			AttrTimeout:     time.Second,
			EntryTimeout:    time.Second,
		}
	}
	conn := nodefs.NewFileSystemConnector(pathFs.Root(), fuseOpts)
	mOpts := fuse.MountOptions{
		// Writes and reads are usually capped at 128kiB on Linux through
		// the FUSE_MAX_PAGES_PER_REQ kernel constant in fuse_i.h. Our
		// sync.Pool buffer pools are sized acc. to the default. Users may set
		// the kernel constant higher, and Synology NAS kernels are known to
		// have it >128kiB. We cannot handle more than 128kiB, so we tell
		// the kernel to limit the size explicitly.
		MaxWrite: fuse.MAX_KERNEL_WRITE,
		Options:  []string{fmt.Sprintf("max_read=%d", fuse.MAX_KERNEL_WRITE)},
	}
	if options.allow_other {
		tlog.Info.Printf(tlog.ColorYellow + "The option \"-allow_other\" is set. Make sure the file " +
			"permissions protect your data from unwanted access." + tlog.ColorReset)
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		mOpts.Options = append(mOpts.Options, "default_permissions")
	}
	if options.forcedecode {
		tlog.Info.Printf(tlog.ColorYellow + "THE OPTION \"-forcedecode\" IS ACTIVE. GOCRYPTFS WILL RETURN CORRUPT DATA!" +
			tlog.ColorReset)
	}
	if options.nonempty {
		mOpts.Options = append(mOpts.Options, "nonempty")
	}
	// Set values shown in "df -T" and friends
	// First column, "Filesystem"
	fsname := options.cipherdir
	if options.fsname != "" {
		fsname = options.fsname
	}
	fsname2 := strings.Replace(fsname, ",", "_", -1)
	if fsname2 != fsname {
		tlog.Warn.Printf("Warning: %q will be displayed as %q in \"df -T\"", fsname, fsname2)
		fsname = fsname2
	}
	mOpts.Options = append(mOpts.Options, "fsname="+fsname)
	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"
	if options.reverse {
		mOpts.Name += "-reverse"
	}
	// Add a volume name if running osxfuse. Otherwise the Finder will show it as
	// something like "osxfuse Volume 0 (gocryptfs)".
	if runtime.GOOS == "darwin" {
		volname := strings.Replace(path.Base(options.mountpoint), ",", "_", -1)
		mOpts.Options = append(mOpts.Options, "volname="+volname)
	}
	// The kernel enforces read-only operation, we just have to pass "ro".
	// Reverse mounts are always read-only.
	if options.ro || options.reverse {
		mOpts.Options = append(mOpts.Options, "ro")
	} else if options.rw {
		mOpts.Options = append(mOpts.Options, "rw")
	}
	// If both "nosuid" and "suid" were passed, the safer option wins.
	if options.nosuid {
		mOpts.Options = append(mOpts.Options, "nosuid")
	} else if options.suid {
		mOpts.Options = append(mOpts.Options, "suid")
	}
	if options.nodev {
		mOpts.Options = append(mOpts.Options, "nodev")
	} else if options.dev {
		mOpts.Options = append(mOpts.Options, "dev")
	}
	if options.noexec {
		mOpts.Options = append(mOpts.Options, "noexec")
	} else if options.exec {
		mOpts.Options = append(mOpts.Options, "exec")
	}
	// Add additional mount options (if any) after the stock ones, so the user has
	// a chance to override them.
	if options.ko != "" {
		parts := strings.Split(options.ko, ",")
		tlog.Debug.Printf("Adding -ko mount options: %v", parts)
		mOpts.Options = append(mOpts.Options, parts...)
	}
	srv, err := fuse.NewServer(conn.RawFS(), options.mountpoint, &mOpts)
	if err != nil {
		tlog.Fatal.Printf("fuse.NewServer failed: %s", strings.TrimSpace(err.Error()))
		if runtime.GOOS == "darwin" {
			tlog.Info.Printf("Maybe you should run: /Library/Filesystems/osxfuse.fs/Contents/Resources/load_osxfuse")
		}
		os.Exit(exitcodes.FuseNewServer)
	}
	srv.SetDebug(options.fusedebug)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	return srv
}

func handleSigint(srv *fuse.Server, mountpoint string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		unmount(srv, mountpoint)
		os.Exit(exitcodes.SigInt)
	}()
}

func handleController(ch chan string, srv *fuse.Server, mountpoint string) {
	go func() {
		for order := range ch {
			switch order {
			case "kill":
				unmount(srv, mountpoint)
				os.Exit(exitcodes.SigInt)
			default:
				tlog.Info.Printf("unknown order : %s", order)
			}
		}
	}()
}

func unmount(srv *fuse.Server, mountpoint string) {
	err := srv.Unmount()
	if err != nil {
		tlog.Warn.Printf("unmount: srv.Unmount returned %v", err)
		if runtime.GOOS == "linux" {
			// MacOSX does not support lazy unmount
			tlog.Info.Printf("Trying lazy unmount")
			cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		}
	}
}
