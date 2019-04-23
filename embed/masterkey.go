package embed

import (
	"encoding/hex"
	"os"
	"strings"

	"github.com/sapiens-sapide/gocryptfs/internal/configfile"
	"github.com/sapiens-sapide/gocryptfs/internal/cryptocore"
	"github.com/sapiens-sapide/gocryptfs/internal/exitcodes"
	"github.com/sapiens-sapide/gocryptfs/internal/readpassword"
	"github.com/sapiens-sapide/gocryptfs/internal/tlog"
)

// parseMasterKey - Parse a hex-encoded master key that was passed on the command line
// Calls os.Exit on failure
func parseMasterKey(masterkey string, fromStdin bool) []byte {
	masterkey = strings.Replace(masterkey, "-", "", -1)
	key, err := hex.DecodeString(masterkey)
	if err != nil {
		tlog.Fatal.Printf("Could not parse master key: %v", err)
		os.Exit(exitcodes.MasterKey)
	}
	if len(key) != cryptocore.KeyLen {
		tlog.Fatal.Printf("Master key has length %d but we require length %d", len(key), cryptocore.KeyLen)
		os.Exit(exitcodes.MasterKey)
	}
	tlog.Info.Printf("Using explicit master key.")
	if !fromStdin {
		tlog.Info.Printf(tlog.ColorYellow +
			"THE MASTER KEY IS VISIBLE VIA \"ps ax\" AND MAY BE STORED IN YOUR SHELL HISTORY!\n" +
			"ONLY USE THIS MODE FOR EMERGENCIES" + tlog.ColorReset)
	}
	return key
}

// getMasterKey reads hex encoded string from options or from password if provided
// Calls os.Exit on failure.
func getMasterKey(pwd *string) (masterkey []byte, confFile *configfile.ConfFile) {
	masterkeyFromStdin := false
	// "-masterkey=stdin"
	if options.masterkey == "stdin" {
		options.masterkey = string(readpassword.Once(nil, "", "Masterkey"))
		masterkeyFromStdin = true
	}
	// "-masterkey=941a6029-3adc6a1c-..."
	if options.masterkey != "" {
		return parseMasterKey(options.masterkey, masterkeyFromStdin), nil
	}
	// "-zerokey"
	if options.zerokey {
		tlog.Info.Printf("Using all-zero dummy master key.")
		tlog.Info.Printf(tlog.ColorYellow +
			"ZEROKEY MODE PROVIDES NO SECURITY AT ALL AND SHOULD ONLY BE USED FOR TESTING." +
			tlog.ColorReset)
		return make([]byte, cryptocore.KeyLen), nil
	}
	// Load master key from config file (normal operation).
	// Prompts the user for the password.
	var err error
	masterkey, confFile, err = loadConfig(pwd)
	if err != nil {
		if options._ctlsockFd != nil {
			// Close the socket file (which also deletes it)
			options._ctlsockFd.Close()
		}
		exitcodes.Exit(err)
	}
	return masterkey, confFile
}

// loadConfig loads the config file "options.config" and returns masterkey either from password or options.masterkey
func loadConfig(pwd *string) (masterkey []byte, cf *configfile.ConfFile, err error) {
	// First check if the file can be read at all, and find out if a Trezor should
	// be used instead of a password.
	cf, err = configfile.Load(options.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		return nil, nil, err
	}
	// The user has passed the master key on the command line (probably because
	// he forgot the password).
	if options.masterkey != "" {
		masterkey = parseMasterKey(options.masterkey, false)
		return masterkey, cf, nil
	}
	var pw []byte
	if cf.IsFeatureFlagSet(configfile.FlagTrezor) {
		// Get binary data from Trezor
		pw = readpassword.Trezor(cf.TrezorPayload)
	} else {
		// Normal password entry
		pw = []byte(*pwd)
	}
	tlog.Info.Println("Decrypting master key")
	masterkey, err = cf.DecryptMasterKey(pw)
	for i := range pw {
		pw[i] = 0
	}

	if err != nil {
		tlog.Fatal.Println(err)
		return nil, nil, err
	}
	return masterkey, cf, nil
}
