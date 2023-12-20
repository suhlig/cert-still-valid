package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"time"

	flag "github.com/spf13/pflag"
	str2duration "github.com/xhit/go-str2duration/v2"
)

// ldflags will be set by goreleaser
var version = "vDEV"
var commit = "NONE"
var date = "UNKNOWN"

func main() {
	if err := mainE(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func mainE() error {
	helpWanted := flag.BoolP("help", "h", false, "provides help")
	versionWanted := flag.BoolP("version", "V", false, "prints the version and exits")
	inDurationStr := flag.StringP("in", "i", "7d", "check if the certificates are valid in this duration from now, e.g. 7d")

	flag.Parse()

	if helpWanted != nil && *helpWanted {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]... HOSTNAME\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Returns with exit code 0 if the certificate of the given HOSTNAME will be valid in the given distance from now, exits 2 if not. On any other error, the exit code will be 1.")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Example:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s --in 7d\n", filepath.Base(os.Args[0]))
		os.Exit(0)
	}

	if versionWanted != nil && *versionWanted {
		fmt.Printf("%s %s (%s), built on %s\n", filepath.Base(os.Args[0]), version, commit, date)
		os.Exit(0)
	}

	inDuration, err := str2duration.ParseDuration(*inDurationStr)

	if err != nil {
		return err
	}

	switch len(flag.Args()) {
	case 0:
		return fmt.Errorf("missing argument for hostname to check")
	case 1:
		return isExpiring(flag.Arg(0), inDuration)
	default:
		return fmt.Errorf("too many arguments; expecting exactly one, but got %d", len(os.Args))
	}
}

func isExpiring(addr string, fromNow time.Duration) error {
	conn, err := tls.Dial("tcp", addr+":443", &tls.Config{})

	if err != nil {
		return err
	}

	err = conn.Handshake()

	if err != nil {
		return err
	}

	certs := conn.ConnectionState().PeerCertificates
	nowPlusDurationUTC := time.Now().Add(fromNow).UTC()

	fmt.Fprintf(os.Stderr, "Retrieved %d certs. Checking if all are going to be valid on %s:\n", len(certs), nowPlusDurationUTC)

	for i, c := range certs {
		fmt.Fprintf(os.Stderr, "%d. %s\n", i+1, c.Subject.CommonName)

		if nowPlusDurationUTC.Before(c.NotBefore.UTC()) {
			return fmt.Errorf("%s is not going to be valid before %s", c.Subject.CommonName, c.NotBefore.UTC())
		}

		if nowPlusDurationUTC.After(c.NotAfter.UTC()) {
			return fmt.Errorf("%s is not going to be valid after %s", c.Subject.CommonName, c.NotAfter.UTC())
		}

		fmt.Fprintf(os.Stderr, "   ✅ valid between %s and %s\n", c.NotBefore, c.NotAfter.UTC())
	}

	return nil
}
