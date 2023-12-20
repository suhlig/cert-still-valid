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

type notValidYet struct {
	CommonName string
	NotBefore  time.Time
}

func (e notValidYet) Error() string {
	return fmt.Sprintf("%s is not going to be valid before %s", e.CommonName, e.NotBefore)
}

type notValidAnymore struct {
	CommonName string
	NotAfter   time.Time
}

func (e notValidAnymore) Error() string {
	return fmt.Sprintf("%s is not going to be valid after %s", e.CommonName, e.NotAfter)
}

func main() {
	err := mainE()

	switch err.(type) {
	case notValidAnymore:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	case notValidYet:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	case error:
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(3)
	}
}

func mainE() error {
	helpWanted := flag.BoolP("help", "h", false, "provides help")
	versionWanted := flag.BoolP("version", "V", false, "prints the version and exits")
	verbose := flag.BoolP("verbose", "v", false, "prints verbose output")
	inDurationStr := flag.StringP("in", "i", "7d", "check if the certificates are valid in this duration from now")

	flag.Parse()

	if helpWanted != nil && *helpWanted {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]... HOSTNAME\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, `Returns with exit code

- 0 if the certificate of the given hostname will be valid in the given distance from now, or
- 1 if the certificate will not be valid anymore, or
- 2 if the certificate will not be valid yet.

On any other error, the exit code will be 3.`)
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
		return isExpiring(flag.Arg(0), inDuration, func(format string, args ...any) {
			if verbose != nil && *verbose {
				fmt.Fprintf(os.Stderr, format, args...)
				fmt.Fprintln(os.Stderr)
			}
		})
	default:
		return fmt.Errorf("too many arguments; expecting exactly one, but got %d", len(os.Args))
	}
}

func isExpiring(addr string, fromNow time.Duration, logger func(string, ...any)) error {
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

	logger("Retrieved %d certs. Checking if all are going to be valid on %s:", len(certs), nowPlusDurationUTC)

	for i, c := range certs {
		logger("%d. %s", i+1, c.Subject.CommonName)

		if nowPlusDurationUTC.Before(c.NotBefore.UTC()) {
			return notValidYet{
				CommonName: c.Subject.CommonName,
				NotBefore:  c.NotBefore.UTC(),
			}
		}

		if nowPlusDurationUTC.After(c.NotAfter.UTC()) {
			return notValidAnymore{
				CommonName: c.Subject.CommonName,
				NotAfter:   c.NotAfter.UTC(),
			}
		}

		logger("  ✅ valid between %s and %s", c.NotBefore, c.NotAfter.UTC())
	}

	return nil
}
