package certcheck

import (
	"crypto/x509"
	"fmt"
	"time"
)

type NotValidYet struct {
	CommonName string
	NotBefore  time.Time
}

func (e NotValidYet) Error() string {
	return fmt.Sprintf("%s is not going to be valid before %s", e.CommonName, e.NotBefore)
}

func (e NotValidYet) String() string {
	return e.Error()
}

type NotValidAnymore struct {
	CommonName string
	NotAfter   time.Time
}

func (e NotValidAnymore) Error() string {
	return fmt.Sprintf("%s is not going to be valid after %s", e.CommonName, e.NotAfter)
}

func (e NotValidAnymore) String() string {
	return e.Error()
}

func Validate(cert *x509.Certificate, pointInTime time.Time) error {
	if pointInTime.Before(cert.NotBefore.UTC()) {
		return NotValidYet{
			CommonName: cert.Subject.CommonName,
			NotBefore:  cert.NotBefore.UTC(),
		}
	}

	if pointInTime.After(cert.NotAfter.UTC()) {
		return NotValidAnymore{
			CommonName: cert.Subject.CommonName,
			NotAfter:   cert.NotAfter.UTC(),
		}
	}

	return nil
}
