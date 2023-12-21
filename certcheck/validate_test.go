package certcheck_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/suhlig/is-tls-expiring/certcheck"
)

var _ = Describe("validation of", func() {
	var (
		err                              error
		pointInTime, notBefore, notAfter time.Time
		privateKey                       ed25519.PrivateKey
	)

	BeforeEach(func() {
		pointInTime = time.Now().UTC()
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
	})

	JustBeforeEach(func() {
		cert, createError := createCert(privateKey, notBefore, notAfter)
		Expect(createError).ToNot(HaveOccurred())

		err = certcheck.Validate(cert, pointInTime)
	})

	Context("a certificate that is valid", func() {
		BeforeEach(func() {
			notBefore = pointInTime.Add(-24 * time.Hour)
			notAfter = pointInTime.Add(24 * time.Hour)
		})

		It("produces no error", func() {
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("a certificate that is not valid yet", func() {
		BeforeEach(func() {
			notBefore = pointInTime.Add(24 * time.Hour)
			notAfter = pointInTime.Add(48 * time.Hour)
		})

		It("produces the expected error", func() {
			Expect(err).To(ContainSubstring("is not going to be valid before"))
		})
	})

	Context("a certificate that is not valid anymore", func() {
		BeforeEach(func() {
			notBefore = pointInTime.Add(-48 * time.Hour)
			notAfter = pointInTime.Add(-24 * time.Hour)
		})

		It("produces the expected error", func() {
			Expect(err).To(ContainSubstring("is not going to be valid after"))
		})
	})
})

func createCert(priv ed25519.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, priv.Public(), priv)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}
