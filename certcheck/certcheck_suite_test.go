package certcheck_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCertcheck(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certcheck Suite")
}
