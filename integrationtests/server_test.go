package integrationtests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("Server tests", func() {
	var CACert *x509.Certificate
	var certDir string

	generateCA := func() (*rsa.PrivateKey, *x509.Certificate) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		Expect(err).ToNot(HaveOccurred())

		t := time.Now().Add(-time.Minute)
		templateRoot := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    t,
			NotAfter:     t.Add(time.Hour),
			IsCA:         true,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, templateRoot, templateRoot, &key.PublicKey, key)
		Expect(err).ToNot(HaveOccurred())
		cert, err := x509.ParseCertificate(certDER)
		Expect(err).ToNot(HaveOccurred())
		return key, cert
	}

	BeforeEach(func() {
		var err error
		certDir, err = ioutil.TempDir("", "quic-server-certs")
		Expect(err).ToNot(HaveOccurred())

		// generate an RSA key pair for the server
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		Expect(err).ToNot(HaveOccurred())
		// save the private key in PKCS8 format to disk (required by quic_server)
		pkcs8key, err := marshalPKCS8PrivateKey(key)
		Expect(err).ToNot(HaveOccurred())
		f, err := os.Create(filepath.Join(certDir, "key.pkcs8"))
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write(pkcs8key)
		Expect(err).ToNot(HaveOccurred())
		f.Close()

		// generate a Certificate Authority
		// this CA is used to sign the server's key
		// it is set as a valid CA in the QUIC client
		var rootKey *rsa.PrivateKey
		rootKey, CACert = generateCA()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			Subject:      pkix.Name{CommonName: "quic.clemente.io"},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, CACert, &key.PublicKey, rootKey)
		Expect(err).ToNot(HaveOccurred())
		// save the certificate to disk
		certOut, err := os.Create(filepath.Join(certDir, "cert.pem"))
		Expect(err).ToNot(HaveOccurred())
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certOut.Close()
	})

	AfterEach(func() {
		Expect(certDir).ToNot(BeEmpty())
		os.RemoveAll(certDir)
		certDir = ""
	})

	It("downloads", func(done Done) {
		port := "6666"
		go func() {
			defer GinkgoRecover()
			command := exec.Command(
				"./quic_server",
				"--quic_response_cache_dir=/tmp/quic-data/www.example.org",
				"--key_file="+filepath.Join(certDir, "key.pkcs8"),
				"--certificate_file="+filepath.Join(certDir, "cert.pem"),
				"--port="+port,
				"--v=1",
			)
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			defer session.Kill()
			select {}
		}()

		time.Sleep(time.Second)
		certPool := x509.NewCertPool()
		certPool.AddCert(CACert)
		client := &http.Client{
			Transport: &h2quic.QuicRoundTripper{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
		}
		resp, err := client.Get("https://quic.clemente.io:" + port + "/")
		Expect(err).ToNot(HaveOccurred())
		_ = resp
	})
})
