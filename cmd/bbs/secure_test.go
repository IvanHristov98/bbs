package main_test

import (
	"os"
	"path"

	"github.com/cloudfoundry-incubator/bbs"
	"github.com/cloudfoundry-incubator/bbs/cmd/bbs/testrunner"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Secure", func() {
	var (
		client bbs.Client
		err    error

		basePath string
	)

	BeforeEach(func() {
		basePath = path.Join(os.Getenv("GOPATH"), "src", "github.com", "cloudfoundry-incubator", "bbs", "cmd", "bbs", "fixtures")
		bbsURL.Scheme = "https"
	})

	JustBeforeEach(func() {
		client = bbs.NewClient(bbsURL.String())
		bbsRunner = testrunner.New(bbsBinPath, bbsArgs)
		bbsProcess = ginkgomon.Invoke(bbsRunner)
	})

	AfterEach(func() {
		ginkgomon.Kill(bbsProcess)
	})

	Context("when configuring mutual SSL", func() {
		BeforeEach(func() {
			bbsArgs.RequireSSL = true
			bbsArgs.CAFile = path.Join(basePath, "green-certs", "server-ca.crt")
			bbsArgs.CertFile = path.Join(basePath, "green-certs", "server.crt")
			bbsArgs.KeyFile = path.Join(basePath, "green-certs", "server.key")
		})

		It("succeeds for a client configured with the right certificate", func() {
			caFile := path.Join(basePath, "green-certs", "server-ca.crt")
			certFile := path.Join(basePath, "green-certs", "client.crt")
			keyFile := path.Join(basePath, "green-certs", "client.key")
			client, err = bbs.NewSecureClient(bbsURL.String(), caFile, certFile, keyFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(client.Ping()).To(BeTrue())
		})

		It("fails for a client with no SSL", func() {
			client = bbs.NewClient(bbsURL.String())
			Expect(client.Ping()).To(BeFalse())
		})

		It("fails for a client configured with the wrong certificate", func() {
			caFile := path.Join(basePath, "blue-certs", "server-ca.crt")
			certFile := path.Join(basePath, "blue-certs", "client.crt")
			keyFile := path.Join(basePath, "blue-certs", "client.key")
			client, err = bbs.NewSecureClient(bbsURL.String(), caFile, certFile, keyFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(client.Ping()).To(BeFalse())
		})

		It("fails to create the client if certs are not valid", func() {
			client, err = bbs.NewSecureClient(bbsURL.String(), "", "", "")
			Expect(err).To(HaveOccurred())
		})
	})
})
