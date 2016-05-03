package migrations_test

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"github.com/cloudfoundry-incubator/bbs/db/etcd"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	"github.com/cloudfoundry/storeadapter/storerunner/etcdstorerunner"
	"github.com/cloudfoundry/storeadapter/storerunner/mysqlrunner"
	etcdclient "github.com/coreos/go-etcd/etcd"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/clock/fakeclock"
	"github.com/pivotal-golang/lager/lagertest"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	_ "github.com/go-sql-driver/mysql"

	"testing"
)

var (
	etcdPort    int
	etcdUrl     string
	etcdRunner  *etcdstorerunner.ETCDClusterRunner
	etcdClient  *etcdclient.Client
	storeClient etcd.StoreClient

	rawSQLDB     *sql.DB
	mySQLProcess ifrit.Process
	mySQLRunner  *mysqlrunner.MySQLRunner

	cryptor   encryption.Cryptor
	fakeClock *fakeclock.FakeClock
	logger    *lagertest.TestLogger
)

func TestMigrations(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Migrations Suite")
}

var _ = BeforeSuite(func() {
	logger = lagertest.NewTestLogger("test")

	etcdPort = 4001 + GinkgoParallelNode()
	etcdUrl = fmt.Sprintf("http://127.0.0.1:%d", etcdPort)
	etcdRunner = etcdstorerunner.NewETCDClusterRunner(etcdPort, 1, nil)

	etcdRunner.Start()

	mySQLRunner = mysqlrunner.NewMySQLRunner(fmt.Sprintf("diego_%d", GinkgoParallelNode()))
	mySQLProcess = ginkgomon.Invoke(mySQLRunner)

	// mysql must be set up on localhost as described in the CONTRIBUTING.md doc
	// in diego-release.
	var err error

	rawSQLDB, err = sql.Open("mysql", mySQLRunner.ConnectionString())
	Expect(err).NotTo(HaveOccurred())
	Expect(rawSQLDB.Ping()).NotTo(HaveOccurred())

	encryptionKey, err := encryption.NewKey("label", "passphrase")
	Expect(err).NotTo(HaveOccurred())
	keyManager, err := encryption.NewKeyManager(encryptionKey, nil)
	Expect(err).NotTo(HaveOccurred())
	cryptor = encryption.NewCryptor(keyManager, rand.Reader)

	fakeClock = fakeclock.NewFakeClock(time.Now())
})

var _ = AfterSuite(func() {
	etcdRunner.Stop()

	ginkgomon.Kill(mySQLProcess)

	Expect(rawSQLDB.Close()).NotTo(HaveOccurred())
})

var _ = BeforeEach(func() {
	etcdRunner.Reset()

	etcdClient = etcdRunner.Client()
	etcdClient.SetConsistency(etcdclient.STRONG_CONSISTENCY)

	storeClient = etcd.NewStoreClient(etcdClient)

	mySQLRunner.Reset()
})
