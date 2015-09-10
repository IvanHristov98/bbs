package main

import (
	"errors"
	"flag"
	"os"
	"time"

	"github.com/cloudfoundry-incubator/bbs/auctionhandlers"
	"github.com/cloudfoundry-incubator/bbs/cellhandlers"
	consuldb "github.com/cloudfoundry-incubator/bbs/db/consul"
	etcddb "github.com/cloudfoundry-incubator/bbs/db/etcd"
	"github.com/cloudfoundry-incubator/bbs/db/migrations"
	"github.com/cloudfoundry-incubator/bbs/events"
	"github.com/cloudfoundry-incubator/bbs/format"
	"github.com/cloudfoundry-incubator/bbs/handlers"
	"github.com/cloudfoundry-incubator/bbs/metrics"
	"github.com/cloudfoundry-incubator/bbs/migration"
	"github.com/cloudfoundry-incubator/bbs/taskworkpool"
	"github.com/cloudfoundry-incubator/bbs/watcher"
	cf_debug_server "github.com/cloudfoundry-incubator/cf-debug-server"
	cf_lager "github.com/cloudfoundry-incubator/cf-lager"
	"github.com/cloudfoundry-incubator/cf_http"
	"github.com/cloudfoundry-incubator/consuladapter"
	legacybbs "github.com/cloudfoundry-incubator/runtime-schema/bbs"
	"github.com/cloudfoundry-incubator/runtime-schema/bbs/lock_bbs"
	legacymodels "github.com/cloudfoundry-incubator/runtime-schema/models"
	"github.com/cloudfoundry/dropsonde"
	etcdclient "github.com/coreos/go-etcd/etcd"
	"github.com/hashicorp/consul/api"
	"github.com/nu7hatch/gouuid"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
)

var listenAddress = flag.String(
	"listenAddress",
	"",
	"The host:port that the server is bound to.",
)

var requireSSL = flag.Bool(
	"requireSSL",
	false,
	"whether the bbs server should require ssl-secured communication",
)

var caFile = flag.String(
	"caFile",
	"",
	"the certificate authority public key file to use with ssl auth",
)

var certFile = flag.String(
	"certFile",
	"",
	"the public key file to use with ssl auth",
)

var keyFile = flag.String(
	"keyFile",
	"",
	"the private key file to use with ssl auth",
)

var advertiseURL = flag.String(
	"advertiseURL",
	"",
	"The URL to advertise to clients",
)

var communicationTimeout = flag.Duration(
	"communicationTimeout",
	10*time.Second,
	"Timeout applied to all HTTP requests.",
)

var auctioneerAddress = flag.String(
	"auctioneerAddress",
	"",
	"The address to the auctioneer api server",
)

var sessionName = flag.String(
	"sessionName",
	"bbs",
	"consul session name",
)

var consulCluster = flag.String(
	"consulCluster",
	"",
	"comma-separated list of consul server URLs (scheme://ip:port)",
)

var lockTTL = flag.Duration(
	"lockTTL",
	lock_bbs.LockTTL,
	"TTL for service lock",
)

var lockRetryInterval = flag.Duration(
	"lockRetryInterval",
	lock_bbs.RetryInterval,
	"interval to wait before retrying a failed lock acquisition",
)

var reportInterval = flag.Duration(
	"metricsReportInterval",
	time.Minute,
	"interval on which to report metrics",
)

var dropsondeDestination = flag.String(
	"dropsondeDestination",
	"localhost:3457",
	"Destination for dropsonde-emitted metrics.",
)

const (
	dropsondeOrigin = "bbs"

	bbsWatchRetryWaitDuration = 3 * time.Second
)

func main() {
	cf_debug_server.AddFlags(flag.CommandLine)
	cf_lager.AddFlags(flag.CommandLine)
	etcdFlags := AddETCDFlags(flag.CommandLine)
	flag.Parse()

	cf_http.Initialize(*communicationTimeout)

	logger, reconfigurableSink := cf_lager.New("bbs")
	logger.Info("starting")

	initializeDropsonde(logger)

	consulClient, err := consuladapter.NewClient(*consulCluster)
	if err != nil {
		logger.Fatal("new-consul-client-failed", err)
	}

	sessionManager := consuladapter.NewSessionManager(consulClient)
	consulDBSession, err := consuladapter.NewSessionNoChecks("consul-db", *lockTTL, consulClient, sessionManager)
	if err != nil {
		logger.Fatal("consul-session-failed", err)
	}

	etcdOptions, err := etcdFlags.Validate()
	if err != nil {
		logger.Fatal("etcd-validation-failed", err)
	}

	consulDB := consuldb.NewConsul(consulDBSession)
	cbWorkPool := taskworkpool.New(logger, taskworkpool.HandleCompletedTask)

	storeClient := initializeEtcdStoreClient(logger, etcdOptions)
	db := initializeEtcdDB(logger, storeClient, cbWorkPool, consulDB)

	migrationsDone := make(chan struct{})

	maintainer := initializeLockMaintainer(logger, consulClient, sessionManager)
	migrationManager := migration.NewManager(logger,
		db,
		storeClient,
		migrations.Migrations,
		migrationsDone,
		clock.NewClock(),
	)

	hub := events.NewHub()

	watcher := watcher.NewWatcher(
		logger,
		db,
		hub,
		clock.NewClock(),
		bbsWatchRetryWaitDuration,
	)

	handler := handlers.New(logger, db, hub, migrationsDone)

	server := http_server.New(*listenAddress, handler)

	metricsNotifier := metrics.NewPeriodicMetronNotifier(
		logger,
		*reportInterval,
		etcdOptions,
		clock.NewClock(),
	)

	members := grouper.Members{
		{"lock-maintainer", maintainer},
		{"workPool", cbWorkPool},
		{"server", server},
		{"migration-manager", migrationManager},
		{"watcher", watcher},
		{"hub-closer", closeHub(logger.Session("hub-closer"), hub)},
		{"metrics", *metricsNotifier},
	}

	if dbgAddr := cf_debug_server.DebugAddress(flag.CommandLine); dbgAddr != "" {
		members = append(grouper.Members{
			{"debug-server", cf_debug_server.Runner(dbgAddr, reconfigurableSink)},
		}, members...)
	}

	group := grouper.NewOrdered(os.Interrupt, members)

	monitor := ifrit.Invoke(sigmon.New(group))

	logger.Info("started")

	err = <-monitor.Wait()
	if err != nil {
		logger.Error("exited-with-failure", err)
		os.Exit(1)
	}

	logger.Info("exited")
}

func initializeLockMaintainer(logger lager.Logger, client *api.Client, sessionManager consuladapter.SessionManager) ifrit.Runner {
	session, err := consuladapter.NewSession("bbs", *lockTTL, client, sessionManager)
	if err != nil {
		logger.Fatal("Couldn't create consul session", err)
	}
	presenceManager := legacybbs.NewBBSPresenceManager(session, clock.NewClock(), logger)

	uuid, err := uuid.NewV4()
	if err != nil {
		logger.Fatal("Couldn't generate uuid", err)
	}

	if *advertiseURL == "" {
		logger.Fatal("Advertise URL must be specified", nil)
	}

	bbsPresence := legacymodels.NewBBSPresence(uuid.String(), *advertiseURL)
	lockMaintainer, err := presenceManager.NewBBSMasterLock(bbsPresence, *lockRetryInterval)
	if err != nil {
		logger.Fatal("Couldn't create lock maintainer", err)
	}

	return lockMaintainer
}

func initializeAuctioneerClient(logger lager.Logger) auctionhandlers.Client {
	if *auctioneerAddress == "" {
		logger.Fatal("auctioneer-address-validation-failed", errors.New("auctioneerAddress is required"))
	}
	return auctionhandlers.NewClient(*auctioneerAddress)
}

func initializeDropsonde(logger lager.Logger) {
	err := dropsonde.Initialize(*dropsondeDestination, dropsondeOrigin)
	if err != nil {
		logger.Error("failed-to-initialize-dropsonde", err)
	}
}

func closeHub(logger lager.Logger, hub events.Hub) ifrit.Runner {
	return ifrit.RunFunc(func(signals <-chan os.Signal, ready chan<- struct{}) error {
		logger.Info("starting")
		defer logger.Info("finished")

		close(ready)
		logger.Info("started")

		<-signals
		logger.Info("shutting-down")
		hub.Close()

		return nil
	})
}

func initializeEtcdDB(
	logger lager.Logger,
	storeClient etcddb.StoreClient,
	cbClient taskworkpool.TaskCompletionClient,
	consulDB *consuldb.ConsulDB,
) *etcddb.ETCDDB {
	return etcddb.NewETCD(
		format.ENCODED_PROTO,
		storeClient,
		initializeAuctioneerClient(logger),
		cellhandlers.NewClient(),
		consulDB,
		clock.NewClock(),
		cbClient,
	)
}

func initializeEtcdStoreClient(logger lager.Logger, etcdOptions *etcddb.ETCDOptions) etcddb.StoreClient {
	var err error
	var etcdClient *etcdclient.Client
	if etcdOptions.IsSSL {
		etcdClient, err = etcdclient.NewTLSClient(etcdOptions.ClusterUrls, etcdOptions.CertFile, etcdOptions.KeyFile, etcdOptions.CAFile)
		if err != nil {
			logger.Fatal("failed-to-construct-etcd-tls-client", err)
		}
	} else {
		etcdClient = etcdclient.NewClient(etcdOptions.ClusterUrls)
	}
	etcdClient.SetConsistency(etcdclient.STRONG_CONSISTENCY)

	return etcddb.NewStoreClient(etcdClient)
}
