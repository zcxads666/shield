package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shield/shield/internal/handler"
	"github.com/shield/shield/internal/service/rules"
	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

func main() {
	var (
		configPath = flag.String("config", "configs/config.yaml", "path to configuration file")
		cmd        = flag.String("cmd", "run", "command: run, stats, blacklist")
	)
	flag.Parse()

	cfgMgr := config.NewManager(*configPath)
	if err := cfgMgr.Load(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cfg := cfgMgr.Get()

	lg, err := logger.New(cfg.Log.Level, cfg.Log.Format, cfg.Log.OutputPath)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	bl := blacklist.NewManager(cfg.Blacklist.PersistPath)
	metrics.Get().SetBlacklistedIPs(uint64(len(bl.List())))

	re := rules.NewEngine(cfg.Rules.RulesPath, cfg.Rules.HotReload)
	if err := re.Load(); err != nil {
		lg.Warn("rules_load_failed", map[string]interface{}{"error": err.Error()})
	}

	switch *cmd {
	case "run":
		runServer(cfg, lg, bl, re, cfgMgr)
	case "stats":
		printStats()
	case "blacklist":
		printBlacklist(bl)
	default:
		fmt.Printf("Unknown command: %s\n", *cmd)
		os.Exit(1)
	}
}

func runServer(cfg *config.Config, lg *logger.Logger, bl *blacklist.Manager, re *rules.Engine, cfgMgr *config.Manager) {
	// Start periodic blacklist cleanup to remove expired entries
	bl.StartCleanupLoop()

	// Hot reload watcher
	if cfg.Rules.HotReload {
		go watchReload(cfgMgr, re)
	}

	// Start admin server
	adm := handler.NewAdminServer(cfg, bl)
	adminSrv := &http.Server{
		Addr:    cfg.Server.AdminBindAddr,
		Handler: adm.Handler(),
	}
	go func() {
		lg.Info("admin_server_starting", map[string]interface{}{"bind": cfg.Server.AdminBindAddr})
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lg.Error("admin_server_error", map[string]interface{}{"error": err.Error()})
		}
	}()

	// Start proxy server
	lg.Info("shield_starting", map[string]interface{}{
		"bind":   cfg.Server.BindAddr,
		"target": cfg.Proxy.TargetURL,
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		lg.Info("shield_shutting_down", nil)
		os.Exit(0)
	}()

	if err := handler.RunProxy(cfg, lg, bl, re); err != nil {
		lg.Error("proxy_run_error", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
}

func watchReload(cfgMgr *config.Manager, re *rules.Engine) {
	ticker := time.NewTicker(time.Duration(cfgMgr.Get().Rules.ReloadIntervalSec) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := cfgMgr.Load(); err == nil {
			if err := re.Load(); err != nil {
				log.Printf("hot-reload rules failed: %v", err)
			}
		} else {
			log.Printf("hot-reload config failed: %v", err)
		}
	}
}

func printStats() {
	m := metrics.Get().Snapshot()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal stats: %v", err)
	}
	fmt.Println(string(data))
}

func printBlacklist(bl *blacklist.Manager) {
	list := bl.List()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal blacklist: %v", err)
	}
	fmt.Println(string(data))
}
