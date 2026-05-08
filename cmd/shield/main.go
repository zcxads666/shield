package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/shield/shield/internal/handler"
	"github.com/shield/shield/internal/portmap"
	"github.com/shield/shield/internal/service/rules"
	"github.com/shield/shield/internal/storage/blacklist"
	"github.com/shield/shield/pkg/config"
	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
	"github.com/shield/shield/pkg/version"
)

var usageText = `Usage: shield [-c <config>] <command> [args]

Commands (aliases):
  (no args)                 Start server with config validation
  start                     Start server
  restart                   Restart server
  status, st                Show server runtime status
  stats, ss                 Print metrics JSON
  logs, log [-n N]          Show last N log lines (default: 50)

  blacklist, bl             List blacklisted IPs
  bl add <ip> [reason] [duration_sec]
                            Add IP (0 duration = permanent)
  bl rm <ip>                Remove IP from blacklist

  mapping, mp               List port mappings
  mp add <listen> <target>  Add mapping (auto-generates id)
  mp add <id> <listen> <target>
                            Add mapping with explicit id
  mp rm <id>                Remove mapping
  mp set <id> <listen> <target>
                            Update mapping

Options:
  -c, --config <path>       Config file path (default: configs/config.yaml)
`

func main() {
	cfgPath := flag.String("c", "configs/config.yaml", "path to configuration file")
	flag.StringVar(cfgPath, "config", "configs/config.yaml", "")
	flag.Usage = func() { fmt.Print(usageText) }
	flag.Parse()

	args := flag.Args()
	cmd := "start"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	cmd = resolveAlias(cmd)

	switch cmd {
	case "start":
		cmdStart(*cfgPath)
	case "restart":
		cmdRestart(*cfgPath)
	case "status":
		cmdStatus(*cfgPath)
	case "stats":
		cmdStats(*cfgPath)
	case "logs", "log":
		cmdLogs(*cfgPath, args)
	case "blacklist", "bl":
		cmdBlacklist(*cfgPath, args)
	case "mapping", "mp":
		cmdMapping(*cfgPath, args)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		fmt.Print(usageText)
		os.Exit(1)
	}
}

func resolveAlias(cmd string) string {
	switch strings.ToLower(cmd) {
	case "st":
		return "status"
	case "ss":
		return "stats"
	case "log":
		return "logs"
	case "bl":
		return "blacklist"
	case "mp":
		return "mapping"
	}
	return cmd
}

// --- start ---

func cmdStart(cfgPath string) {
	cfg, lg := loadConfig(cfgPath)

	if err := validateConfig(cfg, lg); err != nil {
		fmt.Fprintf(os.Stderr, "Config validation failed: %v\n", err)
		lg.Error("config_validation_failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	fmt.Println("Config validation passed.")

	bl := blacklist.NewManager(cfg.Blacklist.PersistPath)
	metrics.Get().SetBlacklistedIPs(uint64(len(bl.List())))

	re := rules.NewEngine(cfg.Rules.RulesPath, cfg.Rules.HotReload)
	if err := re.Load(); err != nil {
		lg.Warn("rules_load_failed", map[string]interface{}{"error": err.Error()})
	}

	_ = os.MkdirAll("data", 0755)
	writePidFile(cfg.Server.PidFile, lg)

	lg.Info("shield_starting", map[string]interface{}{
		"bind":   cfg.Server.BindAddr,
		"target": cfg.Proxy.TargetURL,
	})

	bl.StartCleanupLoop()

	if cfg.Rules.HotReload {
		go watchReload(cfgPath, re)
	}

	pm := portmap.NewManager(lg)
	if len(cfg.PortMappings) > 0 {
		if err := pm.Start(cfg.PortMappings, cfg, lg, bl, re); err != nil {
			lg.Error("portmap_start_failed", map[string]interface{}{"error": err.Error()})
		}
	}

	go statusWriter(cfg, lg)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		lg.Info("shield_shutting_down", nil)
		pm.Stop()
		os.Remove(cfg.Server.PidFile)
		os.Remove(cfg.Server.StatusFile)
		os.Exit(0)
	}()

	if err := handler.RunProxy(cfg, lg, bl, re); err != nil {
		lg.Error("proxy_run_error", map[string]interface{}{"error": err.Error()})
		pm.Stop()
		os.Remove(cfg.Server.PidFile)
		os.Remove(cfg.Server.StatusFile)
		os.Exit(1)
	}
}

// --- restart ---

func cmdRestart(cfgPath string) {
	cfg, lg := loadConfig(cfgPath)

	pid, err := readPidFile(cfg.Server.PidFile)
	if err == nil && pid > 0 {
		fmt.Printf("Stopping process %d...\n", pid)
		killProcess(pid, lg)
		time.Sleep(1 * time.Second)
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot find executable: %v\n", err)
		os.Exit(1)
	}

	proc, err := os.StartProcess(exe, []string{exe, "--config", cfgPath, "start"}, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start new process: %v\n", err)
		lg.Error("restart_failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	_ = proc.Release()
	fmt.Printf("Server restarted (PID %d)\n", proc.Pid)
}

// --- status ---

func cmdStatus(cfgPath string) {
	cfg, _ := loadConfig(cfgPath)

	pid, err := readPidFile(cfg.Server.PidFile)
	if err != nil || pid <= 0 {
		fmt.Println("Server is NOT running (no PID file)")
		os.Exit(1)
	}

	running := isServerReachable(cfg.Server.BindAddr)
	if !running {
		fmt.Printf("Server is NOT running (PID %d not found)\n", pid)
		os.Exit(1)
	}

	fmt.Printf("Server is running (PID %d)\n", pid)

	status, err := readStatusFile(cfg.Server.StatusFile)
	if err == nil {
		fmt.Printf("  Version:  %s\n", status.Version)
		fmt.Printf("  Started:  %s\n", status.StartedAt)
		fmt.Printf("  Bind:     %s\n", status.BindAddr)
		fmt.Printf("  Target:   %s\n", status.TargetURL)
	}
}

// --- stats ---

func cmdStats(cfgPath string) {
	cfg, _ := loadConfig(cfgPath)

	status, err := readStatusFile(cfg.Server.StatusFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read status (is server running?): %v\n", err)
		os.Exit(1)
	}

	data, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(data))
}

// --- logs ---

func cmdLogs(cfgPath string, args []string) {
	lines := 50
	flags := flag.NewFlagSet("logs", flag.ContinueOnError)
	flags.IntVar(&lines, "n", 50, "number of lines")
	_ = flags.Parse(args)

	cfgMgr := config.NewManager(cfgPath)
	if err := cfgMgr.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	cfg := cfgMgr.Get()

	logPath := cfg.Log.OutputPath
	if logPath == "" {
		logPath = "./logs/shield.log"
	}

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open log file %s: %v\n", logPath, err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read log file: %v\n", err)
		os.Exit(1)
	}

	logLines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	start := len(logLines) - lines
	if start < 0 {
		start = 0
	}
	for _, l := range logLines[start:] {
		fmt.Println(l)
	}
}

// --- blacklist ---

func cmdBlacklist(cfgPath string, args []string) {
	cfgMgr := config.NewManager(cfgPath)
	if err := cfgMgr.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	cfg := cfgMgr.Get()
	bl := blacklist.NewManager(cfg.Blacklist.PersistPath)

	if len(args) == 0 {
		args = []string{"list"}
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		list := bl.List()
		if len(list) == 0 {
			fmt.Println("No blacklisted IPs")
			return
		}
		data, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(data))

	case "add":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: shield bl add <ip> [reason] [duration_sec]")
			os.Exit(1)
		}
		ip := subArgs[0]
		reason := ""
		if len(subArgs) > 1 {
			reason = subArgs[1]
		}
		dur := 0
		if len(subArgs) > 2 {
			if d, err := strconv.Atoi(subArgs[2]); err == nil {
				dur = d
			}
		}
		bl.Add(ip, reason, time.Duration(dur)*time.Second, dur == 0)
		_ = bl.Save()
		fmt.Printf("IP %s added to blacklist\n", ip)

	case "rm", "remove":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: shield bl rm <ip>")
			os.Exit(1)
		}
		bl.Remove(subArgs[0])
		_ = bl.Save()
		fmt.Printf("IP %s removed from blacklist\n", subArgs[0])

	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s. Use: list, add, rm\n", sub)
		os.Exit(1)
	}
}

// --- mapping ---

func cmdMapping(cfgPath string, args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}

	sub := args[0]
	subArgs := args[1:]

	yamlData, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read config: %v\n", err)
		os.Exit(1)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse config: %v\n", err)
		os.Exit(1)
	}

	switch sub {
	case "list":
		if len(cfg.PortMappings) == 0 {
			fmt.Println("No port mappings configured")
			return
		}
		data, _ := yaml.Marshal(cfg.PortMappings)
		fmt.Print(string(data))

	case "add":
		var id, listen, target string
		switch len(subArgs) {
		case 2:
			listen, target = subArgs[0], subArgs[1]
			id = "auto-" + listen
		case 3:
			id, listen, target = subArgs[0], subArgs[1], subArgs[2]
		default:
			fmt.Fprintln(os.Stderr, "Usage: shield mp add <listen> <target>")
			fmt.Fprintln(os.Stderr, "  or:  shield mp add <id> <listen> <target>")
			os.Exit(1)
		}
		for _, m := range cfg.PortMappings {
			if m.Listen == listen {
				fmt.Fprintf(os.Stderr, "Error: listen address %q already in use by mapping %q\n", listen, m.ID)
				os.Exit(1)
			}
		}
		if !isValidIPPort(target) {
			fmt.Fprintf(os.Stderr, "Error: invalid target %q (must be ip:port)\n", target)
			os.Exit(1)
		}
		cfg.PortMappings = append(cfg.PortMappings, config.PortMappingItem{
			ID: id, Listen: listen, Target: target,
		})
		if err := writeConfigYAML(cfgPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port mapping %q added (%s -> %s, restart to apply)\n", id, listen, target)

	case "rm", "remove":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: shield mp rm <id>")
			os.Exit(1)
		}
		id := subArgs[0]
		found := false
		newMappings := make([]config.PortMappingItem, 0, len(cfg.PortMappings))
		for _, m := range cfg.PortMappings {
			if m.ID == id {
				found = true
				continue
			}
			newMappings = append(newMappings, m)
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: mapping %q not found\n", id)
			os.Exit(1)
		}
		cfg.PortMappings = newMappings
		if err := writeConfigYAML(cfgPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port mapping %q removed (restart to apply)\n", id)

	case "set", "update":
		if len(subArgs) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: shield mp set <id> <listen> <target>")
			os.Exit(1)
		}
		id, listen, target := subArgs[0], subArgs[1], subArgs[2]
		if !isValidIPPort(target) {
			fmt.Fprintf(os.Stderr, "Error: invalid target %q (must be ip:port)\n", target)
			os.Exit(1)
		}
		found := false
		for i := range cfg.PortMappings {
			if cfg.PortMappings[i].ID == id {
				found = true
				cfg.PortMappings[i].Listen = listen
				cfg.PortMappings[i].Target = target
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: mapping %q not found\n", id)
			os.Exit(1)
		}
		if err := writeConfigYAML(cfgPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port mapping %q updated (%s -> %s, restart to apply)\n", id, listen, target)

	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s. Use: list, add, rm, set\n", sub)
		os.Exit(1)
	}
}

// --- helpers ---

func loadConfig(cfgPath string) (*config.Config, *logger.Logger) {
	cfgMgr := config.NewManager(cfgPath)
	if err := cfgMgr.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	cfg := cfgMgr.Get()

	lg, err := logger.New(cfg.Log.Level, cfg.Log.Format, cfg.Log.OutputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}

	return cfg, lg
}

func isValidIPPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if net.ParseIP(host) == nil {
		return false
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	return true
}

func validateConfig(cfg *config.Config, lg *logger.Logger) error {
	if cfg.Server.BindAddr == "" {
		return fmt.Errorf("server.bind_addr is required")
	}
	if cfg.Proxy.TargetURL == "" {
		return fmt.Errorf("proxy.target_url is required")
	}

	if _, err := url.Parse(cfg.Proxy.TargetURL); err != nil {
		return fmt.Errorf("invalid proxy.target_url: %w", err)
	}

	if err := portmap.ValidateMappings(cfg.PortMappings); err != nil {
		return err
	}

	return nil
}

func writePidFile(path string, lg *logger.Logger) {
	pid := os.Getpid()
	data := fmt.Sprintf("%d", pid)
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		lg.Warn("pid_file_write_error", map[string]interface{}{
			"path":  path,
			"error": err.Error(),
		})
	}
}

func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func isServerReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func killProcess(pid int, lg *logger.Logger) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if err := proc.Kill(); err != nil {
		lg.Warn("kill_process_error", map[string]interface{}{
			"pid":   pid,
			"error": err.Error(),
		})
	}
}

func statusWriter(cfg *config.Config, lg *logger.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	startedAt := time.Now().Format(time.RFC3339)

	for range ticker.C {
		m := metrics.Get().Snapshot()
		status := map[string]interface{}{
			"version":    version.Version,
			"started_at": startedAt,
			"bind_addr":  cfg.Server.BindAddr,
			"target_url": cfg.Proxy.TargetURL,
			"metrics":    m,
		}
		data, err := json.Marshal(status)
		if err != nil {
			continue
		}
		_ = os.WriteFile(cfg.Server.StatusFile, data, 0644)
	}
}

type statusInfo struct {
	Version   string         `json:"version"`
	StartedAt string         `json:"started_at"`
	BindAddr  string         `json:"bind_addr"`
	TargetURL string         `json:"target_url"`
	Metrics   metrics.Metrics `json:"metrics"`
}

func readStatusFile(path string) (*statusInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s statusInfo
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeConfigYAML(path string, cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func watchReload(cfgPath string, re *rules.Engine) {
	cfgMgr := config.NewManager(cfgPath)
	if err := cfgMgr.Load(); err != nil {
		return
	}
	cfg := cfgMgr.Get()
	ticker := time.NewTicker(time.Duration(cfg.Rules.ReloadIntervalSec) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := cfgMgr.Load(); err == nil {
			if err := re.Load(); err != nil {
				fmt.Fprintf(os.Stderr, "hot-reload rules failed: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "hot-reload config failed: %v\n", err)
		}
	}
}
