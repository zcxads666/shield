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

var usageText = `Usage: shield [--config <path>] <command> [args...]

Commands:
  start       Start the shield server (validates config first)
  restart     Stop the running instance and start a new one
  status      Show whether the server is running
  stats       Print current metrics and status
  logs        View recent log output
  blacklist   Manage IP blacklist (list | add | remove)
  mapping     Manage port mappings (list | add | remove | update)

Blacklist subcommands:
  shield blacklist list
  shield blacklist add    --ip <ip> --reason <reason> [--duration <sec>]
  shield blacklist remove --ip <ip>

Mapping subcommands:
  shield mapping list
  shield mapping add    --id <id> --listen <addr> --target <ip:port>
  shield mapping remove --id <id>
  shield mapping update --id <id> [--listen <addr>] [--target <ip:port>]

Other commands:
  shield logs [--lines <n>]

Options:
  --config <path>   Path to configuration file (default: configs/config.yaml)
`

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "path to configuration file")
	flag.Usage = func() { fmt.Print(usageText) }
	flag.Parse()

	args := flag.Args()
	cmd := "start"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "start":
		cmdStart(*cfgPath)
	case "restart":
		cmdRestart(*cfgPath)
	case "status":
		cmdStatus(*cfgPath)
	case "stats":
		cmdStats(*cfgPath)
	case "logs":
		cmdLogs(*cfgPath, args)
	case "blacklist":
		cmdBlacklist(*cfgPath, args)
	case "mapping":
		cmdMapping(*cfgPath, args)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		fmt.Print(usageText)
		os.Exit(1)
	}
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
	proc.Release()
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
	flags.IntVar(&lines, "lines", 50, "number of lines to show")
	flags.Parse(args)

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
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shield blacklist <list|add|remove> [args...]")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	cfgMgr := config.NewManager(cfgPath)
	if err := cfgMgr.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	cfg := cfgMgr.Get()

	bl := blacklist.NewManager(cfg.Blacklist.PersistPath)

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
		flags := flag.NewFlagSet("blacklist add", flag.ContinueOnError)
		ip := flags.String("ip", "", "IP address to block")
		reason := flags.String("reason", "", "reason for blocking")
		duration := flags.Int("duration", 0, "block duration in seconds (0 = permanent)")
		if err := flags.Parse(subArgs); err != nil {
			os.Exit(1)
		}
		if *ip == "" {
			fmt.Fprintln(os.Stderr, "Error: --ip is required")
			os.Exit(1)
		}
		bl.Add(*ip, *reason, time.Duration(*duration)*time.Second, *duration == 0)
		bl.Save()
		fmt.Printf("IP %s added to blacklist\n", *ip)

	case "remove":
		flags := flag.NewFlagSet("blacklist remove", flag.ContinueOnError)
		ip := flags.String("ip", "", "IP address to unblock")
		if err := flags.Parse(subArgs); err != nil {
			os.Exit(1)
		}
		if *ip == "" {
			fmt.Fprintln(os.Stderr, "Error: --ip is required")
			os.Exit(1)
		}
		bl.Remove(*ip)
		bl.Save()
		fmt.Printf("IP %s removed from blacklist\n", *ip)

	default:
		fmt.Fprintf(os.Stderr, "Unknown blacklist subcommand: %s\n", sub)
		os.Exit(1)
	}
}

// --- mapping ---

func cmdMapping(cfgPath string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: shield mapping <list|add|remove|update> [args...]")
		os.Exit(1)
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
		flags := flag.NewFlagSet("mapping add", flag.ContinueOnError)
		id := flags.String("id", "", "mapping identifier")
		listen := flags.String("listen", "", "listen address (e.g. :9090)")
		target := flags.String("target", "", "target ip:port (e.g. 192.168.1.100:8080)")
		if err := flags.Parse(subArgs); err != nil {
			os.Exit(1)
		}
		if *id == "" || *listen == "" || *target == "" {
			fmt.Fprintln(os.Stderr, "Error: --id, --listen, and --target are required")
			os.Exit(1)
		}
		for _, m := range cfg.PortMappings {
			if m.ID == *id {
				fmt.Fprintf(os.Stderr, "Error: mapping with id %q already exists\n", *id)
				os.Exit(1)
			}
		}
		if !isValidIPPort(*target) {
			fmt.Fprintf(os.Stderr, "Error: invalid target %q (must be ip:port, e.g. 192.168.1.100:8080)\n", *target)
			os.Exit(1)
		}
		cfg.PortMappings = append(cfg.PortMappings, config.PortMappingItem{
			ID: *id, Listen: *listen, Target: *target,
		})
		if err := writeConfigYAML(cfgPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port mapping %q added (restart server to apply)\n", *id)

	case "remove":
		flags := flag.NewFlagSet("mapping remove", flag.ContinueOnError)
		id := flags.String("id", "", "mapping identifier to remove")
		if err := flags.Parse(subArgs); err != nil {
			os.Exit(1)
		}
		if *id == "" {
			fmt.Fprintln(os.Stderr, "Error: --id is required")
			os.Exit(1)
		}
		found := false
		newMappings := make([]config.PortMappingItem, 0, len(cfg.PortMappings))
		for _, m := range cfg.PortMappings {
			if m.ID == *id {
				found = true
				continue
			}
			newMappings = append(newMappings, m)
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: mapping with id %q not found\n", *id)
			os.Exit(1)
		}
		cfg.PortMappings = newMappings
		if err := writeConfigYAML(cfgPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port mapping %q removed (restart server to apply)\n", *id)

	case "update":
		flags := flag.NewFlagSet("mapping update", flag.ContinueOnError)
		id := flags.String("id", "", "mapping identifier to update")
		listen := flags.String("listen", "", "new listen address")
		target := flags.String("target", "", "new target ip:port")
		if err := flags.Parse(subArgs); err != nil {
			os.Exit(1)
		}
		if *id == "" {
			fmt.Fprintln(os.Stderr, "Error: --id is required")
			os.Exit(1)
		}
		if *listen == "" && *target == "" {
			fmt.Fprintln(os.Stderr, "Error: at least one of --listen or --target must be provided")
			os.Exit(1)
		}
		if *target != "" {
			if !isValidIPPort(*target) {
				fmt.Fprintf(os.Stderr, "Error: invalid target %q (must be ip:port)\n", *target)
				os.Exit(1)
			}
		}
		found := false
		for i := range cfg.PortMappings {
			if cfg.PortMappings[i].ID == *id {
				found = true
				if *listen != "" {
					cfg.PortMappings[i].Listen = *listen
				}
				if *target != "" {
					cfg.PortMappings[i].Target = *target
				}
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: mapping with id %q not found\n", *id)
			os.Exit(1)
		}
		if err := writeConfigYAML(cfgPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port mapping %q updated (restart server to apply)\n", *id)

	default:
		fmt.Fprintf(os.Stderr, "Unknown mapping subcommand: %s\n", sub)
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

func isProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = proc
	return true
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
