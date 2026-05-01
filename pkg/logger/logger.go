package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "debug"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Error:
		return "error"
	case Fatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// Logger provides structured logging.
type Logger struct {
	mu       sync.Mutex
	level    Level
	format   string
	out      io.Writer
	file     *os.File
	outputPath string
}

// New creates a logger.
func New(level, format, outputPath string) (*Logger, error) {
	lvl := parseLevel(level)
	l := &Logger{
		level:      lvl,
		format:     format,
		outputPath: outputPath,
	}
	if err := l.rotate(); err != nil {
		return nil, err
	}
	return l, nil
}

func parseLevel(s string) Level {
	switch s {
	case "debug":
		return Debug
	case "info":
		return Info
	case "warn":
		return Warn
	case "error":
		return Error
	case "fatal":
		return Fatal
	default:
		return Info
	}
}

func (l *Logger) rotate() error {
	if l.outputPath == "" || l.outputPath == "stderr" {
		l.out = os.Stderr
		return nil
	}
	dir := filepath.Dir(l.outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(l.outputPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if l.file != nil {
		l.file.Close()
	}
	l.file = f
	l.out = f
	return nil
}

// log writes a log entry.
func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := map[string]interface{}{
		"time":    time.Now().Format(time.RFC3339),
		"level":   level.String(),
		"message": msg,
	}
	for k, v := range fields {
		entry[k] = v
	}

	if l.format == "json" {
		b, _ := json.Marshal(entry)
		fmt.Fprintln(l.out, string(b))
	} else {
		fmt.Fprintf(l.out, "[%s] %s %s", entry["time"], entry["level"], entry["message"])
		for k, v := range fields {
			fmt.Fprintf(l.out, " %s=%v", k, v)
		}
		fmt.Fprintln(l.out)
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields map[string]interface{}) { l.log(Debug, msg, fields) }

// Info logs an info message.
func (l *Logger) Info(msg string, fields map[string]interface{}) { l.log(Info, msg, fields) }

// Warn logs a warning message.
func (l *Logger) Warn(msg string, fields map[string]interface{}) { l.log(Warn, msg, fields) }

// Error logs an error message.
func (l *Logger) Error(msg string, fields map[string]interface{}) { l.log(Error, msg, fields) }

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
