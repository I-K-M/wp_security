package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/I-K-M/wp_security/internal/scanner"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var version = "0.2.0-dev"

func main() { os.Exit(run()) }
func run() int {
	target := flag.String("url", "", "Authorised HTTP(S) origin or WordPress base path")
	format := flag.String("format", "text", "text or json (JSON goes to stdout)")
	legacyJSON := flag.Bool("json", false, "Alias for --format json")
	output := flag.String("output", "", "Optional private JSON report file")
	timeout := flag.Duration("timeout", 10*time.Second, "Per-request timeout")
	maxBytes := flag.Int64("max-bytes", 1048576, "Maximum decoded response bytes")
	workers := flag.Int("workers", 4, "Concurrency (1..16)")
	rate := flag.Float64("rate", 5, "Maximum request starts per second (0..100)")
	threshold := flag.String("fail-on", "medium", "Finding threshold: info|low|medium|high|critical")
	showVersion := flag.Bool("version", false, "Print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return 0
	}
	if *legacyJSON {
		*format = "json"
	}
	if *format != "json" && *format != "text" {
		fmt.Fprintln(os.Stderr, "Invalid format")
		return 2
	}
	switch *threshold {
	case "info", "low", "medium", "high", "critical":
	default:
		fmt.Fprintln(os.Stderr, "Invalid severity threshold")
		return 2
	}
	s, err := scanner.New(*target, scanner.Options{Timeout: *timeout, MaxBytes: *maxBytes, Workers: *workers, RequestsPerSecond: *rate})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer s.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report := s.Run(ctx)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return 3
	}
	if *output != "" {
		if err = save(*output, append(data, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, "Cannot save report:", err)
			return 3
		}
	}
	if *format == "json" {
		fmt.Println(string(data))
	} else {
		fmt.Printf("WP Security %s\nTarget: %s\n", version, report.Target)
		for _, r := range report.Results {
			fmt.Printf("%-34s %-15s %-8s %s\n", r.ID, r.Status, r.Severity, r.Evidence)
		}
	}
	return scanner.ExitCode(report, *threshold)
}
func save(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("output already exists (choose a new path)")
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".wp-security-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Hard link creates the final path exclusively, avoiding an overwrite race.
	return os.Link(f.Name(), path)
}
