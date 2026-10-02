package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func opts() Options {
	return Options{Timeout: time.Second, MaxBytes: 10000, Workers: 4, RequestsPerSecond: 100}
}
func get(r Report, id string) Result {
	for _, v := range r.Results {
		if v.ID == id {
			return v
		}
	}
	return Result{}
}
func TestConfirmedExposureAndRedaction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wp-config.php":
			w.Write([]byte("<?php define('DB_PASSWORD','SECRET_TOKEN');"))
		case "/.git/HEAD":
			w.Write([]byte("ref: refs/heads/main\n"))
		case "/.env":
			w.Write([]byte("DB_PASSWORD=SECRET_TOKEN\n"))
		case "/":
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Write([]byte("Home"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s, _ := New(srv.URL, opts())
	defer s.Close()
	r := s.Run(context.Background())
	if get(r, "WP-001").Severity != "critical" || get(r, "WP-002").Severity != "high" || get(r, "WP-003").Severity != "high" {
		t.Fatal(r)
	}
	for _, v := range r.Results {
		if strings.Contains(v.Evidence, "SECRET_TOKEN") {
			t.Fatal("secret leaked")
		}
	}
	if get(r, "HEADER-Content-Security-Policy").Status != "pass" || get(r, "HEADER-X-Frame-Options").Status != "pass" {
		t.Fatal("canonical header/CSP failed")
	}
	if ExitCode(r, "high") != 1 {
		t.Fatal("expected finding exit")
	}
}
func TestSoft404AndEmptyPHPNotCritical(t *testing.T) {
	for _, body := range []string{"<html>Generic error</html>", ""} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		s, _ := New(srv.URL, opts())
		r := s.Run(context.Background())
		s.Close()
		srv.Close()
		if get(r, "WP-001").Status == "finding" || get(r, "WP-002").Status == "finding" {
			t.Fatal(r)
		}
	}
}
func TestCrossOriginRedirectBlocked(t *testing.T) {
	hits := 0
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer external.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, external.URL, 302) }))
	defer srv.Close()
	s, _ := New(srv.URL, opts())
	defer s.Close()
	r := s.Run(context.Background())
	if hits != 0 || ExitCode(r, "critical") != 3 {
		t.Fatal(hits, r)
	}
}
func TestLimitsAndCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 20000))) }))
	defer srv.Close()
	s, _ := New(srv.URL, opts())
	defer s.Close()
	r := s.Run(context.Background())
	if ExitCode(r, "critical") != 3 {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ExitCode(s.Run(ctx), "high") != 3 {
		t.Fatal("cancel not visible")
	}
}
func TestInvalidTargets(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "https://user:secret@example.com", "https://example.com?token=secret", "no-url"} {
		if _, err := New(u, opts()); err == nil {
			t.Fatal(u)
		}
	}
}
func TestRateAndOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	o := opts()
	o.RequestsPerSecond = 50
	s, _ := New(srv.URL, o)
	defer s.Close()
	start := time.Now()
	r := s.Run(context.Background())
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("rate limiter failed")
	}
	for i := 1; i < len(r.Results); i++ {
		if r.Results[i-1].ID > r.Results[i].ID {
			t.Fatal("non deterministic order")
		}
	}
}
