// Package scanner implements bounded, read-only HTTP observations.
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation,omitempty"`
}
type Report struct {
	SchemaVersion int      `json:"schema_version"`
	Target        string   `json:"target"`
	Results       []Result `json:"results"`
}
type Options struct {
	Timeout           time.Duration
	MaxBytes          int64
	Workers           int
	RequestsPerSecond float64
}
type Scanner struct {
	base   *url.URL
	client *http.Client
	opts   Options
	mu     sync.Mutex
	next   time.Time
}
type response struct {
	code    int
	body    []byte
	headers http.Header
	digest  string
}

func New(target string, o Options) (*Scanner, error) {
	u, err := url.Parse(target)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("target must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	if o.Timeout <= 0 || o.MaxBytes <= 0 || o.Workers < 1 || o.Workers > 16 || o.RequestsPerSecond <= 0 || o.RequestsPerSecond > 100 {
		return nil, errors.New("invalid timeout, response limit, worker count or request rate")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = o.Workers
	transport.MaxIdleConnsPerHost = o.Workers
	s := &Scanner{base: u, opts: o}
	s.client = &http.Client{Timeout: o.Timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("redirect limit exceeded")
		}
		if !strings.EqualFold(req.URL.Host, u.Host) || req.URL.Scheme != u.Scheme {
			return errors.New("redirect leaves authorised origin")
		}
		return nil
	}}
	return s, nil
}
func (s *Scanner) Close() { s.client.CloseIdleConnections() }
func (s *Scanner) get(ctx context.Context, path string) (response, error) {
	s.mu.Lock()
	now := time.Now()
	when := s.next
	if when.Before(now) {
		when = now
	}
	s.next = when.Add(time.Duration(float64(time.Second) / s.opts.RequestsPerSecond))
	s.mu.Unlock()
	timer := time.NewTimer(time.Until(when))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return response{}, ctx.Err()
	case <-timer.C:
	}
	u := *s.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", "wp-security/0.2 (authorised read-only assessment)")
	res, err := s.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, s.opts.MaxBytes+1))
	if err != nil {
		return response{}, err
	}
	if int64(len(b)) > s.opts.MaxBytes {
		return response{}, errors.New("response exceeds configured limit")
	}
	h := sha256.Sum256(b)
	return response{res.StatusCode, b, res.Header, hex.EncodeToString(h[:])}, nil
}
func outcome(id, status, severity, confidence, evidence, fix string) Result {
	return Result{id, status, severity, confidence, evidence, fix}
}
func unknown(id string) Result {
	return outcome(id, "unknown", "none", "none", "Response could not be evaluated (transport, redirect, timeout, size or unexpected response)", "")
}

var envPattern = regexp.MustCompile(`(?m)^\s*(DB_PASSWORD|DB_HOST|DATABASE_URL|API_KEY|SECRET_KEY|[A-Z_]*TOKEN)\s*=\s*[^\r\n]+`)

func (s *Scanner) Run(ctx context.Context) Report {
	// A random control endpoint would alter reproducibility. This reserved path
	// identifies common fallback pages without relying on response status alone.
	baseline, baseErr := s.get(ctx, "/.wp-security-nonexistent-control")
	type check struct{ id, path string }
	checks := []check{{"WP-001", "/wp-config.php"}, {"WP-002", "/.env"}, {"WP-003", "/.git/HEAD"}, {"WP-004", "/wp-content/uploads/"}, {"WP-005", "/wp-json/wp/v2/users"}, {"WP-006", "/xmlrpc.php"}, {"WP-007", "/readme.html"}, {"WP-008", ""}}
	jobs := make(chan check)
	results := make(chan []Result, len(checks))
	var wg sync.WaitGroup
	for i := 0; i < s.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				r, err := s.get(ctx, c.path)
				if err != nil {
					results <- []Result{unknown(c.id)}
					continue
				}
				if r.code == 429 || r.code >= 500 {
					results <- []Result{unknown(c.id)}
					continue
				}
				if c.id == "WP-008" {
					results <- headers(r, s.base.Scheme)
					continue
				}
				if r.code == 401 || r.code == 403 || r.code == 404 || r.code == 410 {
					results <- []Result{outcome(c.id, "pass", "none", "medium", fmt.Sprintf("HTTP %d; no exposure observed", r.code), "")}
					continue
				}
				if r.code != 200 && !(c.id == "WP-006" && r.code == 405) {
					results <- []Result{unknown(c.id)}
					continue
				}
				if baseErr != nil || baseline.code == 429 || baseline.code >= 500 {
					results <- []Result{unknown(c.id)}
					continue
				}
				if r.digest == baseline.digest && r.code == baseline.code {
					results <- []Result{outcome(c.id, "unknown", "none", "none", "Same response as nonexistent control path", "")}
					continue
				}
				body := string(r.body)
				low := strings.ToLower(body)
				item := outcome(c.id, "pass", "none", "low", "No matching exposure evidence observed", "")
				switch c.id {
				case "WP-001":
					if strings.Contains(body, "<?php") && (strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "DB_NAME")) {
						item = outcome(c.id, "finding", "critical", "high", "PHP source and database configuration markers; body SHA256 "+r.digest, "Block source-file disclosure, investigate exposure and rotate affected credentials")
					}
				case "WP-002":
					if envPattern.Match(r.body) && !strings.Contains(low, "<html") {
						item = outcome(c.id, "finding", "high", "high", "Environment assignment markers; body SHA256 "+r.digest, "Deny access to environment files and rotate exposed secrets")
					}
				case "WP-003":
					if strings.HasPrefix(strings.TrimSpace(body), "ref: refs/") || regexp.MustCompile(`^[a-fA-F0-9]{40}\s*$`).Match(r.body) {
						item = outcome(c.id, "finding", "high", "high", "Git HEAD syntax; body SHA256 "+r.digest, "Remove Git metadata from the served directory and investigate disclosure")
					}
				case "WP-004":
					if strings.Contains(low, "index of") && strings.Contains(low, "href=") {
						item = outcome(c.id, "finding", "medium", "medium", "Directory-index title and links observed", "Disable directory indexing")
					}
				case "WP-005":
					var users []struct {
						ID   int    `json:"id"`
						Slug string `json:"slug"`
					}
					if json.Unmarshal(r.body, &users) == nil && len(users) > 0 && users[0].ID > 0 {
						item = outcome(c.id, "finding", "info", "medium", fmt.Sprintf("%d public author records; identities omitted", len(users)), "Review intended author visibility; public author data is not by itself an exploit")
					}
				case "WP-006":
					if r.code == 405 && strings.Contains(low, "xml-rpc") {
						item = outcome(c.id, "finding", "info", "medium", "XML-RPC method response observed", "Review integrations before restricting XML-RPC; exposure alone does not prove a vulnerability")
					}
				case "WP-007":
					if strings.Contains(low, "wordpress") && strings.Contains(low, "readme") {
						item = outcome(c.id, "finding", "low", "medium", "WordPress readme markers observed", "Remove unnecessary public documentation")
					}
				}
				results <- []Result{item}
			}
		}()
	}
	for _, c := range checks {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	close(results)
	report := Report{SchemaVersion: 1, Target: s.base.String(), Results: []Result{}}
	for items := range results {
		report.Results = append(report.Results, items...)
	}
	sort.Slice(report.Results, func(i, j int) bool { return report.Results[i].ID < report.Results[j].ID })
	return report
}
func headers(r response, scheme string) []Result {
	if r.code < 200 || r.code >= 300 {
		return []Result{unknown("WP-008")}
	}
	out := []Result{}
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security", "X-Frame-Options"} {
		id := "HEADER-" + h
		if h == "Strict-Transport-Security" && scheme != "https" {
			out = append(out, outcome(id, "not_applicable", "none", "high", "HSTS evaluated only over HTTPS", ""))
			continue
		}
		value := r.headers.Get(h)
		if h == "X-Frame-Options" && value == "" && strings.Contains(strings.ToLower(r.headers.Get("Content-Security-Policy")), "frame-ancestors") {
			out = append(out, outcome(id, "pass", "none", "medium", "CSP frame-ancestors present; policy strength requires review", ""))
			continue
		}
		valid := strings.TrimSpace(value) != ""
		if h == "X-Content-Type-Options" {
			valid = strings.EqualFold(strings.TrimSpace(value), "nosniff")
		}
		if h == "X-Frame-Options" {
			valid = strings.EqualFold(value, "deny") || strings.EqualFold(value, "sameorigin")
		}
		if h == "Strict-Transport-Security" {
			valid = regexp.MustCompile(`(?i)(^|;)\s*max-age\s*=\s*[1-9][0-9]*`).MatchString(value)
		}
		if valid {
			out = append(out, outcome(id, "pass", "none", "low", "Header observed; not a complete policy validation", ""))
		} else {
			out = append(out, outcome(id, "finding", "low", "medium", "Header absent or fails basic value check", "Review the policy for this application; do not blindly add restrictive headers"))
		}
	}
	return out
}
func ExitCode(r Report, threshold string) int {
	ranks := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, v := range r.Results {
		if v.Status == "unknown" || v.Status == "error" {
			return 3
		}
	}
	for _, v := range r.Results {
		if v.Status == "finding" && ranks[v.Severity] >= ranks[threshold] {
			return 1
		}
	}
	return 0
}
