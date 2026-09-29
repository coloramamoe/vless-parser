package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBytes = 8 << 20

var (
	protocol = regexp.MustCompile(`(?i)(?:vmess|vless|trojan|ssr?|tuic|hysteria2?)://`)
	uuidRE   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$`)
	reserved = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

type config struct {
	raw, key, host, uuid, security, network, sni, hostHeader, fp, pbk, sid, path, source string
	port, delay                                                                          int
	query                                                                                url.Values
}

func lines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

func domain(value string) string {
	v, _ := url.QueryUnescape(value)
	v = strings.ToLower(strings.Trim(strings.TrimSpace(v), "."))
	v, _, _ = strings.Cut(v, ",")
	if host, port, err := net.SplitHostPort(v); err == nil && port != "" {
		return strings.Trim(host, "[]")
	}
	if i := strings.LastIndexByte(v, ':'); i > 0 && strings.Count(v, ":") == 1 {
		if _, err := strconv.Atoi(v[i+1:]); err == nil {
			return v[:i]
		}
	}
	return strings.Trim(v, "[]")
}

func validHost(v string) bool {
	v = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(v), "."), "*.")
	if v == "" || len(v) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return true
	}
	for _, label := range strings.Split(v, ".") {
		if !hostRE.MatchString(label) {
			return false
		}
	}
	return true
}

func routable(v string) bool {
	v = strings.ToLower(strings.Trim(v, "[]"))
	if v == "localhost" || strings.HasSuffix(v, ".localhost") || !validHost(v) {
		return false
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return false
		}
		for _, block := range reserved {
			if block.Contains(ip) {
				return false
			}
		}
		return true
	}
	return strings.Contains(v, ".")
}

func domains(path string) (map[string]bool, error) {
	items, err := lines(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, v := range items {
		d := domain(v)
		if d != "" && validHost(d) {
			out[d] = true
		}
	}
	return out, nil
}

func loadDomains(root string, client *http.Client) (map[string]bool, error) {
	known, err := domains(filepath.Join(root, "sources/domains.txt"))
	if err != nil {
		return nil, err
	}
	sources, err := lines(filepath.Join(root, "sources/domains.urls"))
	if err != nil {
		return nil, err
	}
	for i, source := range sources {
		body, err := fetch(context.Background(), client, source)
		if err != nil {
			fmt.Printf("domain src %d: %v\n", i+1, err)
			continue
		}
		added := 0
		for _, raw := range strings.Split(body, "\n") {
			d := strings.TrimPrefix(domain(raw), "*.")
			if !strings.Contains(d, ".") || !validHost(d) {
				continue
			}
			if _, err := netip.ParseAddr(d); err == nil {
				continue
			}
			if !matchesDomain(d, known) {
				known[d] = true
				added++
			}
		}
		fmt.Printf("domain src %d: %d added\n", i+1, added)
	}
	return known, nil
}

func matchesDomain(v string, known map[string]bool) bool {
	d := domain(v)
	for d != "" {
		if known[d] {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

func splitConfigs(text string) []string {
	if !protocol.MatchString(text) {
		compact := strings.Join(strings.Fields(text), "")
		if len(compact) >= 32 {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, err := enc.DecodeString(compact); err == nil && protocol.Match(b) {
					text = string(b)
					break
				}
			}
		}
	}
	var out []string
	for _, row := range strings.Split(text, "\n") {
		row = strings.TrimSpace(row)
		if strings.HasPrefix(row, "#") {
			continue
		}
		starts := protocol.FindAllStringIndex(row, -1)
		for i, span := range starts {
			end := len(row)
			if i+1 < len(starts) {
				end = starts[i+1][0]
			}
			v := strings.TrimSpace(row[span[0]:end])
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func query(raw string) url.Values {
	raw = strings.ReplaceAll(raw, ";", "&")
	raw = strings.ReplaceAll(raw, "+", "%2B")
	decoded, err := url.QueryUnescape(raw)
	if err == nil && strings.Contains(decoded, "=") && !strings.Contains(raw, "=") {
		raw = strings.ReplaceAll(decoded, "+", "%2B")
	}
	q, _ := url.ParseQuery(raw)
	out := make(url.Values)
	for k, values := range q {
		key := strings.ToLower(k)
		if name, value, ok := strings.Cut(key, "="); ok && len(values) == 1 && values[0] == "" {
			if name == "allowinsecure" || name == "allow_insecure" || name == "insecure" {
				out[name] = []string{value}
				continue
			}
		}
		out[key] = values
	}
	return out
}

func insecure(q url.Values) bool {
	for _, k := range []string{"allowinsecure", "allow_insecure", "insecure"} {
		for _, v := range q[k] {
			switch strings.ToLower(v) {
			case "1", "true", "yes":
				return true
			}
		}
	}
	return false
}

func parseVLESS(raw, source string) (config, bool) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "vless") || u.User == nil {
		return config{}, false
	}
	id, err := url.QueryUnescape(u.User.Username())
	if err != nil || !uuidRE.MatchString(id) {
		return config{}, false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || !routable(u.Hostname()) {
		return config{}, false
	}
	q := query(u.RawQuery)
	if insecure(q) {
		return config{}, false
	}
	for _, values := range q {
		if len(values) > 1 {
			return config{}, false
		}
	}
	security := strings.ToLower(q.Get("security"))
	if security != "reality" && security != "tls" {
		return config{}, false
	}
	if security == "reality" && !validReality(q.Get("pbk"), q.Get("sid")) {
		return config{}, false
	}
	sni, hostHeader := domain(q.Get("sni")), domain(q.Get("host"))
	if sni == "" && hostHeader == "" || sni != "" && !validHost(sni) || hostHeader != "" && !validHost(hostHeader) {
		return config{}, false
	}
	network := strings.ToLower(q.Get("type"))
	if network == "" {
		network = "tcp"
	}
	keyParts := []string{strings.ToLower(u.Hostname()), strconv.Itoa(port), strings.ToLower(id), security, network, sni, hostHeader}
	for _, k := range []string{"pbk", "sid", "path", "mode", "flow", "fp", "alpn", "servicename", "encryption", "extra", "packetencoding", "packetingencoding"} {
		keyParts = append(keyParts, q.Get(k))
	}
	return config{raw: raw, key: strings.Join(keyParts, "\x00"), host: u.Hostname(), port: port, uuid: id, security: security, network: network, sni: sni, hostHeader: hostHeader, fp: strings.ToLower(q.Get("fp")), pbk: q.Get("pbk"), sid: q.Get("sid"), path: q.Get("path"), source: source, query: q}, true
}

func score(c config, known map[string]bool) int {
	if !matchesDomain(c.sni, known) && !matchesDomain(c.hostHeader, known) {
		return -100
	}
	v := 24
	if c.security == "reality" {
		v += 24
	} else {
		v += 8
	}
	switch c.network {
	case "tcp":
		v += 14
	case "xhttp":
		v += 12
	case "grpc":
		v += 10
	case "ws":
		v += 7
	default:
		v -= 6
	}
	if c.pbk != "" {
		v += 12
	} else {
		v -= 20
	}
	if c.sid != "" {
		v += 4
	}
	switch c.port {
	case 443, 8443, 2053, 2083, 2087, 2096, 9443:
		v += 6
	}
	switch c.fp {
	case "chrome", "firefox", "edge", "safari":
		v += 4
	case "qq", "random", "randomized":
		v -= 8
	}
	if c.path != "" && c.network != "tcp" {
		v += 2
	}
	if _, err := netip.ParseAddr(c.host); err != nil {
		v += 2
	}
	if strings.Contains(c.source, "igareck") {
		v += 6
	}
	if strings.Contains(c.source, "ByeWhiteLists") {
		v += 4
	}
	return v
}

func shortlist(all []config, known map[string]bool, limit, perSNI int) []config {
	best := make(map[string]config)
	for _, c := range all {
		if c.security != "reality" || c.pbk == "" || c.sid == "" || c.fp == "randomized" || c.fp == "random" || c.fp == "qq" || score(c, known) < 60 {
			continue
		}
		if _, err := netip.ParseAddr(c.host); err == nil && strings.Contains(c.host, ":") {
			continue
		}
		name := c.sni
		if name == "" {
			name = c.hostHeader
		}
		k := strings.ToLower(c.host) + ":" + strconv.Itoa(c.port) + ":" + name
		if prev, ok := best[k]; !ok || score(c, known) > score(prev, known) {
			best[k] = c
		}
	}
	var ordered []config
	for _, c := range best {
		ordered = append(ordered, c)
	}
	slices.SortFunc(ordered, func(a, b config) int {
		if d := score(b, known) - score(a, known); d != 0 {
			return d
		}
		return strings.Compare(a.raw, b.raw)
	})
	counts := make(map[string]int)
	var out []config
	for _, c := range ordered {
		name := c.sni
		if name == "" {
			name = c.hostHeader
		}
		if counts[name] >= perSNI {
			continue
		}
		out = append(out, c)
		counts[name]++
		if len(out) == limit {
			break
		}
	}
	return out
}

func candidates(all, best, previous []config, known map[string]bool, limit, round int) []config {
	seen, hosts, snis := make(map[string]bool), make(map[string]int), make(map[string]int)
	var out []config
	take := func(c config) {
		if len(out) >= limit || seen[c.key] || hosts[c.host] >= 3 || snis[c.sni] >= 12 || !probeSupported(c) {
			return
		}
		seen[c.key] = true
		hosts[c.host]++
		snis[c.sni]++
		out = append(out, c)
	}
	for _, c := range previous {
		take(c)
		if len(out) >= limit/2 {
			break
		}
	}
	for _, c := range best {
		take(c)
		if len(out) >= limit/2 {
			break
		}
	}
	bySource := make(map[string][]config)
	for _, c := range all {
		if score(c, known) < 0 {
			bySource[c.source] = append(bySource[c.source], c)
		}
	}
	var sources []string
	for source := range bySource {
		sources = append(sources, source)
	}
	slices.Sort(sources)
	for _, source := range sources {
		slices.SortFunc(bySource[source], func(a, b config) int { return strings.Compare(a.raw, b.raw) })
	}
	for index := 0; len(out) < limit; index++ {
		active := false
		for _, source := range sources {
			if index < len(bySource[source]) {
				active = true
				entries := bySource[source]
				take(entries[(round+index)%len(entries)])
			}
			if len(out) == limit {
				break
			}
		}
		if !active {
			break
		}
	}
	other := append([]config(nil), all...)
	slices.SortFunc(other, func(a, b config) int {
		if d := score(b, known) - score(a, known); d != 0 {
			return d
		}
		return strings.Compare(a.raw, b.raw)
	})
	for _, c := range other {
		if len(out) == limit {
			break
		}
		take(c)
	}
	return out
}

func previousChecked(path string, current map[string]config) ([]config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var previous []config
	for _, raw := range splitConfigs(string(b)) {
		if c, ok := parseVLESS(raw, ""); ok {
			if current, exists := current[c.key]; exists {
				previous = append(previous, current)
			}
		}
	}
	return previous, nil
}

func validateSnapshot(path string, count, working, total int) error {
	if working*2 < total {
		return fmt.Errorf("only %d/%d sources fetched; keeping existing feeds", working, total)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	previous := len(splitConfigs(string(b)))
	if previous > 0 && count*2 < previous {
		return fmt.Errorf("only %d/%d previous links remain; keeping existing feeds", count, previous)
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, raw string) (string, error) {
	var last error
	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "vless-parser/2")
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			host := req.URL.Hostname()
			if host == "github.com" || host == "raw.githubusercontent.com" || host == "api.github.com" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
		}
		resp, err := client.Do(req)
		if err == nil {
			if resp.StatusCode == 200 {
				b, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
				resp.Body.Close()
				if readErr != nil {
					return "", readErr
				}
				if len(b) > maxBytes {
					return "", errors.New("response too large")
				}
				return string(b), nil
			}
			resp.Body.Close()
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
				break
			}
		} else {
			last = err
		}
		if i == 0 {
			time.Sleep(400 * time.Millisecond)
		}
	}
	return "", last
}

func writeFeed(path, title string, cfgs []config) (bool, error) {
	if len(cfgs) == 0 {
		return false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# profile-title: %s\n# profile-update-interval: 1\n# profile-web-page-url: https://github.com/coloramamoe/vless-parser\n# profile-content-type: vless\n# profile-count: %d\n\n", title, len(cfgs))
	for _, c := range cfgs {
		b.WriteString(c.raw)
		b.WriteByte('\n')
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == b.String() {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(b.String()), 0644)
}

func run() error {
	dry := flag.Bool("dry-run", false, "print counts without writing files")
	check := flag.Bool("check", false, "probe through Mihomo")
	mihomo := flag.String("mihomo", "mihomo", "Mihomo binary")
	limit := flag.Int("limit", 350, "shortlist size")
	probeLimit := flag.Int("probe-limit", 160, "maximum live probes")
	workers := flag.Int("workers", 8, "concurrent source fetches and probes")
	allowShrink := flag.Bool("allow-shrink", false, "allow a large feed drop")
	root := flag.String("root", ".", "repository root")
	links := flag.Bool("check-links", false, "check source and README links")
	flag.Parse()
	if *links {
		return checkLinks(*root)
	}
	if *workers < 1 || *workers > 32 || *limit < 1 || *probeLimit < 1 {
		return errors.New("invalid limit or workers")
	}
	sources, err := lines(filepath.Join(*root, "sources/vless.txt"))
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return errors.New("no sources")
	}
	client := &http.Client{Timeout: 12 * time.Second}
	known, err := loadDomains(*root, client)
	if err != nil {
		return err
	}
	type result struct {
		text string
		err  error
	}
	results := make([]result, len(sources))
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	for i, source := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i].text, results[i].err = fetch(context.Background(), client, source)
		}()
	}
	wg.Wait()
	allMap := make(map[string]config)
	working := 0
	for i, r := range results {
		if r.err != nil {
			fmt.Printf("src %d: %v\n", i+1, r.err)
			continue
		}
		working++
		found := 0
		links := splitConfigs(r.text)
		for _, link := range links {
			if c, ok := parseVLESS(link, sources[i]); ok {
				if _, exists := allMap[c.key]; !exists {
					allMap[c.key] = c
					found++
				}
			}
		}
		fmt.Printf("src %d: %d/%d new VLESS\n", i+1, found, len(links))
	}
	if len(allMap) == 0 {
		return errors.New("no valid VLESS; keeping existing files")
	}
	if !*allowShrink {
		if err := validateSnapshot(filepath.Join(*root, "githubmirror/full.txt"), len(allMap), working, len(sources)); err != nil {
			return err
		}
	}
	var all, whitelist []config
	for _, c := range allMap {
		all = append(all, c)
		if matchesDomain(c.sni, known) || matchesDomain(c.hostHeader, known) {
			whitelist = append(whitelist, c)
		}
	}
	order := func(xs []config) {
		slices.SortFunc(xs, func(a, b config) int {
			if d := strings.Compare(a.sni+a.hostHeader, b.sni+b.hostHeader); d != 0 {
				return d
			}
			return strings.Compare(a.raw, b.raw)
		})
	}
	order(all)
	order(whitelist)
	best := shortlist(whitelist, known, *limit, 8)
	var checked []config
	if *check {
		previous, err := previousChecked(filepath.Join(*root, "githubmirror/internet.txt"), allMap)
		if err != nil {
			return err
		}
		selected := candidates(all, best, previous, known, *probeLimit, int(time.Now().UTC().Unix()/(9*60)))
		checked, err = probe(*mihomo, selected, *workers)
		if err != nil {
			return err
		}
		order(checked)
		fmt.Printf("probe: %d/%d passed twice\n", len(checked), len(selected))
	}
	if !*dry {
		feeds := []struct {
			name, title string
			items       []config
		}{
			{"full.txt", "Full", all},
			{"whitelist-vless.txt", "VLESS | Whitelist", whitelist},
			{"ru-sni-best-vless.txt", "VLESS | RU shortlist", best},
			{"internet.txt", "Internet", checked},
		}
		for _, feed := range feeds {
			changed, err := writeFeed(filepath.Join(*root, "githubmirror", feed.name), feed.title, feed.items)
			if err != nil {
				return err
			}
			if changed {
				fmt.Printf("updated %s\n", feed.name)
			}
		}
	}
	fmt.Printf("done: %d/%d sources, %d full, %d whitelist, %d shortlist, %d internet\n", working, len(sources), len(all), len(whitelist), len(best), len(checked))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
