package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var probeURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
}

var badProxy = regexp.MustCompile(`proxy ([0-9]+):`)

func validReality(pbk, sid string) bool {
	key, err := base64.RawURLEncoding.DecodeString(pbk)
	if err != nil || len(key) != 32 || len(sid) > 16 {
		return false
	}
	_, err = hex.DecodeString(sid)
	return err == nil
}

func probeSupported(c config) bool {
	switch c.network {
	case "tcp", "ws", "grpc", "xhttp", "http", "h2":
	default:
		return false
	}
	if c.security == "reality" {
		if !validReality(c.pbk, c.sid) {
			return false
		}
	}
	switch c.fp {
	case "", "chrome", "firefox", "edge", "safari", "ios", "android":
	default:
		return false
	}
	if flow := c.query.Get("flow"); flow != "" && flow != "xtls-rprx-vision" {
		return false
	}
	return true
}

func proxyMap(c config, name string) map[string]any {
	m := map[string]any{
		"name": name, "type": "vless", "server": c.host, "port": c.port,
		"uuid": c.uuid, "tls": true, "network": c.network,
	}
	if c.sni != "" {
		m["servername"] = c.sni
	} else {
		m["servername"] = c.hostHeader
	}
	if c.fp != "" {
		m["client-fingerprint"] = c.fp
	}
	if flow := c.query.Get("flow"); flow != "" {
		m["flow"] = flow
	}
	if alpn := c.query.Get("alpn"); alpn != "" {
		m["alpn"] = strings.Split(alpn, ",")
	}
	encoding := c.query.Get("packetencoding")
	if encoding == "" {
		encoding = c.query.Get("packetingencoding")
	}
	if encoding != "" {
		m["packet-encoding"] = encoding
	}
	if encryption := c.query.Get("encryption"); encryption != "" {
		m["encryption"] = encryption
	}
	if c.security == "reality" {
		m["reality-opts"] = map[string]any{"public-key": c.pbk, "short-id": c.sid}
	}
	switch c.network {
	case "ws":
		opts := map[string]any{"path": c.path}
		if c.hostHeader != "" {
			opts["headers"] = map[string]any{"Host": c.hostHeader}
		}
		m["ws-opts"] = opts
	case "grpc":
		service := c.query.Get("servicename")
		if service == "" {
			service = c.path
		}
		m["grpc-opts"] = map[string]any{"grpc-service-name": service}
	case "xhttp":
		opts := xhttpOptions(c.query.Get("extra"))
		if c.path != "" {
			opts["path"] = c.path
		}
		if c.hostHeader != "" {
			opts["host"] = c.hostHeader
		}
		if mode := c.query.Get("mode"); mode != "" {
			opts["mode"] = mode
		}
		m["xhttp-opts"] = opts
	case "h2":
		opts := map[string]any{"path": c.path}
		if c.hostHeader != "" {
			opts["host"] = []string{c.hostHeader}
		}
		m["h2-opts"] = opts
	case "http":
		opts := map[string]any{"path": []string{c.path}}
		if c.hostHeader != "" {
			opts["headers"] = map[string]any{"Host": []string{c.hostHeader}}
		}
		m["http-opts"] = opts
	}
	return m
}

func xhttpOptions(raw string) map[string]any {
	opts := make(map[string]any)
	var fields map[string]any
	if json.Unmarshal([]byte(raw), &fields) != nil {
		return opts
	}
	names := map[string]string{
		"path": "path", "host": "host", "mode": "mode", "headers": "headers",
		"noGRPCHeader": "no-grpc-header", "xPaddingBytes": "x-padding-bytes",
		"xPaddingObfsMode": "x-padding-obfs-mode", "xPaddingKey": "x-padding-key",
		"xPaddingHeader": "x-padding-header", "xPaddingPlacement": "x-padding-placement",
		"xPaddingMethod": "x-padding-method", "uplinkHTTPMethod": "uplink-http-method",
		"sessionIDPlacement": "session-placement", "sessionIDKey": "session-key",
		"sessionIDTable": "session-table", "sessionIDLength": "session-length",
		"seqPlacement": "seq-placement", "seqKey": "seq-key",
		"uplinkDataPlacement": "uplink-data-placement", "uplinkDataKey": "uplink-data-key",
		"uplinkChunkSize": "uplink-chunk-size", "scMaxEachPostBytes": "sc-max-each-post-bytes",
		"scMinPostsIntervalMs": "sc-min-posts-interval-ms",
	}
	for key, value := range fields {
		if name, ok := names[key]; ok {
			if name == "sc-max-each-post-bytes" {
				n, ok := value.(float64)
				if !ok || n <= 0 {
					continue
				}
			}
			opts[name] = value
		}
	}
	return opts
}

func probe(binary string, selected []config, workers int) ([]config, error) {
	if len(selected) == 0 {
		return nil, nil
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vless-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address := listener.Addr().String()
	listener.Close()
	secretBytes := make([]byte, 16)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	secret := hex.EncodeToString(secretBytes)
	path := filepath.Join(dir, "config.json")
	selected, err = validateProxies(binary, dir, path, address, secret, selected)
	if err != nil || len(selected) == 0 {
		return nil, err
	}
	cmd := exec.Command(binary, "-d", dir, "-f", path)
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() { _ = cmd.Process.Kill(); <-done }
	defer func() {
		if !stopped {
			stop()
		}
	}()
	client := &http.Client{Timeout: 7 * time.Second, Transport: &http.Transport{Proxy: nil}}
	base := "http://" + address
	ready := false
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest(http.MethodGet, base+"/version", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		stop()
		stopped = true
		return nil, fmt.Errorf("mihomo did not start: %s", output.String())
	}
	type result struct {
		index, delay int
		ok           bool
	}
	results := make([]result, len(selected))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range selected {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := fmt.Sprintf("p%04d", i)
			first, ok := probeOne(client, base, secret, name, probeURLs[0])
			if !ok || first > 3000 {
				return
			}
			second, ok := probeOne(client, base, secret, name, probeURLs[1])
			if !ok || second > 3000 {
				return
			}
			results[i] = result{index: i, delay: (first + second) / 2, ok: true}
		}()
	}
	wg.Wait()
	select {
	case err := <-done:
		stopped = true
		return nil, fmt.Errorf("mihomo stopped during checks: %w: %s", err, output.String())
	default:
	}
	var checked []config
	for _, r := range results {
		if r.ok {
			c := selected[r.index]
			c.delay = r.delay
			checked = append(checked, c)
		}
	}
	return checked, nil
}

func validateProxies(binary, dir, path, address, secret string, selected []config) ([]config, error) {
	for len(selected) > 0 {
		proxies := make([]map[string]any, len(selected))
		for i, c := range selected {
			proxies[i] = proxyMap(c, fmt.Sprintf("p%04d", i))
		}
		b, err := json.Marshal(map[string]any{
			"external-controller": address, "secret": secret, "log-level": "error",
			"proxies": proxies,
		})
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			return nil, err
		}
		output, err := exec.Command(binary, "-t", "-d", dir, "-f", path).CombinedOutput()
		if err == nil {
			return selected, nil
		}
		match := badProxy.FindStringSubmatch(string(output))
		if len(match) != 2 {
			return nil, fmt.Errorf("mihomo config check: %w: %s", err, strings.TrimSpace(string(output)))
		}
		index, convErr := strconv.Atoi(match[1])
		if convErr != nil || index < 0 || index >= len(selected) {
			return nil, fmt.Errorf("mihomo config check: %w: %s", err, strings.TrimSpace(string(output)))
		}
		fmt.Printf("probe: skipped invalid proxy %d\n", index)
		selected = append(selected[:index], selected[index+1:]...)
	}
	return nil, nil
}

func probeOne(client *http.Client, base, secret, name, target string) (int, bool) {
	q := url.Values{"url": {target}, "timeout": {"6000"}, "expected": {"204"}}
	req, err := http.NewRequest(http.MethodGet, base+"/proxies/"+name+"/delay?"+q.Encode(), nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, false
	}
	var result struct {
		Delay *int `json:"delay"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result); err != nil || result.Delay == nil || *result.Delay < 0 {
		return 0, false
	}
	return *result.Delay, true
}
