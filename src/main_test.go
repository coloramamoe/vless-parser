package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "vless://b12eebc2-369c-4f3c-96a0-a8bd150ca8d5@example.com:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=123456&sni=avito.ru&fp=chrome#node"

func TestSplitConfigs(t *testing.T) {
	for _, input := range []string{sample + "\n" + sample, sample + sample, base64.StdEncoding.EncodeToString([]byte(sample + "\n" + sample))} {
		if got := splitConfigs(input); len(got) != 2 {
			t.Fatalf("split: got %d", len(got))
		}
	}
	if got := splitConfigs("# comment\n" + sample); len(got) != 1 {
		t.Fatalf("comments: got %d", len(got))
	}
}

func TestParseVLESS(t *testing.T) {
	c, ok := parseVLESS(sample, "source")
	if !ok || c.sni != "avito.ru" || c.security != "reality" {
		t.Fatal("valid VLESS rejected")
	}
	for _, change := range []string{
		strings.Replace(sample, "example.com", "127.0.0.1", 1),
		strings.Replace(sample, "security=reality", "security=none", 1),
		strings.Replace(sample, "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&", "", 1),
		strings.Replace(sample, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "bad", 1),
		strings.Replace(sample, "sid=123456", "sid=123", 1),
		strings.Replace(sample, "example.com", "192.0.2.1", 1),
		strings.Replace(sample, "example.com", "100.64.0.1", 1),
		strings.Replace(sample, "example.com", "[2001:db8::1]", 1),
		strings.Replace(sample, "&fp=chrome", "&security=tls", 1),
		strings.Replace(sample, "&fp=chrome", "&allowInsecure=1", 1),
		strings.Replace(sample, "&fp=chrome", "&allowInsecure%3D1", 1),
	} {
		if _, ok := parseVLESS(change, "source"); ok {
			t.Fatalf("accepted invalid URI: %s", change)
		}
	}
	a, ok := parseVLESS(sample, "a")
	if !ok {
		t.Fatal("parse a")
	}
	b, ok := parseVLESS(strings.Replace(sample, "#node", "#other", 1), "b")
	if !ok || a.key != b.key {
		t.Fatal("fragment affected deduplication")
	}
	c, ok = parseVLESS(strings.Replace(sample, "type=tcp&security=reality", "security=reality&type=tcp", 1), "b")
	if !ok || a.key != c.key {
		t.Fatal("query order affected deduplication")
	}
}

func TestCandidatesMix(t *testing.T) {
	ru, _ := parseVLESS(sample, "a")
	other, _ := parseVLESS(strings.ReplaceAll(strings.Replace(sample, "example.com", "other.example.com", 1), "avito.ru", "example.org"), "b")
	selected := candidates([]config{ru, other}, []config{ru}, nil, map[string]bool{"avito.ru": true}, 2, 0)
	if len(selected) != 2 || selected[0].key != ru.key || selected[1].key != other.key {
		t.Fatal("candidate groups not mixed")
	}
}

func TestCandidatesRotateAndRetest(t *testing.T) {
	var all []config
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		raw := strings.ReplaceAll(strings.Replace(sample, "example.com", host, 1), "avito.ru", "outside.org")
		c, ok := parseVLESS(raw, "source")
		if !ok {
			t.Fatal("candidate rejected")
		}
		all = append(all, c)
	}
	known := map[string]bool{"avito.ru": true}
	a := candidates(all, nil, nil, known, 1, 0)
	b := candidates(all, nil, nil, known, 1, 1)
	if len(a) != 1 || len(b) != 1 || a[0].key == b[0].key {
		t.Fatal("new candidates did not rotate")
	}
	retained := candidates(all, nil, []config{all[2]}, known, 2, 0)
	if len(retained) != 2 || retained[0].key != all[2].key {
		t.Fatal("previously checked node was not retested")
	}
}

func TestDomainsFallback(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sources"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sources/domains.txt"), []byte("avito.ru\n"), 0644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("example.org\ninvalid host\n192.0.2.1\n"))
	}))
	if err := os.WriteFile(filepath.Join(root, "sources/domains.urls"), []byte(server.URL+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	known, err := loadDomains(root, server.Client())
	if err != nil || !known["avito.ru"] || !known["example.org"] || known["192.0.2.1"] {
		t.Fatal("domain source not merged", err)
	}
	server.Close()
	known, err = loadDomains(root, server.Client())
	if err != nil || !known["avito.ru"] {
		t.Fatal("local domains lost on fetch failure", err)
	}
}

func TestSnapshotGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "full.txt")
	c, _ := parseVLESS(sample, "source")
	items := make([]config, 10)
	for i := range items {
		items[i] = c
	}
	if _, err := writeFeed(path, "Full", items); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshot(path, 4, 8, 8); err == nil {
		t.Fatal("large drop accepted")
	}
	if err := validateSnapshot(path, 6, 3, 8); err == nil {
		t.Fatal("source outage accepted")
	}
	if err := validateSnapshot(path, 6, 8, 8); err != nil {
		t.Fatal("safe update rejected", err)
	}
}

func TestPreviousChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "internet.txt")
	old, _ := parseVLESS(sample, "old")
	if _, err := writeFeed(path, "Internet", []config{old}); err != nil {
		t.Fatal(err)
	}
	newer, _ := parseVLESS(strings.Replace(sample, "#node", "#current", 1), "current")
	previous, err := previousChecked(path, map[string]config{newer.key: newer})
	if err != nil || len(previous) != 1 || previous[0].raw != newer.raw {
		t.Fatal("current version of checked node not reused", err)
	}
	previous, err = previousChecked(path, nil)
	if err != nil || len(previous) != 0 {
		t.Fatal("removed source node retained", err)
	}
}

func TestDomainsAndShortlist(t *testing.T) {
	c, _ := parseVLESS(sample, "source")
	known := map[string]bool{"avito.ru": true}
	if !matchesDomain("sub.avito.ru", known) || matchesDomain("evil-avito.ru", known) {
		t.Fatal("domain boundary")
	}
	if got := shortlist([]config{c}, known, 10, 8); len(got) != 1 {
		t.Fatalf("shortlist: %d", len(got))
	}
	withoutSID, _ := parseVLESS(strings.Replace(sample, "&sid=123456", "", 1), "source")
	if got := shortlist([]config{withoutSID}, known, 10, 8); len(got) != 0 {
		t.Fatal("missing sid selected")
	}
}

func TestProbeConfig(t *testing.T) {
	c, _ := parseVLESS(sample, "source")
	if !probeSupported(c) {
		t.Fatal("supported Reality rejected")
	}
	m := proxyMap(c, "p0000")
	if m["tls"] != true || m["servername"] != "avito.ru" {
		t.Fatal("TLS config")
	}
	reality := m["reality-opts"].(map[string]any)
	if reality["short-id"] != "123456" {
		t.Fatal("Reality config")
	}
}

func TestXHTTPOptions(t *testing.T) {
	extra := `{"host":"extra.example","path":"/from-extra","noGRPCHeader":true,"scMaxEachPostBytes":0,"unknown":1}`
	raw := strings.Replace(sample, "type=tcp", "type=xhttp&extra="+url.QueryEscape(extra), 1)
	c, ok := parseVLESS(raw, "source")
	if !ok {
		t.Fatal("valid XHTTP rejected")
	}
	opts := proxyMap(c, "p0000")["xhttp-opts"].(map[string]any)
	if opts["host"] != "extra.example" || opts["path"] != "/from-extra" || opts["no-grpc-header"] != true || opts["unknown"] != nil {
		t.Fatal("XHTTP options lost or unrecognized option forwarded")
	}
	if _, exists := opts["sc-max-each-post-bytes"]; exists {
		t.Fatal("invalid XHTTP post size forwarded")
	}
}

func TestWriteFeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.txt")
	c, _ := parseVLESS(sample, "source")
	changed, err := writeFeed(path, "Full", []config{c})
	if err != nil || !changed {
		t.Fatal("first write", err)
	}
	b, _ := os.ReadFile(path)
	changed, err = writeFeed(path, "Full", []config{c})
	if err != nil || changed {
		t.Fatal("unchanged feed rewritten", err)
	}
	changed, err = writeFeed(path, "Full", nil)
	if err != nil || changed {
		t.Fatal("empty feed overwrote output", err)
	}
	after, _ := os.ReadFile(path)
	if string(b) != string(after) {
		t.Fatal("feed changed")
	}
}
