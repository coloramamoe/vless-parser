package main

import (
	"encoding/base64"
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
	selected := candidates([]config{ru, other}, []config{ru}, map[string]bool{"avito.ru": true}, 2)
	if len(selected) != 2 || selected[0].key != ru.key || selected[1].key != other.key {
		t.Fatal("candidate groups not mixed")
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
	bad, _ := parseVLESS(strings.Replace(sample, c.pbk, "bad", 1), "source")
	if probeSupported(bad) {
		t.Fatal("invalid Reality key probed")
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
