package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	externalURL  = regexp.MustCompile("https?://[^\\s)\\]>`]+")
	markdownLink = regexp.MustCompile(`\[[^]]+\]\(([^)]+)\)`)
)

func checkLinks(root string) error {
	const feedPrefix = "https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/"
	sources, err := lines(filepath.Join(root, "sources/vless.txt"))
	if err != nil {
		return err
	}
	domains, err := lines(filepath.Join(root, "sources/domains.urls"))
	if err != nil {
		return err
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		return err
	}
	urls := append(append([]string(nil), sources...), domains...)
	for _, raw := range externalURL.FindAllString(string(readme), -1) {
		if !strings.Contains(raw, "/badge.svg") {
			urls = append(urls, raw)
		}
	}
	slices.Sort(urls)
	urls = slices.Compact(urls)
	if len(urls) == 0 {
		return errors.New("no links")
	}
	for _, match := range markdownLink.FindAllStringSubmatch(string(readme), -1) {
		target := match[1]
		if strings.Contains(target, "://") || strings.HasPrefix(target, "#") {
			continue
		}
		path, err := url.PathUnescape(strings.Split(target, "#")[0])
		if err != nil || filepath.IsAbs(path) || strings.HasPrefix(filepath.Clean(path), "..") {
			return fmt.Errorf("invalid local link: %s", target)
		}
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			return fmt.Errorf("broken local link: %s", target)
		}
	}
	client := &http.Client{Timeout: 20 * time.Second}
	errs := make([]error, len(urls))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, raw := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if strings.HasPrefix(raw, feedPrefix) {
				name := strings.TrimPrefix(raw, feedPrefix)
				if name == "" || strings.ContainsAny(name, "/\\") {
					errs[i] = fmt.Errorf("invalid feed link: %s", raw)
					return
				}
				if _, err := os.Stat(filepath.Join(root, "githubmirror", name)); err != nil {
					errs[i] = fmt.Errorf("missing feed: %s", raw)
				}
				return
			}
			if !strings.HasPrefix(raw, "https://") {
				errs[i] = fmt.Errorf("non-HTTPS URL: %s", raw)
				return
			}
			req, err := http.NewRequest(http.MethodGet, raw, nil)
			if err != nil {
				errs[i] = err
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", raw, err)
				return
			}
			io.CopyN(io.Discard, resp.Body, 1)
			resp.Body.Close()
			if resp.StatusCode >= 300 || resp.Request.URL.Scheme != "https" {
				errs[i] = fmt.Errorf("%s: HTTP %d", raw, resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	var failed bool
	for i, err := range errs {
		if err != nil {
			fmt.Println("FAIL", err)
			failed = true
		} else {
			fmt.Println("OK", urls[i])
		}
	}
	if failed {
		return errors.New("link check failed")
	}
	fmt.Printf("checked %d links\n", len(urls))
	return nil
}
