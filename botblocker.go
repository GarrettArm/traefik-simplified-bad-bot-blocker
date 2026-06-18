package traefik_simplified_bad_bot_blocker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync"

	"net/http"
	"net/netip"

	"strings"
	"time"

	log "github.com/Dakraid/traefik-simplified-bad-bot-blocker/utils"
)

type Config struct {
	IpBlocklistUrls        []string `json:"ipblocklisturls,omitempty"`
	UserAgentBlocklistUrls []string `json:"useragentblocklisturls,omitempty"`
	LogLevel               string   `json:"loglevel,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		IpBlocklistUrls:        []string{},
		UserAgentBlocklistUrls: []string{},
		LogLevel:               "INFO",
	}
}

type BotBlocker struct {
	next               http.Handler
	name               string
	prefixBlocklist    map[netip.Prefix]bool
	userAgentBlockList map[string]bool
	lastUpdated        time.Time
	mu                 sync.RWMutex
	Config
}

func (b *BotBlocker) updateIps() error {
	prefixBlockList := make(map[netip.Prefix]bool, len(b.prefixBlocklist))

	log.Info("Updating CIDR blocklist")

	type prefixResult struct {
		prefixes []netip.Prefix
		err      error
	}

	results := make(chan prefixResult, len(b.IpBlocklistUrls))

	for _, url := range b.IpBlocklistUrls {
		go func(url string) {
			resp, err := http.Get(url)
			if err != nil {
				results <- prefixResult{err: fmt.Errorf("failed fetch CIDR list: %w", err)}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode > 299 {
				results <- prefixResult{err: fmt.Errorf("failed to fetch CIDR list: received a %v from %v", resp.Status, url)}
				return
			}

			prefixes, err := readPrefixes(resp.Body)
			results <- prefixResult{prefixes: prefixes, err: err}
		}(url)
	}

	for i := 0; i < len(b.IpBlocklistUrls); i++ {
		result := <-results
		if result.err != nil {
			return result.err
		}
		for _, prefix := range result.prefixes {
			prefixBlockList[prefix] = true
		}
	}

	b.mu.Lock()
	b.prefixBlocklist = prefixBlockList
	b.mu.Unlock()

	return nil
}

func readPrefixes(prefixReader io.ReadCloser) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0)
	defer prefixReader.Close()
	scanner := bufio.NewScanner(prefixReader)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		var prefix netip.Prefix
		if strings.Contains(entry, "/") {
			var err error
			prefix, err = netip.ParsePrefix(entry)
			if err != nil {
				return []netip.Prefix{}, err
			}
		} else {
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				return []netip.Prefix{}, err
			}
			var bits int
			if addr.Is4() {
				bits = 32
			} else {
				bits = 128
			}
			prefix, err = addr.Prefix(bits)
			if err != nil {
				return []netip.Prefix{}, err
			}
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func readUserAgents(userAgentReader io.ReadCloser) ([]string, error) {
	userAgents := make([]string, 0)

	defer userAgentReader.Close()
	scanner := bufio.NewScanner(userAgentReader)
	for scanner.Scan() {
		agent := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(scanner.Text(), "\\", "")))
		userAgents = append(userAgents, agent)
	}

	return userAgents, nil
}

func (b *BotBlocker) updateUserAgents() error {
	userAgentBlockList := make(map[string]bool)

	log.Info("Updating user agent blocklist")
	for _, url := range b.UserAgentBlocklistUrls {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed fetch useragent list: %w", err)
		}
		if resp.StatusCode > 299 {
			return fmt.Errorf("failed fetch useragent list: received a %v from %v", resp.Status, url)
		}

		agents, err := readUserAgents(resp.Body)
		if err != nil {
			return err
		}
		for _, agent := range agents {
			userAgentBlockList[agent] = true
		}
	}

	b.userAgentBlockList = userAgentBlockList

	return nil
}

func (b *BotBlocker) update() error {
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)
	var ipErr, uaErr error

	go func() {
		defer wg.Done()
		ipErr = b.updateIps()
	}()

	go func() {
		defer wg.Done()
		uaErr = b.updateUserAgents()
	}()

	wg.Wait()

	if ipErr != nil {
		return fmt.Errorf("failed to update CIDR blocklists: %w", ipErr)
	}
	if uaErr != nil {
		return fmt.Errorf("failed to update user agent blocklists: %w", uaErr)
	}

	b.mu.Lock()
	b.lastUpdated = time.Now()
	b.mu.Unlock()

	duration := time.Since(startTime)
	log.Info("Updated block lists. Blocked CIDRs: ", len(b.prefixBlocklist), " Duration: ", duration)
	return nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to set log level: %w", err)
	}
	log.Default().Level = logLevel

	blocker := BotBlocker{
		name:   name,
		next:   next,
		Config: *config,
	}
	err = blocker.update()
	if err != nil {
		return nil, fmt.Errorf("failed to update blocklists: %s", err)
	}
	return &blocker, nil
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	b.mu.RLock()
	timeSinceUpdate := time.Since(b.lastUpdated)
	b.mu.RUnlock()

	if timeSinceUpdate > time.Hour {
		go func() {
			err := b.update()
			if err != nil {
				log.Errorf("Failed to update blocklist: %v", err)
			}
		}()
	}

	startTime := time.Now()
	log.Debugf("Checking request: CIDR: \"%v\" user agent: \"%s\"", req.RemoteAddr, req.UserAgent())
	defer func() {
		log.Debugf("Checked request in %v", time.Since(startTime))
	}()

	remoteAddrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, "Internal Error", http.StatusInternalServerError)
		return
	}

	b.mu.RLock()
	hasIPBlocklist := len(b.prefixBlocklist) != 0
	hasUABlocklist := len(b.userAgentBlockList) != 0
	b.mu.RUnlock()

	if hasIPBlocklist {
		if b.shouldBlockIp(remoteAddrPort.Addr()) {
			log.Infof("Blocked request with from IP %v", remoteAddrPort.Addr())
			http.Error(rw, "Blocked", http.StatusForbidden)
			return
		}
	}

	if hasUABlocklist {
		agent := strings.ToLower(req.UserAgent())
		if b.shouldBlockAgent(agent) {
			log.Infof("Blocked request with user agent %v", agent)
			http.Error(rw, "Blocked", http.StatusForbidden)
			return
		}
	}

	b.next.ServeHTTP(rw, req)
}

func (b *BotBlocker) shouldBlockIp(addr netip.Addr) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, blocked := b.prefixBlocklist[netip.PrefixFrom(addr, addr.BitLen())]; blocked {
		return true
	}

	for badPrefix := range b.prefixBlocklist {
		if badPrefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *BotBlocker) shouldBlockAgent(userAgent string) bool {
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))

	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, blocked := b.userAgentBlockList[userAgent]; blocked {
		return true
	}

	for badAgent := range b.userAgentBlockList {
		if len(badAgent) <= len(userAgent) && strings.Contains(userAgent, badAgent) {
			return true
		}
	}
	return false
}
