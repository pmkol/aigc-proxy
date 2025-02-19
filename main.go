package main

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// Global configuration variables
	bearerKey      string // Client request key (without Bearer prefix)
	upstreamKey    string // Upstream request key (without Bearer prefix)
	skipCIDRemoval bool   // If false, intercept and remove CONTEXT_ID (enable cache); if true, do not intercept
	logLevel       string // Log level: "info", "warn", "debug"

	// Regular expressions
	contextIDRegex = regexp.MustCompile(`\[CONTEXT_ID:[^\]]+\]`)
	convTagRegex   = regexp.MustCompile("^[0-9a-fA-F]{32}$")

	// Global cache (only used if interception is enabled)
	contextCache *ContextCache
)

// ContextCache is a simple LRU cache for storing intercepted CONTEXT_ID strings
type ContextCache struct {
	capacity int
	mu       sync.Mutex
	ll       *list.List               // Stores *entry, with the oldest record at the head
	cache    map[string]*list.Element // key -> *list.Element
}

type entry struct {
	key   string
	value string
}

func NewContextCache(cap int) *ContextCache {
	return &ContextCache{
		capacity: cap,
		ll:       list.New(),
		cache:    make(map[string]*list.Element),
	}
}

func (c *ContextCache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.cache[key]; ok {
		return ele.Value.(*entry).value, true
	}
	return "", false
}

func (c *ContextCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.cache[key]; ok {
		c.ll.Remove(ele)
		delete(c.cache, key)
	}
}

func (c *ContextCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.cache[key]; ok {
		ele.Value.(*entry).value = value
		return
	}
	ele := c.ll.PushBack(&entry{key, value})
	c.cache[key] = ele
	if c.ll.Len() > c.capacity {
		// Evict the oldest record
		oldest := c.ll.Front()
		if oldest != nil {
			ent := oldest.Value.(*entry)
			delete(c.cache, ent.key)
			c.ll.Remove(oldest)
		}
	}
}

func main() {
	// Custom help message
	flag.Usage = func() {
		helpText := `
Usage: %s [options]

Options:
  -l        Listen IP (default: all interfaces)
  -p        Listen port (default: 2023)
  -api      Upstream API address (default: "https://api.openai.com")
  -key      Upstream request key (default: "")
  -bearer   Client request key (default: same as -key)
  -nocid    If set, intercept and remove [CONTEXT_ID]
  -cache    Maximum cache size (default: 10000)
  -log      Log level: "info" | "warn" | "debug" (default: "info")
  help      Show this help message

Examples:
  ./aigc-proxy -l 0.0.0.0 -p 2023 -api "https://api.example.com" -key "your-key" -nocid -cache 10000 -log debug
`
		fmt.Fprintf(os.Stderr, helpText, os.Args[0])
	}

	// If the first non-flag argument is "help", show help and exit
	if len(os.Args) > 1 && os.Args[1] == "help" {
		flag.Usage()
		os.Exit(0)
	}

	// Define command-line flags
	listenIP := flag.String("l", "", "Listen IP (default: all interfaces)")
	listenPort := flag.String("p", "2023", "Listen port (default: 2023)")
	apiAddr := flag.String("api", "https://api.openai.com", "Upstream API address")
	keyFlag := flag.String("key", "", "Upstream request key")
	bearerFlag := flag.String("bearer", "", "Client request key (default: same as -key)")
	nocidFlag := flag.Bool("nocid", false, "If set, intercept and remove [CONTEXT_ID]")
	cacheSize := flag.Int("cache", 10000, "Maximum cache size")
	logFlag := flag.String("log", "info", `Log level: "info" | "warn" | "debug" (default: "info")`)
	flag.Parse()

	// Set keys and related configurations
	upstreamKey = *keyFlag
	if *bearerFlag == "" {
		bearerKey = upstreamKey
	} else {
		bearerKey = *bearerFlag
	}
	skipCIDRemoval = !(*nocidFlag) // If -nocid is true, skipCIDRemoval is false (intercept)
	logLevel = *logFlag

	// Enable cache if interception is enabled
	if !skipCIDRemoval {
		contextCache = NewContextCache(*cacheSize)
	} else {
		contextCache = nil
	}

	// Parse upstream server address
	targetURL, err := url.Parse(*apiAddr)
	if err != nil {
		log.Fatalf("Failed to parse API address %s: %v", *apiAddr, err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	proxy.Transport = client.Transport

	// Modify request: adjust URL, handle Authorization
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host

		clientAuth := req.Header.Get("Authorization")
		clientIP := getClientIP(req)
		if logLevel == "debug" {
			log.Printf("[DEBUG] Request Method: %s, URL: %s", req.Method, req.URL.String())
			log.Printf("[DEBUG] Request Headers: %+v", req.Header)
		}
		if logLevel == "info" || logLevel == "debug" {
			log.Printf("Client IP: %s, Authorization: %s", clientIP, clientAuth)
		}

		req.Header.Del("Authorization")
		if clientAuth == "Bearer "+bearerKey {
			req.Header.Set("Authorization", "Bearer "+upstreamKey)
		}
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-IP")
		req.Host = targetURL.Host
	}

	// Modify response: if interception is enabled, intercept [CONTEXT_ID] and remove it from the response
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !skipCIDRemoval {
			convKey := getConversationKey(resp.Request)
			resp.Body = io.NopCloser(filterStream(resp.Body, convKey))
		}
		return nil
	}

	// HTTP root handler: validate Authorization, handle POST requests to restore CONTEXT_ID
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if logLevel == "debug" {
			log.Printf("[DEBUG] Incoming Request: Method=%s, URL=%s, Headers=%+v", r.Method, r.URL.String(), r.Header)
			if r.Method == http.MethodPost {
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					log.Printf("[DEBUG] Error reading request body: %v", err)
				} else {
					log.Printf("[DEBUG] Original POST Body: %s", string(bodyBytes))
				}
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		if !isValidAuth(r) {
			clientIP := getClientIP(r)
			log.Printf("Unauthorized request from IP: %s, Authorization: %s", clientIP, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		// If POST and Content-Type is JSON, and interception is enabled, restore CONTEXT_ID
		if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "application/json") && contextCache != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				log.Printf("Error reading request body: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			var reqMap map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &reqMap); err != nil {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			} else {
				convKey := getConversationKey(r)
				var chain []string
				if stored, found := contextCache.Get(convKey); found {
					trimmed := strings.TrimPrefix(stored, "[CONTEXT_ID:")
					trimmed = strings.TrimSuffix(trimmed, "]")
					if trimmed != "" {
						chain = strings.Split(trimmed, "|")
					}
					contextCache.Delete(convKey)
				}

				// Process "messages" field
				messagesRaw, ok := reqMap["messages"]
				if ok {
					messagesSlice, ok := messagesRaw.([]interface{})
					if ok {
						for i, mRaw := range messagesSlice {
							msg, ok := mRaw.(map[string]interface{})
							if !ok {
								continue
							}
							role, _ := msg["role"].(string)
							if role == "assistant" {
								content, _ := msg["content"].(string)
								// Remove existing CONTEXT_ID (if any)
								content = contextIDRegex.ReplaceAllString(content, "")
								content = strings.TrimSpace(content)
								newUUID := generateUUID()
								chain = append(chain, newUUID)
								newChainStr := "[CONTEXT_ID:" + strings.Join(chain, "|") + "]"
								msg["content"] = content + "\n" + newChainStr
								messagesSlice[i] = msg
							}
						}
						reqMap["messages"] = messagesSlice
						newChainStr := "[CONTEXT_ID:" + strings.Join(chain, "|") + "]"
						contextCache.Set(convKey, newChainStr)
					}
				}

				newBodyBytes, err := json.Marshal(reqMap)
				if err != nil {
					log.Printf("Error marshaling modified chat request: %v", err)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				} else {
					if logLevel == "debug" {
						log.Printf("[DEBUG] Final forwarded POST body: %s", string(newBodyBytes))
					}
					r.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
					r.ContentLength = int64(len(newBodyBytes))
					r.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBodyBytes)))
				}
			}
		}

		proxy.ServeHTTP(w, r)
	})

	// Construct listen address
	addr := ""
	if *listenIP == "" {
		addr = ":" + *listenPort
	} else {
		addr = *listenIP + ":" + *listenPort
	}
	log.Printf("Starting reverse proxy server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// isValidAuth checks if the request's Authorization is "Bearer "+bearerKey
func isValidAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+bearerKey
}

// getClientIP retrieves the client IP address from the request
func getClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// getOrderedConversationTags extracts all tags matching convTagRegex and with value "[tag]" from the request headers
func getOrderedConversationTags(r *http.Request) []string {
	var tags []string
	for k, v := range r.Header {
		if convTagRegex.MatchString(k) && len(v) > 0 && v[0] == "[tag]" {
			tags = append(tags, k)
		}
	}
	sort.Strings(tags)
	return tags
}

// getConversationKey constructs a conversation key from the client request's tags
func getConversationKey(r *http.Request) string {
	tags := getOrderedConversationTags(r)
	return strings.Join(tags, "|")
}

// generateUUID generates a UUIDv4 string
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Fatalf("Failed to generate UUID: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// filterStream reads the upstream response stream line by line, intercepts [CONTEXT_ID:...], and removes it from the response
func filterStream(r io.Reader, convKey string) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		scanner := bufio.NewScanner(r)
		writer := bufio.NewWriter(pw)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "[CONTEXT_ID:") {
				match := contextIDRegex.FindString(line)
				if match != "" {
					storeResponseContext(convKey, match)
				}
				line = contextIDRegex.ReplaceAllString(line, "")
				if strings.TrimSpace(line) == "" {
					continue
				}
			}
			_, err := writer.WriteString(line + "\n")
			if err != nil {
				log.Printf("Failed to write to pipe: %v", err)
				return
			}
			writer.Flush()
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Scanner error: %v", err)
			pw.CloseWithError(err)
		}
	}()
	return pr
}

// storeResponseContext stores the intercepted CONTEXT_ID in the global cache (only if interception is enabled)
func storeResponseContext(convKey, contextStr string) {
	if contextCache == nil {
		return
	}
	contextCache.Set(convKey, contextStr)
}
