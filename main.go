package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// Regex to match [CONTEXT_ID:...] strings that may appear anywhere in the text
	contextIDRegex = regexp.MustCompile(`\n?\[CONTEXT_ID:[^\]]+\]`)

	// Global configuration variables
	bearerKey      string // The key that clients need to include in their requests (without the Bearer prefix)
	upstreamKey    string // The key used for upstream requests (without the Bearer prefix)
	skipCIDRemoval bool   // If true, do not remove [CONTEXT_ID], forward the entire content as is
	logLevel       string // Log level: "info" logs all requests, "warn" logs only requests with wrong keys, "debug" logs detailed debug information
)

func main() {
	// Define startup parameters
	listenIP := flag.String("l", "", "Listening IP (default listens on all interfaces)")
	listenPort := flag.String("p", "2023", "Listening port (default 2023)")
	apiAddr := flag.String("api", "https://api.openai.com", "Upstream API address")
	keyFlag := flag.String("key", "", "Key used for upstream requests (without the Bearer prefix)")
	bearerFlag := flag.String("bearer", "", "Key that clients need to include in their requests (without the Bearer prefix), if not set, it will be the same as -key")
	nocidFlag := flag.Bool("nocid", false, "If set, intercept and remove [CONTEXT_ID], otherwise do not intercept")
	logFlag := flag.String("log", "info", `Log level: "info" logs all requests, "warn" logs only requests with wrong keys, "debug" logs detailed debug information`)
	flag.Parse()

	// Set keys and related configurations
	upstreamKey = *keyFlag
	if *bearerFlag == "" {
		bearerKey = upstreamKey
	} else {
		bearerKey = *bearerFlag
	}
	skipCIDRemoval = !*nocidFlag // Invert logic
	logLevel = *logFlag

	// Define the target upstream server URL
	targetURL, err := url.Parse(*apiAddr)
	if err != nil {
		log.Fatalf("Failed to parse API address %s: %v", *apiAddr, err)
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Set timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	proxy.Transport = client.Transport

	// Modify the request, forwarding client request headers to the upstream server
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host

		clientAuth := req.Header.Get("Authorization")
		clientIP := getClientIP(req)

		// When logging, if the client did not pass a key, display an empty string
		logAuth := clientAuth
		if logAuth == "" {
			logAuth = `""`
		}

		// If in debug mode, output more detailed request information
		if logLevel == "debug" {
			log.Printf("[DEBUG] Request Method: %s, URL: %s", req.Method, req.URL.String())
			log.Printf("[DEBUG] Request Headers: %+v", req.Header)
		}

		// Output request logs if log level is "info" or "debug"
		if logLevel == "info" || logLevel == "debug" {
			log.Printf("Client IP: %s, Authorization: %s", clientIP, logAuth)
		}

		// Remove the Authorization header from the client
		req.Header.Del("Authorization")
		// If the client's Authorization is "Bearer "+bearerKey, convert it to the upstream required "Bearer "+upstreamKey
		if clientAuth == "Bearer "+bearerKey {
			req.Header.Set("Authorization", "Bearer "+upstreamKey)
		}

		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-IP")
		req.Host = targetURL.Host
	}

	// Modify the response, wrapping the response body as a line-by-line filtered stream and extracting [CONTEXT_ID]
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Use bufio.Reader to read the first line of the upstream response body
		br := bufio.NewReader(resp.Body)
		firstLine, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}

		// If not skipping CID processing and the first line starts with "data:", try to extract [CONTEXT_ID:...]
		if !skipCIDRemoval && strings.HasPrefix(firstLine, "data:") {
			cid := contextIDRegex.FindString(firstLine)
			if cid != "" {
				// Remove the [CONTEXT_ID:...] part from the first line
				firstLine = contextIDRegex.ReplaceAllString(firstLine, "")
			}
		}

		// Process the remaining content through filterStream (also filters subsequent lines)
		filteredRest := filterStream(br)
		// Combine the first line with the remaining content
		newBody := io.MultiReader(strings.NewReader(firstLine), filteredRest)
		resp.Body = io.NopCloser(newBody)
		return nil
	}

	// HTTP root handler: Check if the Authorization is correct, otherwise return 401
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If in debug mode, print the full request information (including POST request body)
		if logLevel == "debug" {
			log.Printf("[DEBUG] Incoming Request: Method=%s, URL=%s, Headers=%+v", r.Method, r.URL.String(), r.Header)
			if r.Method == http.MethodPost {
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					log.Printf("[DEBUG] Error reading request body: %v", err)
				} else {
					log.Printf("[DEBUG] Request Body: %s", string(bodyBytes))
				}
				// Restore the request body
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		if !isValidAuth(r) {
			clientIP := getClientIP(r)
			auth := r.Header.Get("Authorization")
			logAuth := auth
			if logAuth == "" {
				logAuth = `""`
			}
			log.Printf("Unauthorized request from IP: %s, Authorization: %s", clientIP, logAuth)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
		proxy.ServeHTTP(w, r)
	})

	// Construct the listening address
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

// isValidAuth checks if the Authorization in the request is "Bearer "+bearerKey
func isValidAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+bearerKey
}

// getClientIP retrieves the client IP address from the request, supports IPv6
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

// filterStream reads the upstream response stream line by line and filters each line starting with "data:" (removes [CONTEXT_ID:...] part)
// If logLevel is "debug", it outputs each line of the stream
func filterStream(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		scanner := bufio.NewScanner(r)
		writer := bufio.NewWriter(pw)
		for scanner.Scan() {
			line := scanner.Text()
			originalLine := line
			if !skipCIDRemoval && strings.HasPrefix(line, "data:") {
				line = contextIDRegex.ReplaceAllString(line, "")
				if line == "" {
					line = originalLine
				}
			}
			if logLevel == "debug" {
				log.Printf("[DEBUG] Upstream stream line: %s", line)
			}
			if _, err := writer.WriteString(line + "\n"); err != nil {
				log.Printf("Failed to write to pipe: %v", err)
				return
			}
			if err := writer.Flush(); err != nil {
				log.Printf("Failed to flush writer: %v", err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Scanner error: %v", err)
			pw.CloseWithError(err)
		}
	}()
	return pr
}
