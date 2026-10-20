package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ANSI Color Codes for Terminal Display
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// Custom Branding Logo
func printLogo() {
	banner := `
  ____             _                   _             _ 
 / ___|  ___  ___ | |  _ __  _ __ ___ | |_ ___   ___| |
 \___ \ / _ \/ __|| | | '_ \| '__/ _ \| __/ _ \ / _ \ |
  ___) |  __/ (__ | |_| |_) | | | (_) | || (_) |  __/ |
 |____/ \___|\___||_(_) .__/|_|  \___/ \__\___/ \___|_|
                      |_|                              
`
	fmt.Println(ColorCyan + ColorBold + banner + ColorReset)
	fmt.Println(ColorYellow + "========================================================" + ColorReset)
	fmt.Println(ColorBold + "   Website Testing Developer by Swami" + ColorReset)
	fmt.Println(ColorYellow + "========================================================\n" + ColorReset)
}

// Target security headers
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

func checkWebsite(rawURL string) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Printf(ColorRed+"[!] Invalid URL: %v\n"+ColorReset, err)
		return
	}

	// Timeout & Transport settings
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: customTransport,
	}

	fmt.Printf(ColorBold+"[*] Scanning Target: %s\n"+ColorReset, parsedURL.String())
	fmt.Println(ColorYellow + "--------------------------------------------------------" + ColorReset)

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		fmt.Printf(ColorRed+"[!] Request creation error: %v\n"+ColorReset, err)
		return
	}
	req.Header.Set("User-Agent", "Swami-WebAudit-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[!] Connection Error: %v\n"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP Status: %s%s%s\n\n", ColorGreen+ColorBold, resp.Status, ColorReset)
	fmt.Println(ColorBold + "--- Security Headers Analysis ---" + ColorReset)

	for _, header := range securityHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			fmt.Printf("%s[+] %s: PRESENT%s\n    Value: %s\n", ColorGreen, header, ColorReset, value)
		} else {
			fmt.Printf("%s[-] %s: MISSING%s\n", ColorRed, header, ColorReset)
		}
	}

	fmt.Println(ColorYellow + "\n========================================================" + ColorReset)
	fmt.Println(ColorCyan + "   Audit completed by Swami Security Tool" + ColorReset)
	fmt.Println(ColorYellow + "========================================================\n" + ColorReset)
}

func main() {
	printLogo()

	var target string
	fmt.Print(ColorBold + "Enter website URL (e.g., example.com): " + ColorReset)
	fmt.Scanln(&target)

	if strings.TrimSpace(target) == "" {
		fmt.Println(ColorRed + "[!] Target URL cannot be empty." + ColorReset)
		return
	}

	checkWebsite(target)
}
