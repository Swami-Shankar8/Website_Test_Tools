package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// Target Security Headers
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// Common Network Ports
var commonPorts = []int{80, 443, 8080, 8443, 21, 22, 25, 3306}

func printBanner() {
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
	fmt.Println(ColorBold + "   Website Testing & Recon Tool - Developer: Swami" + ColorReset)
	fmt.Println(ColorYellow + "========================================================\n" + ColorReset)
}

// Option 1: Extended Server Info, Technology Stack, Allowed Methods & Headers
func inspectServerAndHeaders(targetDomain string) {
	if !strings.HasPrefix(targetDomain, "http://") && !strings.HasPrefix(targetDomain, "https://") {
		targetDomain = "https://" + targetDomain
	}

	parsedURL, err := url.Parse(targetDomain)
	if err != nil {
		fmt.Printf(ColorRed+"[!] Invalid URL: %v\n"+ColorReset, err)
		return
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	fmt.Printf(ColorBold+"\n[*] Auditing Target: %s\n"+ColorReset, parsedURL.String())
	fmt.Println(ColorYellow + "--------------------------------------------------------" + ColorReset)

	// 1. GET Request for General Headers
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		fmt.Printf(ColorRed+"[!] Request creation error: %v\n"+ColorReset, err)
		return
	}
	req.Header.Set("User-Agent", "Swami-WebAudit-Tool/2.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[!] Connection Error: %v\n"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	// Server & Stack Information
	fmt.Printf("HTTP Status Code : %s%s%s\n", ColorGreen+ColorBold, resp.Status, ColorReset)
	
	server := resp.Header.Get("Server")
	if server != "" {
		fmt.Printf("Server Software  : %s%s%s\n", ColorCyan, server, ColorReset)
	} else {
		fmt.Println("Server Software  : " + ColorYellow + "Hidden / Undisclosed" + ColorReset)
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		fmt.Printf("Technology Stack : %s%s%s\n", ColorCyan, poweredBy, ColorReset)
	} else {
		fmt.Println("Technology Stack : " + ColorYellow + "Not Disclosed in Headers" + ColorReset)
	}

	// 2. Query Allowed Methods via OPTIONS Request
	optionsReq, _ := http.NewRequest("OPTIONS", parsedURL.String(), nil)
	optionsResp, err := client.Do(optionsReq)
	if err == nil {
		allowHeader := optionsResp.Header.Get("Allow")
		if allowHeader != "" {
			fmt.Printf("Allowed Methods  : %s%s%s\n", ColorGreen, allowHeader, ColorReset)
		} else {
			fmt.Println("Allowed Methods  : " + ColorYellow + "Header Not Returned" + ColorReset)
		}
		optionsResp.Body.Close()
	}

	// 3. SSL/TLS Details
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		fmt.Printf("SSL Certificate  : Issuer [%s] | Expires [%s]\n", cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"))
	}

	// 4. Security Headers Checklist
	fmt.Println(ColorBold + "\n--- Security Headers Checklist ---" + ColorReset)
	for _, header := range securityHeaders {
		val := resp.Header.Get(header)
		if val != "" {
			fmt.Printf("%s[+] %s: PRESENT%s\n", ColorGreen, header, ColorReset)
		} else {
			fmt.Printf("%s[-] %s: MISSING%s\n", ColorRed, header, ColorReset)
		}
	}
}

// Option 2: Basic Port Accessibility Check
func checkOpenPorts(domain string) {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")

	fmt.Printf(ColorBold+"\n[*] Checking Common Network Ports on: %s\n"+ColorReset, domain)
	fmt.Println(ColorYellow + "--------------------------------------------------------" + ColorReset)

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", domain, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)

		if err != nil {
			fmt.Printf("%s[-] Port %d: CLOSED / TIMEOUT%s\n", ColorRed, port, ColorReset)
		} else {
			conn.Close()
			fmt.Printf("%s[+] Port %d: OPEN%s\n", ColorGreen, port, ColorReset)
		}
	}
}

// Option 3: DNS & IP Address Lookup
func resolveDNS(domain string) {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")

	fmt.Printf(ColorBold+"\n[*] Resolving DNS Records for: %s\n"+ColorReset, domain)
	fmt.Println(ColorYellow + "--------------------------------------------------------" + ColorReset)

	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf(ColorRed+"[!] DNS Lookup failed: %v\n"+ColorReset, err)
		return
	}

	for _, ip := range ips {
		fmt.Printf("[+] IP Address: %s%s%s\n", ColorCyan, ip.String(), ColorReset)
	}
}

func main() {
	printBanner()

	var target string
	fmt.Print(ColorBold + "Enter Target Domain/URL (e.g., example.com): " + ColorReset)
	fmt.Scanln(&target)

	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Println(ColorRed + "[!] Target cannot be empty." + ColorReset)
		return
	}

	for {
		fmt.Println("\n" + ColorYellow + "=================== SELECT OPTION ===================" + ColorReset)
		fmt.Println(" 1. Server Info, Tech Stack, Allowed Methods & Headers")
		fmt.Println(" 2. Basic Port Accessibility Check")
		fmt.Println(" 3. DNS & IP Address Lookup")
		fmt.Println(" 4. Exit")
		fmt.Println(ColorYellow + "=====================================================" + ColorReset)
		fmt.Print(ColorBold + "Choose an option (1-4): " + ColorReset)

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			inspectServerAndHeaders(target)
		case 2:
			checkOpenPorts(target)
		case 3:
			resolveDNS(target)
		case 4:
			fmt.Println(ColorCyan + "\nExiting Swami Security Tool. Goodbye!" + ColorReset)
			return
		default:
			fmt.Println(ColorRed + "[!] Invalid choice! Please select 1, 2, 3, or 4." + ColorReset)
		}
	}
}
