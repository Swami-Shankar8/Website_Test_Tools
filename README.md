# 🛡️ Website Testing Tools

A fast, concurrent, and lightweight HTTP Response Headers Security Audit Tool written in **Go (Golang)**. Created and developed by **Swami**.

---

## 📌 Features

- ⚡ **High Performance & Fast Execution:** Powered by Go's native HTTP client with built-in concurrency support.
- 🎨 **Colored Terminal Output:** Clear visual indicators (`[+] PRESENT` in Green, `[-] MISSING` in Red).
- 🔒 **Defensive Security Audit:** Checks for critical HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- ⏱️ **Safe Networking:** Includes built-in connection timeouts to prevent hangs on slow or unresponsive targets.
- 📱 **Cross-Platform Support:** Works seamlessly on **Windows (VS Code / CMD)**, **Linux**, and **Android (Termux)**.

---

## 🛠️ Security Headers Checked

| Header | Description |
| :--- | :--- |
| **Strict-Transport-Security (HSTS)** | Enforces HTTPS connections and prevents MITM attacks. |
| **Content-Security-Policy (CSP)** | Protects against Cross-Site Scripting (XSS) and data injection. |
| **X-Frame-Options** | Prevents Clickjacking attacks by restricting iframe loading. |
| **X-Content-Type-Options** | Disables MIME-type sniffing to prevent unexpected script execution. |
| **Referrer-Policy** | Controls how much referrer information is sent with requests. |
| **Permissions-Policy** | Restricts browser features (Camera, Microphone, Geolocation). |

---

## 🚀 Installation & Setup

### Prerequisites
Make sure you have **Go** installed on your system.
```bash
go version
1.Running in VS Code / Desktop (Windows / Linux / macOS)
[go mod init audit-tool
go run main.go
2.Running in Termux (Android)
pkg update && pkg upgrade -y
pkg install golang git -y
go mod init audit-tool
go run main.go](https://github.com/Swami-Shankar8/Website_Test_Tools.git)
🖥️ Usage Example
Plaintext
  ____             _                   _             _ 
 / ___|  ___  ___ | |  _ __  _ __ ___ | |_ ___   ___| |
 \___ \ / _ \/ __|| | | '_ \| '__/ _ \| __/ _ \ / _ \ |
  ___) |  __/ (__ | |_| |_) | | | (_) | || (_) |  __/ |
 |____/ \___|\___||_(_) .__/|_|  \___/ \__\___/ \___|_|
                      |_|                              

========================================================
   Website Testing Developer by Swami
========================================================

Enter website URL (e.g., example.com): apple.com

[*] Scanning Target: [https://apple.com](https://apple.com)
--------------------------------------------------------
HTTP Status: 200 OK

--- Security Headers Analysis ---
[+] Strict-Transport-Security: PRESENT
    Value: max-age=31536000; includeSubdomains; preload
[+] Content-Security-Policy: PRESENT
[+] X-Frame-Options: PRESENT
[+] X-Content-Type-Options: PRESENT
[+] Referrer-Policy: PRESENT
[-] Permissions-Policy: MISSING

========================================================
   Audit completed by Swami Security Tool
========================================================
🔨 Building Standalone Binary
If you want to compile the script into a runnable standalone binary file:

On Windows:

Bash
go build -o website_testing_tool.exe main.go
.\website_testing_tool.exe
On Linux / Termux:
go build -o website_testing_tool main.go
./website_testing_tool
📄 License & Credits
Developer: Swami

Language: Go (Golang)
