<div id="top">

<!-- HEADER STYLE: CLASSIC -->
<div align="center">

<img src="https://ghost.org/images/logos/ghost-logo-dark.png" width="200" alt="GhostScan Logo"/>

<p align="center">
  <strong>👻 Security Scanner for Ghost CMS 👻</strong>
</p>

# GHOSTSCAN

<em></em>

<!-- BADGES -->
<!-- local repository, no metadata badges. -->

<em>Built with the tools and technologies:</em>

<img src="https://img.shields.io/badge/Go-00ADD8.svg?style=flat-square&logo=Go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/Docker-2496ED.svg?style=flat-square&logo=Docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/SQLite-003B57.svg?style=flat-square&logo=SQLite&logoColor=white" alt="SQLite">
<img src="https://img.shields.io/badge/YAML-CB171E.svg?style=flat-square&logo=YAML&logoColor=white" alt="YAML">
<img src="https://img.shields.io/badge/JSON-000000.svg?style=flat-square&logo=JSON&logoColor=white" alt="JSON">
<img src="https://img.shields.io/badge/Prometheus-E6522C.svg?style=flat-square&logo=Prometheus&logoColor=white" alt="Prometheus">
<br>
<img src="https://img.shields.io/badge/Cobra-000000.svg?style=flat-square&logo=Go&logoColor=white" alt="Cobra CLI">
<img src="https://img.shields.io/badge/Viper-000000.svg?style=flat-square&logo=Go&logoColor=white" alt="Viper Config">
<img src="https://img.shields.io/badge/Resty-00ADD8.svg?style=flat-square&logo=Go&logoColor=white" alt="Resty HTTP">
<img src="https://img.shields.io/badge/Logrus-000000.svg?style=flat-square&logo=Go&logoColor=white" alt="Logrus">
<img src="https://img.shields.io/badge/Alpine%20Linux-0D597F.svg?style=flat-square&logo=Alpine-Linux&logoColor=white" alt="Alpine Linux">
<img src="https://img.shields.io/badge/BSD--2--Clause-AB2B28.svg?style=flat-square&logo=BSD&logoColor=white" alt="BSD-2-Clause License">

</div>
<br>

---

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
    - [Project Index](#project-index)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Usage](#usage)
    - [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

**GhostScan** is a security scanner specifically designed for Ghost CMS penetration testing and security assessment. More powerful than WPScan, GhostScan offers comprehensive analysis of Ghost CMS installations with extensive enumeration capabilities, intelligent vulnerability detection, and attack vectors tailored for Ghost CMS.

Built with penetration testers and security researchers in mind, GhostScan performs deep analysis of Ghost CMS installations, providing professional-grade security scanning capabilities that go beyond basic vulnerability detection.

---

## Features

### 🎯 **Ghost CMS Specialized**
- **Ghost Detection**: Multi-vector Ghost CMS fingerprinting
- **Version Fingerprinting**: Precise version detection with build information
- **Theme & Plugin Enumeration**: Comprehensive discovery of installed components
- **API Endpoint Discovery**: Intelligent Ghost API enumeration
- **Configuration Analysis**: Deep configuration and security posture assessment

### 🔐 **Security Assessment**
- **CVE Database Integration**: Real-time vulnerability scanning with latest CVEs
- **Exploit Integration**: Built-in exploit modules for known vulnerabilities
- **Security Misconfiguration Detection**: Security hardening checks
- **Admin Panel Discovery**: Multiple techniques for admin interface detection
- **Database Information Disclosure**: Detection of database leaks and exposures

### ⚡ **Enumeration**
- **User & Author Discovery**: Multi-vector user enumeration techniques
- **Content Discovery**: Posts, pages, tags, and metadata enumeration
- **Integration Detection**: Third-party service and webhook discovery
- **Route Mapping**: Complete application route discovery
- **File & Directory Discovery**: Sensitive file and backup detection

### 🔨 **Attack Capabilities**
- **Intelligent Brute Force**: Multi-target brute force (admin, API, login forms)
- **Custom Wordlists**: Support for custom username and password lists
- **Rate Limiting Bypass**: Techniques to bypass rate limiting
- **Session Management**: Intelligent session handling and cookie management

### 🛡️ **Stealth & Evasion**
- **Passive Scanning**: Non-intrusive reconnaissance mode
- **Random User Agents**: Rotating user agent strings
- **Request Throttling**: Configurable delays and randomization
- **Proxy Support**: Full HTTP/HTTPS proxy integration
- **SSL Bypass**: Options for SSL certificate validation bypass

### 📊 **Professional Reporting**
- **Multiple Output Formats**: Text, JSON, XML, CSV export
- **Detailed Logging**: Comprehensive audit trails
- **Risk Assessment**: Automated risk scoring and prioritization
- **Executive Summary**: High-level security posture reporting

---

## Project Structure

```sh
└── ghostscan/
    ├── 25.2
    ├── Dockerfile
    ├── LICENSE
    ├── Makefile
    ├── README.md
    ├── cmd
    │   ├── brute.go
    │   ├── enumerate.go
    │   ├── ghostscan
    │   ├── root.go
    │   ├── scan.go
    │   └── vuln.go
    ├── configs
    │   ├── bruteforce.yaml
    │   ├── enumeration.yaml
    │   ├── output.yaml
    │   ├── scanner.yaml
    │   └── vulnerabilities.yaml
    ├── examples
    │   └── usage_examples.sh
    ├── ghostscan
    ├── go.mod
    ├── go.sum
    ├── helm
    │   └── ghostscan
    ├── k8s
    │   └── deployment.yaml
    ├── main.go
    ├── pkg
    │   ├── bruteforce
    │   ├── cache
    │   ├── cli
    │   ├── config
    │   ├── database
    │   ├── enumeration
    │   ├── exploits
    │   ├── fingerprint
    │   ├── ghost
    │   ├── logging
    │   ├── monitoring
    │   ├── output
    │   ├── payloads
    │   ├── performance
    │   ├── pool
    │   ├── reporting
    │   ├── scanner
    │   ├── security
    │   ├── themes
    │   ├── ui
    │   └── vulnerabilities
    ├── tests
    │   └── integration_test.go
    └── wordlists
        ├── endpoints.txt
        ├── passwords.txt
        ├── themes.txt
        └── usernames.txt
```

### Project Index

<details open>
	<summary><b><code>GHOSTSCAN/</code></b></summary>
	<!-- __root__ Submodule -->
	<details>
		<summary><b>__root__</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ __root__</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='go.mod'>go.mod</a></b></td>
					<td style='padding: 8px;'>Go module definition and dependencies</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='LICENSE'>LICENSE</a></b></td>
					<td style='padding: 8px;'>BSD-2-Clause License for the project</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='Dockerfile'>Dockerfile</a></b></td>
					<td style='padding: 8px;'>Docker container configuration</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='Makefile'>Makefile</a></b></td>
					<td style='padding: 8px;'>Build automation and project tasks</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='main.go'>main.go</a></b></td>
					<td style='padding: 8px;'>Main application entry point</td>
				</tr>
			</table>
		</blockquote>
	</details>
</details>

---

## Getting Started

### Prerequisites

- **Go**: Version 1.21 or higher
- **Git**: For cloning the repository
- **Internet Connection**: For vulnerability database updates

### Installation

#### From Source

```bash
# Clone the repository
git clone https://github.com/ibrahmsql/ghostscan.git
cd ghostscan

# Build the application
go mod tidy
go build -o ghostscan cmd/ghostscan/main.go

# Make it executable
chmod +x ghostscan
```

#### Using Docker

```bash
# Build Docker image
docker build -t ghostscan .

# Run with Docker
docker run --rm ghostscan -u https://example.com
```

#### Using Make

```bash
# Build using Makefile
make build

# Install to system
make install

# Run tests
make test
```

### Usage

#### Basic Scanning

```bash
# Quick Ghost CMS detection and basic security scan
./ghostscan -u https://example.com

# Comprehensive scan with all enumeration
./ghostscan -u https://target.com --enumerate all --verbose

# Passive reconnaissance (stealth mode)
./ghostscan -u https://target.com --passive --random-user-agent
```

#### Enumeration

```bash
# Full enumeration of all Ghost components
./ghostscan -u https://target.com --enumerate all

# Specific component enumeration
./ghostscan -u https://target.com --detect-themes --detect-users --detect-plugins

# API and admin discovery
./ghostscan -u https://target.com --detect-api --detect-admin --detect-routes
```

#### Security Assessment

```bash
# Comprehensive vulnerability scan
./ghostscan -u https://target.com --vuln-scan --aggressive

# Update vulnerability database and scan
./ghostscan -u https://target.com --update --vuln-scan
```

#### Brute Force Attacks

```bash
# Admin panel brute force
./ghostscan -u https://target.com --brute-admin --userlist users.txt --passlist passwords.txt

# API endpoint brute force
./ghostscan -u https://target.com --brute-api --brute-users
```

### Testing

```bash
# Run unit tests
go test ./...

# Run integration tests
go test -tags=integration ./tests/

# Run with coverage
go test -cover ./...

# Benchmark tests
go test -bench=. ./...
```

---

## Roadmap

- [ ] **Enhanced Vulnerability Detection**
  - [ ] Machine learning-based anomaly detection
  - [ ] Custom vulnerability rule engine
  - [ ] Integration with external threat intelligence

- [ ] **Enhanced Reporting**
  - [ ] HTML report generation
  - [ ] PDF export functionality
  - [ ] Integration with SIEM systems

- [ ] **Performance Improvements**
  - [ ] Distributed scanning capabilities
  - [ ] Enhanced caching mechanisms
  - [ ] Optimized memory usage

- [ ] **Additional Features**
  - [ ] Web interface for easier usage
  - [ ] Plugin system for extensibility
  - [ ] API for integration with other tools

---

## Command Line Options

| Flag | Description | Default |
|------|-------------|----------|
| `--url, -u` | Target Ghost CMS URL (required) | - |
| `--verbose, -v` | Enable verbose output | false |
| `--output, -o` | Output file for results | stdout |
| `--format` | Output format (text, json, xml, csv) | text |
| `--enumerate, -e` | Components to enumerate | - |
| `--brute-force` | Enable brute force attack | false |
| `--threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 30 |
| `--user-agent` | Custom User-Agent string | GhostScan/1.0 |
| `--proxy` | HTTP/HTTPS proxy URL | - |
| `--passive` | Enable passive scanning mode | false |
| `--aggressive` | Enable aggressive scanning | false |
| `--random-user-agent` | Use random User-Agent strings | false |
| `--skip-ssl` | Skip SSL certificate validation | false |



## Detection Methods

### Primary Detection
1. **HTTP Headers**
   - `X-Ghost-Cache: miss/hit`
   - `X-Ghost-Version: 4.x.x`

2. **HTML Meta Tags**
   - `<meta name="generator" content="Ghost 4.48.2">`

3. **API Endpoints**
   - `/ghost/api/v4/admin/site/`
   - `/ghost/api/v4/content/settings/`
   - `/.well-known/ghost/`

4. **Static Files**
   - `/assets/built/admin.js`
   - `/content/themes/[theme]/`
   - `/ghost/assets/`

### Version Detection
1. **Direct Methods**
   - Meta generator tag parsing
   - API version responses
   - Admin asset versioning

2. **Fingerprinting**
   - JavaScript bundle analysis
   - API response structure
   - Theme helper availability

## Vulnerability Database

### High-Priority CVEs
- **CVE-2023-32235**: Path Traversal in Theme Preview (≤ 5.52.1)
- **CVE-2023-40028**: Arbitrary File Read via Theme Upload (≤ 5.58.0)
- **CVE-2024-23724**: Stored XSS via Profile Image Upload

### Security Misconfigurations
- Admin interface over HTTP
- Directory browsing enabled
- Debug mode in production
- Exposed configuration files
- Default credentials

## Example Output

```
=== GhostScan Results ===

[+] Ghost CMS Detected!
    Version: 4.48.2
    Active Theme: casper

[!] Vulnerabilities Found:
    [High] Path Traversal in Theme Preview (CVE-2023-32235)
        Description: Path traversal vulnerability in Ghost theme preview functionality
        Affected: ≤ 5.52.1
        Fixed in: 5.52.2

[*] Users Found:
    admin (admin)
    john-doe (john-doe) [Author]
    jane-smith (jane-smith) [Editor]

[*] Themes Found:
    [+] [ACTIVE] casper (v4.8.0)
        Description: The default personal blogging theme for Ghost
        Author: Ghost Foundation

[*] Interesting Files:
    /robots.txt
    /sitemap.xml
    /rss/
    /ghost/
    /content/themes/

=== Scan Summary ===
Vulnerabilities: 1
Misconfigurations: 0
Users: 3
Themes: 1
Interesting Files: 5
```

## Architecture

### Core Components
- **Scanner**: Main detection and vulnerability assessment engine
- **Enumerator**: Component discovery and information gathering
- **BruteForcer**: Authentication testing and credential discovery
- **Output**: Flexible reporting with multiple formats

### Technology Stack
- **Language**: Go 1.21+
- **HTTP Client**: Resty v2 for robust HTTP handling
- **CLI Framework**: Cobra for command-line interface
- **JSON Parsing**: gjson for fast JSON processing
- **Output**: Fatih/color for terminal colors

## Security Considerations

### Ethical Usage
- Only scan systems you own or have explicit permission to test
- Respect rate limits and avoid overwhelming target servers
- Use responsibly and in accordance with applicable laws

### Rate Limiting
- Built-in delays between requests to avoid detection
- Configurable thread count for controlled scanning
- Automatic detection of rate limiting responses

---

## Contributing

Contributions are welcome! Here's how you can help:

<details>
<summary>Contributing Guidelines</summary>

#### Fork the Project

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

</details>

---

## License

This project is licensed under the BSD-2-Clause License. See the [LICENSE](LICENSE) file for details.



---

## Acknowledgments

- **Ghost CMS Team**: For creating an excellent content management system and providing comprehensive API documentation
- **Security Community**: For responsible disclosure of vulnerabilities and continuous improvement of security practices
- **Go Community**: For excellent libraries, tools, and best practices that make development efficient
- **Contributors**: All the developers who have contributed to making GhostScan better

---

## Disclaimer

**⚠️ IMPORTANT NOTICE**

This tool is designed for **authorized security testing and educational purposes only**. Users must:

- Only scan systems they own or have explicit written permission to test
- Comply with all applicable local, state, and federal laws
- Respect the target system's resources and avoid causing disruption
- Use the tool responsibly and ethically

The authors and contributors of GhostScan are not responsible for any misuse, damage, or illegal activities performed with this tool. Users assume full responsibility for their actions.

---

<div align="center">

**[⬆ Back to Top](#top)**

</div>