# 🎯 Freddy — AI Cybersecurity Terminal Copilot

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔐 FREDDY - AI Cyber Intelligence Terminal Copilot 🔐      ║
║                                                               ║
║   Your AI SOC Analyst in the Terminal                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

Freddy is a **terminal-based AI security assistant** that runs security tools, analyzes their output, and provides **actionable remediation guidance** using the Anthropic Claude API.

Freddy is purpose-built for **authorized defensive security analysis** on Linux systems, helping security professionals and system administrators identify vulnerabilities, misconfigurations, and attack indicators — then fix them.

---

## ✨ Features at a Glance

| Feature | Command | What It Does |
|---------|---------|--------------|
| 🔍 **Nmap Scanning** | `scan <target>` | Scan targets for open ports and services |
| 📍 **Port Analysis** | `ports` | Enumerate and analyze open ports on local systems |
| 📋 **Log Analysis** | `logs <file>` | Detect brute force, suspicious logins, anomalies |
| 🔐 **System Audit** | `audit` | Comprehensive security audit of firewall, services, users |
| 🌐 **Web Security** | `webcheck <target>` | Check web servers with nikto, whatweb, curl |
| 🔒 **TLS/SSL Analysis** | `tlscheck <target>` | Validate certificates and TLS configuration |
| 📡 **DNS Reconnaissance** | `dnscheck <domain>` | Query DNS records and detect misconfigurations |
| 🔎 **WHOIS Lookup** | `whois <domain>` | Identify domain registrants and infrastructure |
| 📂 **File Analysis** | `analyze <file>` | Analyze any tool output or log file |
| 🤖 **AI-Powered** | All commands | Claude provides structured security intelligence |
| 🎨 **Rich Output** | All commands | Beautiful, formatted reports with colors and panels |  

---

## 🚀 Quick Start (5 Minutes)

### 1️⃣ Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2️⃣ Get Anthropic API Key
1. Go to 🔗 [Anthropic Console](https://console.anthropic.com/)
2. Sign up or login
3. Copy your API key (`sk-ant-...`)

### 3️⃣ Set API Key
**Option A: Temporary** (this session)
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
python3 freddy.py info
```

**Option B: Permanent** (.env file)
```bash
cp .env.example .env
nano .env  # Add your API key
```

### 4️⃣ Try It!
```bash
python3 freddy.py analyze samples/sample_auth.log
```

---

## 📋 System Requirements

### ✅ OS
- 🐧 **Linux**: Kali Linux, Ubuntu, Debian, Parrot OS, or any Debian/Ubuntu-based distro
- 🪟 **WSL2** (Windows Subsystem for Linux)

### ✅ Software
- **Python 3.10+**
- **pip** (Python package manager)
- **Anthropic API Key** 🔑 (requires paid account)

### ✅ Optional Security Tools
```bash
# Install all security tools at once:
sudo apt update && sudo apt install -y \
  nmap whois dnsutils openssl net-tools iproute2 curl wget \
  nikto whatweb gobuster tshark tcpdump bind-tools traceroute
```

---

## 💻 Installation & Setup

### Clone the Repository
```bash
git clone https://github.com/yourname/Freddy.git
cd Freddy
```

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Get Anthropic API Key
👉 [Get your key here](https://console.anthropic.com/)

### Configure API Key (Choose One)

#### 🟢 Option A: Environment Variable (Recommended)
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
python3 freddy.py info
```

#### 🟡 Option B: .env File (Persistent)
```bash
cp .env.example .env
nano .env  # Edit and add your API key
# Now Freddy automatically loads it
```

#### 🔵 Option C: Bash Profile (System-wide)
```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

### Verify Installation ✅
```bash
python3 freddy.py info
```

Expected output:
```
Freddy Configuration

API Key Set: ✓
Model: claude-3-5-sonnet-20241022
Max Tokens: 4096
System Prompt: /path/to/prompts/system_prompt.txt
```

---

## 🎯 All Commands Reference

```bash
# 🔍 Scanning & Enumeration
python3 freddy.py scan <target>           # Nmap scan + AI analysis
python3 freddy.py ports                   # List and analyze open ports
python3 freddy.py webcheck <target>       # Web server security check
python3 freddy.py tlscheck <target>       # TLS/SSL certificate analysis
python3 freddy.py dnscheck <domain>       # DNS configuration check
python3 freddy.py whois <domain>          # WHOIS domain lookup

# 📋 Analysis & Auditing
python3 freddy.py analyze <file>          # Analyze any file
python3 freddy.py logs <file>             # Analyze log file
python3 freddy.py audit                   # Full system security audit

# ℹ️ Information
python3 freddy.py info                    # Show Freddy configuration
python3 freddy.py version                 # Show version information
```

---

## 🔥 Usage Examples

### Example 1: Analyze a Log File (Easiest - No Tools Required) 
```bash
python3 freddy.py analyze samples/sample_auth.log
```

**Output:**
```
🔐 FREDDY — Cyber Intelligence Report

Analysis

EXECUTIVE SUMMARY
Brute force attack detected on SSH with 1,240+ failed login attempts 
from single external IP over 5-minute period.

CONFIRMED FINDINGS
- Brute force attack underway
- 1,240+ failed password attempts
- Source: 203.0.113.50
- Weak SSH password policy

SEVERITY LEVEL
🔴 HIGH - Active attack attempts

ROOT CAUSE ANALYSIS
SSH allows weak password authentication and lacks rate limiting.

REMEDIATION STEPS
1. Install fail2ban: sudo apt install fail2ban
2. Edit /etc/ssh/sshd_config: PasswordAuthentication no
3. Use SSH keys only
4. Reload SSH: sudo systemctl restart ssh

HARDENING RECOMMENDATIONS
- Disable SSH password auth completely
- Use SSH keys
- Implement fail2ban for brute force protection
- Monitor logs with auditd/Wazuh
```

---

### Example 2: Check Open Ports (Requires sudo)
```bash
sudo python3 freddy.py ports
```

**Output:** Analysis of which ports are listening and whether they're safe.

---

### Example 3: Scan a Target (Requires nmap)
```bash
python3 freddy.py scan 8.8.8.8
```

---

### Example 4: System Security Audit (Comprehensive)
```bash
sudo python3 freddy.py audit
```

Checks:
- ✅ Open ports
- ✅ Running services
- ✅ Firewall status
- ✅ System users
- ✅ Iptables rules
- ✅ System info

---

### Example 5: Check TLS Certificate
```bash
python3 freddy.py tlscheck example.com
```

---

### Example 6: DNS Reconnaissance
```bash
python3 freddy.py dnscheck example.com
```

---

## Quick Start

---

## 🛠️ Supported Tools & Services

### 🌍 Network & Host Analysis
```
✓ nmap          (port scanning, service detection)
✓ ss            (socket statistics, open ports) ⭐ PREFERRED
✓ netstat       (network statistics, fallback)
✓ lsof          (list open files)
✓ ip            (IP routing, interface info)
✓ ping          (ICMP echo requests)
✓ traceroute    (route tracing)
✓ arp           (ARP table inspection)
```

### 📦 Packet & Traffic Analysis
```
✓ tcpdump       (packet sniffer)
✓ tshark        (Wireshark CLI)
✓ wireshark     (GUI packet analyzer)
```

### 🔍 DNS & WHOIS
```
✓ dig           (DNS lookup)
✓ nslookup      (name server lookup)
✓ host          (DNS hostname resolution)
✓ whois         (domain/IP registration lookup)
✓ dnsrecon      (DNS reconnaissance)
```

### 🌐 Web & Application Security
```
✓ nikto         (web server scanner)
✓ whatweb       (web technology identifier)
✓ gobuster      (directory/DNS brute force)
✓ ffuf          (fast web fuzzer)
✓ curl          (HTTP client, headers)
✓ wget          (file downloader)
```

### 🔐 Cryptography & TLS
```
✓ openssl       (SSL/TLS certificate inspection)
✓ testssl.sh    (TLS configuration analysis)
```

### 🐧 Linux Security & Firewall
```
✓ ssh/sshd      (SSH server configuration)
✓ ufw           (UFW firewall management)
✓ iptables      (Netfilter firewall rules)
✓ nft           (Nftables firewall)
✓ fail2ban      (intrusion prevention)
✓ journalctl    (systemd journal)
✓ systemctl     (service management)
```

### 📜 Logs
```
✓ auth.log      (authentication logs)
✓ syslog        (system logs)
✓ kern.log      (kernel logs)
✓ nginx logs    (web server logs)
✓ apache logs   (web server logs)
✓ dmesg         (kernel ring buffer)
```

### 🐳 Container & Orchestration
```
✓ docker ps     (container listing)
✓ docker inspect (container details)
✓ docker-compose (compose file analysis)
✓ systemd       (service files)
```

---

## 📁 Project Structure

```
Freddy/
│
├── 📄 freddy.py                    ← Main CLI application
├── ⚙️  config.py                    ← Configuration & API setup
├── 🤖 ai_engine.py                 ← Claude API integration
├── 📋 requirements.txt              ← Python dependencies
├── 📝 .env.example                 ← Environment template
├── 📗 README.md                    ← This file
├── 📜 LICENSE                      ← MIT License
│
├── 📂 prompts/
│   └── system_prompt.txt           ← Freddy's AI system prompt (400+ lines)
│
├── 📂 commands/                    ← CLI command handlers
│   ├── scan.py                     (nmap scanning)
│   ├── ports.py                    (port enumeration)
│   ├── analyze.py                  (file analysis)
│   ├── audit.py                    (system audit)
│   ├── webcheck.py                 (web security)
│   ├── tlscheck.py                 (TLS analysis)
│   ├── dnscheck.py                 (DNS checking)
│   ├── whois_lookup.py             (WHOIS lookup)
│   └── logs.py                     (log analysis)
│
├── 📂 modules/                     ← Reusable security modules
│   ├── tool_runner.py              (safe command execution)
│   ├── output_formatter.py         (terminal formatting)
│   ├── file_loader.py              (file reading)
│   ├── log_analyzer.py             (log patterns)
│   ├── network_analyzer.py         (network parsing)
│   ├── vulnerability_detector.py   (vuln detection)
│   └── threat_classifier.py        (severity classification)
│
└── 📂 samples/                     ← Sample tool outputs
    ├── sample_nmap.txt             (nmap scan example)
    ├── sample_auth.log             (SSH brute force example)
    ├── sample_nginx_error.log      (web server errors)
    └── sample_ss_output.txt        (open ports example)
```

---

## Usage Examples

### Example 1: Scan a Web Server

```bash
$ python3 freddy.py scan 93.184.216.34

🔍 Scanning 93.184.216.34 with Nmap...

FREDDY — Cyber Intelligence Report

Analysis

EXECUTIVE SUMMARY
Moderate security findings detected. Web server exposed, telnet service running,
MySQL listening on all interfaces.

CONFIRMED FINDINGS
- Port 22/TCP (SSH) open to the world
- Port 80/TCP (HTTP) open — unencrypted web traffic
- Port 23/TCP (Telnet) OPEN — CRITICAL vulnerability
- Port 3306/TCP (MySQL) open on 0.0.0.0:3306 — database exposed

SEVERITY LEVEL
HIGH - Multiple services unnecessarily exposed; Telnet is critical

REMEDIATION STEPS
1. Disable Telnet: systemctl disable telnetd
2. MySQL: Edit /etc/mysql/my.cnf, change bind-address to 127.0.0.1
3. SSH: Edit /etc/ssh/sshd_config, use firewall to restrict access
4. Firewall: sudo ufw deny 22,23,3306
```

### Example 2: Analyze Auth Log for Brute Force

```bash
$ python3 freddy.py logs /var/log/auth.log

📜 Analyzing logs from /var/log/auth.log...

FREDDY — Cyber Intelligence Report

Analysis

EXECUTIVE SUMMARY
Brute force attack detected on SSH service with 1,240+ failed login attempts
from single external IP over 5-minute period.

OBSERVED EVIDENCE
- 1,240+ Failed password attempts for user admin
- Source IP: 203.0.113.50
- Attempts: 14:25:00 to 14:26:45
- Usernames targeted: admin, root, user

CONFIRMED FINDINGS
- Active brute force attack underway
- Weak SSH password policy (allows weak credentials)
- No rate limiting in place

SEVERITY LEVEL
HIGH - Active attacker attempting credential compromise

REMEDIATION STEPS
1. Install fail2ban: sudo apt install fail2ban
2. Enable/configure: sudo systemctl enable fail2ban
3. Edit sshd_config: PasswordAuthentication no (use keys only)
4. Reload SSH: sudo systemctl restart ssh
5. Verify: fail2ban-client status sshd

HARDENING RECOMMENDATIONS
- Use SSH keys only, disable password auth
- Limit SSH to non-standard port (not 22)
- Implement fail2ban or rate limiting
- Monitor /var/log/auth.log with auditd or Wazuh
```

### Example 3: System Audit

```bash
$ sudo python3 freddy.py audit

🔐 Running system security audit...

ℹ  Running system security audit...
ℹ  Checking open ports (ss)...
ℹ  Checking running services...
ℹ  Checking firewall (ufw)...

FREDDY — Cyber Intelligence Report

Analysis

EXECUTIVE SUMMARY
System has reasonable security posture but several services exposed unnecessarily.

CONFIRMED FINDINGS
- SSH open on standard port 22 (should be restricted)
- Web server (nginx) on ports 80/443 (appropriate)
- MySQL exposed to all interfaces

SEVERITY LEVEL
MEDIUM - Fix database binding

REMEDIATION
[...detailed steps...]
```

---

## Troubleshooting

### "ANTHROPIC_API_KEY not set"

**Problem:** You see this error when running Freddy.

**Solution:**
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key"
python3 freddy.py scan example.com
```

Or create a .env file:
```bash
cp .env.example .env
# Edit .env with your key
nano .env
```

### "Nmap is not installed"

**Solution:**
```bash
sudo apt update
sudo apt install nmap
```

### "Permission denied" errors

**Problem:** Some commands require elevated privileges (e.g., listing all listening ports).

**Solution:**
```bash
sudo python3 freddy.py ports
sudo python3 freddy.py audit
```

### "Command timed out"

**Problem:** A tool took too long to run (e.g., nmap on large network).

**Solution:**
- Break scans into smaller targets
- Increase timeout (open `commands/*.py` and adjust `timeout` parameter)
- Run from a more powerful machine

### "No tool output"

**Problem:** A command ran but produced no output.

**Solution:**
- Verify the tool is installed: `which nmap`
- Try running the tool manually: `nmap -sV example.com`
- Check target is valid and reachable
- Look for error messages in stderr

### "curl: command not found"

**Solution:**
```bash
sudo apt install curl
```

### Rich formatting looks weird

**Problem:** Colors/boxes don't display properly.

**Solution:**
- Update Rich: `pip install --upgrade rich`
- Use `TERM=xterm-256color python3 freddy.py scan example.com`
- Check terminal supports 256 colors

---

## API Costs

Each Freddy command sends data to Anthropic's Claude API, which is **not free** but very affordable:

- **Claude 3.5 Sonnet**: ~$0.01 per small analysis (~15k input tokens)
- A typical scan analysis costs **$0.01 - $0.05**
- Logging/monitoring costs less than a cup of coffee per month

See [Anthropic Pricing](https://www.anthropic.com/pricing) for current rates.

---

## Security Considerations

1. **API Key Security**
   - Never commit `.env` to git
   - Use environment variables or `.env.example`
   - Rotate keys periodically

2. **Tool Permissions**
   - Some tools require `sudo` (scanning, firewall, etc.)
   - Be cautious when sharing sudo access
   - Use `sudo -u restricted_user` if possible

3. **Data Sent to Anthropic**
   - Freddy sends tool output to Claude API for analysis
   - Do NOT analyze sensitive customer data, credentials, or secrets
   - Review output before sending if unsure

4. **Authorized Use Only**
   - Freddy is for authorized security testing only
   - Always get written permission before scanning targets
   - Use only on systems and networks you own or have permission to test

---

---

## 🐛 Troubleshooting

### ❌ "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key"
python3 freddy.py scan example.com
```

Or use `.env` file (see Installation section above).

---

### ❌ "Nmap is not installed"
```bash
sudo apt update
sudo apt install nmap
```

---

## ⚖️ License & Legal Protection

**🔒 PROPRIETARY SOFTWARE - INTELLECTUAL PROPERTY PROTECTED**

This project is **protected under a comprehensive proprietary license**. You do NOT have permission to:

❌ **Copy** the source code  
❌ **Modify** or **fork** the project  
❌ **Distribute** or share with others  
❌ **Sell** or use commercially  
❌ **Re-publish** under a different name  
❌ **Bypass** licensing restrictions  

### ✅ What You CAN Do

✅ **Use Freddy for authorized security testing** (your own systems or with written permission)  
✅ **Team sharing** within your organization only (under your responsibility)  
✅ **Improve your security** using the analysis and recommendations  

### ✅ What You CANNOT Do

❌ **Commercial use** - No SaaS, no API services, no reselling  
❌ **Cloning/Forking** - This project cannot be forked on GitHub  
❌ **Redistribution** - Cannot share copies publicly or privately  
❌ **Copyright stripping** - Must maintain all original copyright notices  
❌ **Modifications** - No derivative works without explicit written consent  

---

## 📜 Read the Full License

**👉 [See LICENSE file for complete legal terms](./LICENSE)**

### Key License Sections:

| Section | What It Means |
|---------|--------------|
| **Ownership** | This software is proprietary. You don't own it. |
| **Grant** | You can only use it for authorized security testing. |
| **Prohibitions** | Copying, modifying, distributing = violation |
| **Commercial Use** | Absolutely prohibited without written agreement |
| **Enforcement** | Violations result in immediate license termination + legal action |
| **Damages** | Copyright infringement can result in civil damages (up to $150k+ per work) |
| **Criminal** | In some jurisdictions, this is prosecutable criminally |

---

## 🚨 Anti-Theft Protection

This project implements multiple protections against intellectual property theft:

### 1️⃣ **Copyright Protection**
- All files contain copyright headers
- Registered copyright ©2025
- Monitored for unauthorized copies

### 2️⃣ **Legal Enforcement**
- Comprehensive proprietary license with legal force
- Right to pursue civil litigation
- Right to claim damages
- Right to seek injunctions against violators

### 3️⃣ **Git Protection**
- Repository cannot be publicly forked
- License prevents redistribution
- Private use monitored and enforced

### 4️⃣ **DCMA & Regulations**
- Protected under Digital Millennium Copyright Act (DMCA)
- Compliance with international copyright law
- Export controlled under U.S. regulations

---

## 📞 Licensing & Commercial Inquiries

**Want to use Freddy commercially or need a different license?**

Contact for licensing negotiations:
```
📧 Email: licensing@example.com
🌐 Website: example.com
📋 Subject: "Freddy Enterprise License Inquiry"
```

---

## ✨ Respect the Work

This project took significant time, expertise, and resources to develop.

**Please respect the license terms.**

✅ **Use Freddy ethically**  
✅ **Don't steal or copy the code**  
✅ **Help improve cybersecurity responsibly**  
✅ **Contact us for commercial opportunities**  

---

**© 2025 Freddy Project. All Rights Reserved. Proprietary & Confidential.**

### ❌ "Permission denied" on ports/audit
Some commands need elevated privileges:
```bash
sudo python3 freddy.py ports
sudo python3 freddy.py audit
```

---

### ❌ "Command timed out"
- Break scans into smaller targets
- Increase timeout in `commands/*.py` (adjust `timeout=` parameter)
- Run from a more powerful machine

---

### ❌ "Command produced no output"
```bash
# Verify tool is installed
which nmap

# Try running manually
nmap -sV example.com

# Check target is valid and reachable
ping example.com
```

---

### ❌ "Rich formatting looks weird"
```bash
# Update Rich
pip install --upgrade rich

# Use with explicit color support
TERM=xterm-256color python3 freddy.py scan example.com
```

---

## 💰 API Pricing

Each Freddy command sends data to Anthropic's Claude API:

| Analysis Type | Tokens | Cost |
|---------------|--------|------|
| Small scan | ~15k | ~$0.01 |
| Log analysis | ~5k | ~$0.003 |
| System audit | ~20k | ~$0.02 |
| **Monthly (20 analyses)** | - | **~$0.30** ☕ |

See [Anthropic Pricing](https://www.anthropic.com/pricing) for current rates.

---

## 🔒 Security Best Practices

### 🔑 API Key Security
```bash
# ✅ DO THIS
export ANTHROPIC_API_KEY="sk-ant-..."
# ✅ OR USE .env FILE

# ❌ NEVER DO THIS
python3 freddy.py scan example.com --api-key="sk-ant-..."  # WRONG!
```

### 📂 Git & Version Control
```bash
# Ensure API key is NOT committed
echo ".env" >> .gitignore
echo "*.pyc" >> .gitignore

# Before committing:
git diff  # Make sure no API keys in code
```

### 🛡️ Data Privacy
- Freddy sends tool output to Claude API
- ⚠️ **DO NOT analyze** sensitive customer data, credentials, or secrets
- Review output before sending if unsure
- Use within closed, authorized testing environments only

### 🔐 Authorized Use Only
- ✅ Use only on systems **you own or have written permission to test**
- ✅ Follow all applicable laws and regulations
- ✅ Get explicit authorization before scanning targets
- ❌ Never use for unauthorized access or damage

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- ✅ Add support for more security tools
- ✅ Improve system prompt for better analysis
- ✅ Add command-line options (verbosity, formats, etc.)
- ✅ Create installer scripts
- ✅ Add Windows/macOS support
- ✅ Extend monitoring and logging
- ✅ Build web UI dashboard
- ✅ Add Docker containerization

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

```
MIT License - You are free to use, modify, and distribute Freddy,
as long as you include the original license notice.
```

**📝 License Summary:**
- ✅ **Commercial use** - Allowed
- ✅ **Modification** - Allowed
- ✅ **Distribution** - Allowed
- ✅ **Private use** - Allowed
- ⚠️ **Liability** - No warranty provided
- ⚠️ **License notice** - Must be included

---

## 📞 Support & Resources

| Resource | Link |
|----------|------|
| 🐛 **Bug Reports** | [GitHub Issues](https://github.com/yourname/Freddy/issues) |
| 💡 **Feature Requests** | [GitHub Discussions](https://github.com/yourname/Freddy/discussions) |
| 📚 **Documentation** | See README sections above |
| 📦 **Samples** | Check `samples/` directory |
| 🔑 **API Docs** | [Anthropic API](https://docs.anthropic.com/) |

---

## 🚫 Disclaimer

**Freddy is an educational and authorized security testing tool.**

Users are responsible for:
- ✅ Obtaining proper authorization before testing any systems
- ✅ Complying with all applicable laws and regulations
- ✅ Securing API keys and not exposing them publicly
- ✅ Using Freddy only for defensive, authorized security analysis
- ❌ NOT using Freddy for unauthorized access or damage

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

---

## 📊 Project Stats

```
┌─────────────────────────────────────┐
│  Freddy v1.0.0                      │
├─────────────────────────────────────┤
│  ✓ 9 CLI Commands                   │
│  ✓ 7 Reusable Security Modules      │
│  ✓ 50+ Tools Supported              │
│  ✓ 400+ Line System Prompt          │
│  ✓ AI-Powered Analysis              │
│  ✓ Production-Ready                 │
└─────────────────────────────────────┘
```

---

## 🎉 Getting Started Checklist

- [ ] Clone repository: `git clone https://github.com/yourname/Freddy.git`
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Get API key: https://console.anthropic.com/
- [ ] Set API key: `export ANTHROPIC_API_KEY="..."`
- [ ] Verify setup: `python3 freddy.py info`
- [ ] Try first command: `python3 freddy.py analyze samples/sample_auth.log`
- [ ] Read the docs: See README sections above
- [ ] Install security tools: `sudo apt install nmap curl openssl dnsutils`
- [ ] Run a real scan: `sudo python3 freddy.py ports`
- [ ] Share your findings! 🚀

---

## 🌟 Star This Project

If Freddy helped you secure your systems, please ⭐ star this repository!

```
GitHub: https://github.com/yourname/Freddy
```

---

**Made with ❤️ for the cybersecurity community**

**Freddy v1.0.0** — *Your AI Cybersecurity Terminal Copilot* 🔐🚀
