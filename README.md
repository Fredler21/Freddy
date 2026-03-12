# Freddy — AI Cybersecurity Terminal Copilot

Freddy is an AI-powered cybersecurity terminal assistant that runs security tools, captures their output, sends it to the Anthropic Claude API for analysis, and returns structured security intelligence — all from your terminal.

Freddy works like a **SOC analyst assistant** in your shell.

## Features

- **Nmap scanning** — scan targets for open ports and services
- **Port analysis** — list and analyze open local ports
- **Log analysis** — detect brute force, suspicious logins, anomalies
- **System audit** — check ports, firewall, services, and users
- **AI-powered** — Claude analyzes results and provides remediation guidance
- **Rich output** — formatted reports with severity, evidence, and fix steps

## Requirements

- **OS:** Linux (Kali Linux, Ubuntu, Debian)
- **Python:** 3.10+
- **Tools:** nmap, ss (iproute2), ufw, systemctl
- **API Key:** [Anthropic API key](https://console.anthropic.com/)

## Installation

```bash
# Clone the repo
git clone https://github.com/Fredler21/Freddy.git
cd Freddy

# Install system tools (if not already present)
sudo apt update
sudo apt install python3 python3-pip nmap

# Install Python dependencies
pip install -r requirements.txt

# Set your Anthropic API key
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

To make the API key persistent, add the export line to your `~/.bashrc` or `~/.zshrc`.

## Usage

```bash
# Scan a target for open ports and services
python3 freddy.py scan example.com

# List and analyze open ports on this machine
python3 freddy.py ports

# Analyze a log file for threats
python3 freddy.py analyze /var/log/auth.log

# Run a full system security audit
python3 freddy.py audit
```

## Example Output

```
╭──────────────────────────────────────────────╮
│  FREDDY — Cyber Intelligence Report         │
╰──────────────────────────────────────────────╯

╭─ Analysis ───────────────────────────────────╮
│                                              │
│  Executive Summary                           │
│  Open ports detected on target server.       │
│                                              │
│  Evidence                                    │
│  Port 22 SSH — OpenSSH 8.9p1                 │
│  Port 80 HTTP — Apache 2.4.52               │
│  Port 443 HTTPS — Apache 2.4.52             │
│                                              │
│  Severity: Medium                            │
│                                              │
│  Remediation                                 │
│  Restrict SSH access using UFW rules.        │
│                                              │
│  Verification                                │
│  sudo ufw status                             │
│                                              │
╰──────────────────────────────────────────────╯
```

## Project Structure

```
freddy/
├── freddy.py              # CLI entry point
├── config.py              # Configuration and validation
├── ai_engine.py           # Claude API integration
├── requirements.txt       # Python dependencies
├── commands/              # CLI command handlers
│   ├── scan.py            # Nmap scan command
│   ├── analyze.py         # File/log analysis command
│   ├── ports.py           # Open ports command
│   └── audit.py           # System audit command
├── modules/               # Local analysis modules
│   ├── log_analyzer.py    # Brute force & login detection
│   ├── network_analyzer.py# Port parsing utilities
│   ├── vulnerability_detector.py
│   └── threat_classifier.py
└── prompts/
    └── system_prompt.txt  # AI system prompt
```

## Roadmap

- **v1** — Nmap scanning, log analysis, port analysis, system audit *(current)*
- **v2** — Automatic vulnerability scans, packet analysis (tcpdump)
- **v3** — Real-time monitoring, attack detection
- **v4** — SIEM-style log correlation, security dashboard

## License

MIT
