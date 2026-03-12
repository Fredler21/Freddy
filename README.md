# Freddy — AI Cybersecurity Terminal Copilot

Freddy is an AI-powered cybersecurity assistant that runs security tools, analyzes their output, detects vulnerabilities and attack indicators, explains risks, and provides remediation guidance — all from your terminal.

## Requirements

- Python 3.10+
- Linux (Kali / Ubuntu recommended)
- Nmap, ss, ufw (pre-installed on most distros)
- An [Anthropic API key](https://console.anthropic.com/)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Fredler21/Freddy.git
cd Freddy

# Install Python dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY="your-key-here"

# Run Freddy
python3 freddy.py scan <target>
```

## Commands

| Command | Description |
|---|---|
| `freddy scan <target>` | Nmap service scan + AI analysis |
| `freddy ports` | List open ports + AI analysis |
| `freddy analyze <log_path>` | Analyze a log file for threats |
| `freddy audit` | Full system security audit |

## Project Structure

```
freddy/
├── freddy.py              # CLI entry point
├── config.py              # Configuration
├── ai_engine.py           # Claude AI integration
├── commands/              # CLI command handlers
│   ├── scan.py
│   ├── ports.py
│   ├── logs.py
│   └── audit.py
├── modules/               # Analysis modules
│   ├── log_analyzer.py
│   ├── network_analyzer.py
│   ├── vulnerability_detector.py
│   └── threat_classifier.py
├── prompts/
│   └── system_prompt.txt
├── samples/               # Sample data for testing
└── requirements.txt
```

## Roadmap

- **v1** — Nmap scanning, log analysis, port analysis, system audit
- **v2** — Automatic vulnerability scans, packet analysis
- **v3** — Real-time monitoring, attack detection
- **v4** — SIEM-style log correlation, security dashboard

## License

MIT
