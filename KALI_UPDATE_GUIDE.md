# Updating Freddy on Kali Linux

This guide walks you through deploying the latest Freddy (with 2,280-question bank) to your Kali system.

## Quick Update

If you already have Freddy cloned on Kali, run these commands:

```bash
cd ~/Freddy
git fetch origin
git checkout main
git pull --ff-only origin main

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt

python3 freddy.py learn
```

## Fresh Installation on Kali

If you're setting up Freddy for the first time:

```bash
# Clone the repository
cd ~
git clone https://github.com/Fredler21/Freddy.git
cd Freddy

# Set up Python environment
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt

# Build knowledge index (downloads 42 PDFs, extracts text, builds vector store)
python3 freddy.py learn

# Verify it works
python3 freddy.py --help
```

## What's New in This Update

### Guided Mode for Tool Commands
- Freddy now asks a confirmation question before running tool-heavy actions.
- Example prompt: `Do you want me to scan this target: 192.168.1.0/24? [Y/n]`
- This applies to: `scan`, `recon`, `ports`, `audit`, `host-audit`, `analyze`, `investigate`, `logs`, `webcheck`, `tlscheck`, `dnscheck`, and `whois`.
- Use `--yes` or `-y` to skip prompts for scripting/automation.

### Guided Mode Examples

```bash
# Interactive mode (Freddy asks first)
python3 freddy.py scan 192.168.1.0/24
# Prompt: Do you want me to scan this target: 192.168.1.0/24? [Y/n]

python3 freddy.py recon example.com
# Prompt: Do you want me to run full reconnaissance against: example.com? [Y/n]

# Automation mode (skip prompts)
python3 freddy.py scan 192.168.1.0/24 --yes
python3 freddy.py recon example.com --yes
python3 freddy.py audit --yes
```

### 2,280-Question Bank (164% Expansion)
- **864 → 2,280 questions** with semantic variations
- **Platform/tool contexts**: Ubuntu, Debian, OpenSSL, Docker, iptables, JWT, bcrypt, etc.
- **7-8 phrasings per intent** (was 3) — similar questions get answers
- **42 knowledge sources** — all questions aligned with available knowledge

### How to Test the Question Bank

```bash
# Single question test
python3 freddy.py knowledge-search "How do I harden SSH?"
python3 freddy.py knowledge-search "What are SSH best practices on Ubuntu?"
python3 freddy.py knowledge-search "SSH configuration mistakes?"

# Bulk test from question bank
python3 generate_question_bank.py --format jsonl  # Regenerate if needed
grep "ssh_hardening" questions/question_bank.jsonl | head -5

# View random sample of questions
cat questions/question_bank.jsonl | shuf -n 10
```

## Verify Knowledge Index

After running `python3 freddy.py learn`, check the vector store:

```bash
# Check that indexing completed
ls -lh .freddy/vector_store/

# Test knowledge-search works
python3 freddy.py knowledge-search "patch management"
python3 freddy.py knowledge-search "ssh hardening"
python3 freddy.py knowledge-search "web security owasp"
```

## Examine the Question Bank

```bash
# View question bank statistics
python3 verify_question_coverage.py

# Show sample questions
python3 show_question_samples.py

# View all SSH hardening questions
grep "ssh_hardening" questions/question_bank.jsonl | wc -l
grep "ssh_hardening" questions/question_bank.jsonl | head -10

# View all platform-specific contextual questions
grep '"intent": "contextual"' questions/question_bank.jsonl | head -10
```

## Files Updated in Latest Commit

| File | Change |
|------|--------|
| `questions/question_bank.jsonl` | 864 → 2,280 questions |
| `questions/question_bank.csv` | Updated with all variations |
| `generate_question_bank.py` | 7-8 templates per intent, contextual variants |
| `questions/README.md` | Documentation for 2,280 questions |
| `README.md` | Updated testing section |
| `show_question_samples.py` | Demo script (new) |
| `verify_question_coverage.py` | Coverage verification (new) |

## Troubleshooting

### "learn" command takes a long time

This is normal on first run. The script:
1. Loads 42 knowledge files (~5-10 MB of text)
2. Chunks them into 11,546+ segments
3. Embeds each chunk (sentence-transformers)
4. Stores in ChromaDB vector database

On Kali with CPU-only: **5-15 minutes is normal**

Monitor progress:
```bash
# In another terminal
watch -n 3 'du -sh .freddy/vector_store'
ps aux | grep freddy.py
```

### knowledge-search returns no results

1. Make sure `learn` completed successfully:
   ```bash
   ls -lh .freddy/vector_store/
   ```

2. Test with a direct question:
   ```bash
   python3 freddy.py knowledge-search "nmap"
   ```

3. If still no results, rebuild index:
   ```bash
   rm -rf .freddy/vector_store
   python3 freddy.py learn
   ```

### Out of disk space during "learn"

The vector store takes ~200-300 MB. Check available space:

```bash
df -h ~
du -sh .freddy/
```

If needed, `--no-cache-dir` was already used. The issue is the vector database itself.

## Command Reference

### Core Commands

```bash
# Index knowledge (required after git pull)
python3 freddy.py learn

# Search knowledge base
python3 freddy.py knowledge-search "your question"

# View scan history
python3 freddy.py history
python3 freddy.py history --target example.com

# View memory stats
python3 freddy.py memory-stats

# Scan a target
python3 freddy.py scan <target>
python3 freddy.py scan <target> --yes

# Analyze a log file
python3 freddy.py analyze <logfile>
python3 freddy.py analyze <logfile> --yes

# Check open ports
python3 freddy.py ports
python3 freddy.py ports --yes

# Run full host audit
python3 freddy.py audit
python3 freddy.py audit --yes
```

### Prompt Behavior Quick Notes

- Press `Enter` for default `Yes` (`[Y/n]` prompt).
- Type `n` to cancel without running the command.
- Add `--yes` to bypass confirmations in batch jobs.

### Question Bank Tools

```bash
# Regenerate question bank
python3 generate_question_bank.py --format both

# Verify coverage
python3 verify_question_coverage.py

# Show samples
python3 show_question_samples.py

# Test specific topic
grep "ssh_hardening" questions/question_bank.jsonl | wc -l
```

## Next Steps

1. ✅ **Pull latest from GitHub** (includes 2,280 questions)
2. ✅ **Run `python3 freddy.py learn`** (index knowledge)
3. ✅ **Test with questions**: `python3 freddy.py knowledge-search "your question"`
4. 📊 **Review question coverage**: `python3 verify_question_coverage.py`
5. 🧪 **Test answer quality**: Use question bank to validate

## Help

For full documentation see:
- [README.md](README.md) - Main project docs
- [questions/README.md](questions/README.md) - Question bank usage guide
- `python3 freddy.py --help` - Command reference

---

**Last Updated:** 2026-03-12  
**Latest Version:** 2,280-question bank with semantic variations
