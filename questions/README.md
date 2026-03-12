# Freddy Question Bank

## Overview

The question bank contains **2,280 templated cybersecurity Q&A pairs** (expanded from 864 to cover semantic variations). This is perfect for:

- **Testing** Freddy's knowledge-search capability with semantically similar questions
- **Ensuring coverage** of 7-8 phrasings per question intent
- **Validating** answer quality across platform/tool-specific contexts (Ubuntu, OpenSSL, iptables, etc.)
- **Benchmarking** retrieval performance on varied question phrasings
- **Learning** what types of questions Freddy can handle

## Files

| File | Format | Use Case |
|------|--------|----------|
| `question_bank.jsonl` | JSON Lines (1 obj/line) | ML pipelines, automated testing, data processing |
| `question_bank.csv` | Spreadsheet | Manual review, Excel/Google Sheets, filtering |

## Question Structure

Each question includes:

```json
{
  "id": 1,
  "question": "What is nmap network scanning?",
  "topic": "nmap_scanning",
  "topic_display": "Nmap Network Scanning",
  "intent": "what_is",
  "intent_description": "Definition/explanation questions",
  "difficulty": "beginner",
  "expected_keywords": ["nmap", "port", "scan", "network", "host", "service"],
  "generated_at": "2026-03-12T18:55:30.040549"
}
```

## Coverage

### By Scope (2,280 total)
- **Base questions**: 24 topics × 12 intents × 7-8 templates = ~2,112 questions
- **Platform/tool variants**: 168 contextual variations (Ubuntu, Debian, OpenSSL, Docker, etc.)
- **Total**: 2,280 questions aligned with 42 knowledge sources

### By Topic (24 domains)
Network Security, Web Security, Linux Security, Authentication, Cryptography:
- Network: Nmap, Protocols, Wireshark, Firewall, VPN, BGP
- Web: OWASP Top 10, SQL Injection, XSS, Headers, Auth, APIs
- Linux: SSH, Permissions, Firewall, Logs, Container, Kernel
- Auth: Passwords, MFA, Access Control, Identity Mgmt
- Crypto: TLS/SSL, Encryption Algorithms

**Per topic:** 88-112 questions (balanced with contextual variants)

### By Intent (13 types - includes contextual)
1. **what_is** - Definition/explanation (192 questions)
2. **why_matters** - Security importance (168 questions)
3. **how_detect** - Detection/identification (192 questions)
4. **how_fix** - Remediation (192 questions)
5. **how_verify** - Validation (168 questions)
6. **common_mistakes** - Pitfalls (168 questions)
7. **best_practices** - Recommended approach (168 questions)
8. **commands** - Tool/command usage (192 questions)
9. **compliance** - Standards/regulations (168 questions)
10. **incident_response** - IR procedures (168 questions)
11. **testing** - Audit/assessment (168 questions)
12. **troubleshooting** - Problem solving (168 questions)
13. **contextual** - Platform/tool-specific variants (168 questions)

### By Difficulty
- **Beginner:** 402 questions (17.6%)
- **Intermediate:** 1,104 questions (48.4%)  
- **Advanced:** 774 questions (33.9%)

### Semantic Variations Included
Topics with platform/tool-specific variants (Ubuntu, Debian, OpenSSL, iptables, Docker, TOTP, JWT, etc.):
- SSH Hardening (112 questions total - includes Ubuntu/Debian/CentOS variants)
- Linux Firewall (104 questions - includes iptables/ufw variants)
- TLS/SSL Security (104 questions - includes OpenSSL/certificate contexts)
- Container Security (104 questions - includes Docker/Kubernetes variants)
- Password Security (104 questions - includes bcrypt/salting variants)
- Web Authentication (104 questions - includes JWT/OAuth/cookie contexts)
- And more...

## Usage Examples

### 1. Test Similar Questions

Since the bank includes 7-8 phrasings per intent + platform variants, similar questions will be covered:

```bash
# These all have answers available in the knowledge base
python3 freddy.py knowledge-search "How do I secure SSH?"
python3 freddy.py knowledge-search "What's SSH hardening?"
python3 freddy.py knowledge-search "How do I configure SSH on Ubuntu?"
python3 freddy.py knowledge-search "What are SSH best practices?"
python3 freddy.py knowledge-search "How do I strengthen SSH security?"
```

### 2. Parse JSONL for Bulk Testing

**Python:**
```python
import json
from pathlib import Path

with open('questions/question_bank.jsonl') as f:
    for line in f:
        question = json.loads(line)
        # Do something with each question
        print(f"{question['id']}: {question['question']}")
```

### 3. Filter by Topic or Difficulty

**Bash (JSONL):**
```bash
# Get all SSH hardening questions
grep "ssh_hardening" questions/question_bank.jsonl

# Get all beginner questions
grep '"difficulty": "beginner"' questions/question_bank.jsonl | wc -l

# Get all platform-specific variants
grep '"intent": "contextual"' questions/question_bank.jsonl | head -10
```

**Excel/Sheets:**
```
Just open questions/question_bank.csv in your spreadsheet editor
- Filter by topic
- Sort by difficulty
- Color-code by intent
- See platform variants with "contextual" intent
```

### 4. Validate Answer Coverage

Test that when you ask similar questions, Freddy returns answers:

```bash
#!/bin/bash
# similar_questions.sh

questions=(
    "What is SSH hardening?"
    "How do I harden SSH?"
    "SSH best practices"
    "Securing SSH on Ubuntu"
    "How to configure SSH properly"
)

for q in "${questions[@]}"; do
    echo "Q: $q"
    python3 freddy.py knowledge-search "$q" 2>/dev/null | head -5
    echo "---"
done
```

### 5. Check Platform/Tool Coverage

```bash
# View all contextual variations
grep '"intent": "contextual"' questions/question_bank.jsonl | \
  python3 -c "import sys, json; \
    [print(json.loads(line)['question']) for line in sys.stdin]" | sort | uniq | head -20
```

## Generation

To regenerate the question bank with custom parameters:

```bash
# Default: both JSONL and CSV
python3 generate_question_bank.py --format both

# JSONL only
python3 generate_question_bank.py --format jsonl

# CSV only
python3 generate_question_bank.py --format csv

# Custom output directory
python3 generate_question_bank.py --format both --output my_questions/
```

## Extending the Question Bank

To add more questions or variants, edit `generate_question_bank.py`:

1. **Add topics:** Add to `TOPICS` dict (line ~30)
2. **Add intents:** Add to `INTENTS` dict (line ~85)
3. **Expand templates:** Add more phrasings to each intent's template list
4. **Add platform variants:** Add to `CONTEXTUAL_VARIATIONS` dict

Example: Add SSH key management with Ubuntu/Debian variants:
```python
"ssh_keys": {
    "name": "SSH Key Management",
    "keywords": ["ssh", "key", "authentication", "id_rsa", "authorized_keys"],
    "level": "intermediate"
}

# Then add contextual variants:
CONTEXTUAL_VARIATIONS["ssh_keys"] = [
    " on Ubuntu?",
    " on Debian?",
    " with OpenSSH?",
    " for authentication?",
]
```

## Statistics

- **Total Questions:** 2,280
- **Increase from original:** 164% (864 → 2,280)
- **Topics:** 24
- **Intents:** 12 base + contextual variants
- **Question Templates:** 7-8 per intent (expanded from 3)
- **Platform/Tool Variants:** 168 (Ubuntu, Debian, OpenSSL, Docker, etc.)
- **Generated:** 2026-03-12
- **File Sizes:** 
  - JSONL: ~725 KB (compressed: ~82 KB)
  - CSV: ~625 KB

## Key Improvements

✅ **Semantic Similarity**: 7-8 phrasings per intent ensure similar questions find answers  
✅ **Platform Coverage**: Ubuntu/Debian/CentOS/OpenSSL/Docker variants included  
✅ **Difficulty Progression**: 402 beginner → 1,104 intermediate → 774 advanced  
✅ **Complete Knowledge Alignment**: All 2,280 questions map to 42 knowledge sources  
✅ **Real-World Contexts**: Questions include tool-specific and platform-specific scenarios  

## Next Steps

1. **Test with Freddy**: `python3 freddy.py knowledge-search "your similar question"`
2. **Identify gaps**: Look for questions without good answers
3. **Add premium templates**: Create multi-section answers for important intents
4. **Expand topics**: Add new domains (containers, microservices, compliance frameworks)
5. **Benchmark**: Use full bank to measure retrieval and answer quality

---

**Questions?** See [../README.md](../README.md) for Freddy documentation.

