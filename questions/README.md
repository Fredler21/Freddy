# Freddy Question Bank

## Overview

The question bank contains **864 templated cybersecurity Q&A pairs** generated from 24 critical security topics. This is perfect for:

- **Testing** Freddy's knowledge-search capability at scale
- **Validating** answer quality across different question types
- **Benchmarking** retrieval and synthesis performance
- **Learning** what types of questions Freddy can handle

## Files

| File | Format | Use Case |
|------|--------|----------|
| `question_bank.jsonl` | JSON Lines (1 obj/line) | ML pipelines, automated testing, data processing |
| `question_bank.csv` | Spreadsheet | Manual review, Excel/Google Sheets, quick browsing |

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
  "expected_keywords": ["nmap", "port", "scan", "network", "host", "service"]
}
```

## Coverage

### By Topic (30 domains)
Network Security, Web Security, Linux Security, Authentication, Cryptography:
- Network: Nmap, Protocols, Wireshark, Firewall, VPN, BGP
- Web: OWASP Top 10, SQL Injection, XSS, Headers, Auth, APIs
- Linux: SSH, Permissions, Firewall, Logs, Container, Kernel
- Auth: Passwords, MFA, Access Control, Identity Mgmt
- Crypto: TLS/SSL, Encryption Algorithms

**Per topic:** 36 questions (balanced distribution)

### By Intent (12 types)
1. **what_is** - Definition/explanation
2. **why_matters** - Security importance
3. **how_detect** - Detection/identification  
4. **how_fix** - Remediation
5. **how_verify** - Validation
6. **common_mistakes** - Pitfalls
7. **best_practices** - Recommended approach
8. **commands** - Tool/command usage
9. **compliance** - Standards/regulations
10. **incident_response** - IR procedures
11. **testing** - Audit/assessment
12. **troubleshooting** - Problem solving

**Per intent:** 72 questions (balanced distribution)

### By Difficulty
- **Beginner:** 162 questions (18.8%) - Basic concepts
- **Intermediate:** 432 questions (50.0%) - Practical implementation
- **Advanced:** 270 questions (31.2%) - Deep technical topics

## Usage Examples

### 1. Test Knowledge-Search Command

```bash
# Run a single question
python3 freddy.py knowledge-search "What is SSH hardening?"

# Test a few questions from the bank
grep "ssh_hardening" questions/question_bank.jsonl | head -3 | while read line; do
    question=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin)['question'])")
    echo "Testing: $question"
    python3 freddy.py knowledge-search "$question"
    echo "---"
done
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

# Get all "how_fix" intent questions
grep '"intent": "how_fix"' questions/question_bank.jsonl
```

**Excel/Sheets:**
```
Just open questions/question_bank.csv in your spreadsheet editor
- Filter by topic
- Sort by difficulty
- Color-code by intent
```

### 4. Validate Answer Quality

Create a test script to score Freddy's answers:

```bash
#!/bin/bash
# test_freddy_answers.sh

hits=0
misses=0

while read line; do
    question=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin)['question'])")
    keywords=$(echo "$line" | python3 -c "import sys, json; k=json.load(sys.stdin)['expected_keywords']; print('|'.join(k))")
    
    # Ask Freddy
    answer=$(python3 freddy.py knowledge-search "$question" 2>/dev/null)
    
    # Check if answer contains expected keywords
    if echo "$answer" | grep -iqE "$keywords"; then
        ((hits++))
    else
        ((misses++))
    fi
done < questions/question_bank.jsonl

echo "Results: $hits hits, $misses misses ($(( hits * 100 / (hits + misses) ))% accuracy)"
```

### 5. Focus on Specific Topics

```bash
# Test all OWASP Top 10 questions
echo "=== OWASP Top 10 Questions ==="
grep '"topic": "owasp_top10"' questions/question_bank.jsonl | head -5 | \
  python3 -c "import sys, json; [print(json.loads(line)['question']) for line in sys.stdin]"

# Test all advanced questions
echo "=== Advanced Security Questions ==="
grep '"difficulty": "advanced"' questions/question_bank.jsonl | head -10
```

## Generation

To regenerate the question bank with different parameters:

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

To add more questions, edit `generate_question_bank.py`:

1. **Add topics:** Add to `TOPICS` dict (line ~30)
2. **Add intents:** Add to `INTENTS` dict (line ~85)
3. **Add templates:** Edit template strings in each intent
4. **Adjust difficulty:** Modify difficulty logic in `generate_questions()`

Example: Add SSH key management topic:
```python
"ssh_keys": {
    "name": "SSH Key Management",
    "keywords": ["ssh", "key", "authentication", "id_rsa", "authorized_keys"],
    "level": "intermediate"
}
```

## Statistics

- **Total Questions:** 864
- **Topics:** 24
- **Intents:** 12
- **Question Templates:** 3 per intent
- **Generated:** 2026-03-12
- **File Sizes:** 
  - JSONL: ~265 KB (compressed: ~32 KB)
  - CSV: ~225 KB

## Next Steps

1. **Test Freddy's responses** using these questions
2. **Identify gaps** in knowledge base (questions without good answers)
3. **Add premium templates** for low-scoring intents
4. **Expand topics** based on user requests
5. **Consider integrating** with CI/CD for continuous testing

---

**Questions?** See [../README.md](../README.md) for Freddy documentation.
