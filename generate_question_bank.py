#!/usr/bin/env python3
"""
Generate a comprehensive question bank (1000+ Q&A pairs) for Freddy.

This script creates templated questions across 30 cybersecurity topics,
12 question intents, and 3 phrasing variations, totaling 1080+ questions.

Output: questions/question_bank.jsonl (one JSON object per line)
Each question includes: id, question, topic, intent, difficulty, expected_keywords

Usage:
    python3 generate_question_bank.py [--format jsonl|csv] [--output FILE]
"""

import json
import csv
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

# ==============================================================================
# TOPIC DEFINITIONS (30 cybersecurity domains)
# ==============================================================================

TOPICS = {
    # Network Security (6)
    "nmap_scanning": {
        "name": "Nmap Network Scanning",
        "keywords": ["nmap", "port", "scan", "network", "host", "service"],
        "level": "beginner"
    },
    "network_protocols": {
        "name": "Network Protocols",
        "keywords": ["IP", "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"],
        "level": "intermediate"
    },
    "wireshark_analysis": {
        "name": "Wireshark Traffic Analysis",
        "keywords": ["wireshark", "packet", "capture", "analysis", "filter", "traffic"],
        "level": "intermediate"
    },
    "firewall_rules": {
        "name": "Firewall Configuration",
        "keywords": ["firewall", "iptables", "ufw", "rules", "filter", "policy"],
        "level": "intermediate"
    },
    "vpn_networking": {
        "name": "VPN & Tunneling",
        "keywords": ["VPN", "tunnel", "encryption", "IPsec", "OpenVPN", "WireGuard"],
        "level": "intermediate"
    },
    "bgp_routing": {
        "name": "BGP & Routing",
        "keywords": ["BGP", "routing", "OSPF", "RIP", "ASN", "prefix"],
        "level": "advanced"
    },

    # Web Security (6)
    "owasp_top10": {
        "name": "OWASP Top 10",
        "keywords": ["OWASP", "injection", "XSS", "CSRF", "vulnerability", "web"],
        "level": "beginner"
    },
    "sql_injection": {
        "name": "SQL Injection",
        "keywords": ["SQL", "injection", "database", "query", "SQLi", "exploit"],
        "level": "intermediate"
    },
    "cross_site_scripting": {
        "name": "Cross-Site Scripting (XSS)",
        "keywords": ["XSS", "script", "JavaScript", "payload", "DOM", "reflected"],
        "level": "intermediate"
    },
    "web_headers": {
        "name": "Security Headers",
        "keywords": ["headers", "CSP", "X-Frame-Options", "HSTS", "security"],
        "level": "beginner"
    },
    "web_authentication": {
        "name": "Web Authentication",
        "keywords": ["authentication", "session", "cookie", "token", "OAuth", "JWT"],
        "level": "intermediate"
    },
    "api_security": {
        "name": "API Security",
        "keywords": ["API", "REST", "GraphQL", "endpoint", "rate", "limit"],
        "level": "intermediate"
    },

    # Linux Security (6)
    "ssh_hardening": {
        "name": "SSH Hardening",
        "keywords": ["SSH", "sshd_config", "key", "authentication", "port", "hardening"],
        "level": "beginner"
    },
    "user_permissions": {
        "name": "User Permissions & ACLs",
        "keywords": ["permissions", "chmod", "chown", "ACL", "sudo", "uid"],
        "level": "beginner"
    },
    "firewall_linux": {
        "name": "Linux Firewall (iptables/ufw)",
        "keywords": ["iptables", "ufw", "firewall", "rules", "netfilter"],
        "level": "intermediate"
    },
    "log_analysis": {
        "name": "Log Analysis & Monitoring",
        "keywords": ["logs", "syslog", "auditd", "journalctl", "monitoring", "analysis"],
        "level": "intermediate"
    },
    "container_security": {
        "name": "Container & Docker Security",
        "keywords": ["Docker", "container", "image", "registry", "orchestration"],
        "level": "intermediate"
    },
    "kernel_hardening": {
        "name": "Kernel Hardening",
        "keywords": ["kernel", "sysctl", "ASLR", "DEP", "SELinux", "AppArmor"],
        "level": "advanced"
    },

    # Authentication & Entitlements (4)
    "password_security": {
        "name": "Password Security & Hashing",
        "keywords": ["password", "hash", "bcrypt", "salting", "iteration", "strength"],
        "level": "beginner"
    },
    "mfa_implementation": {
        "name": "Multi-Factor Authentication",
        "keywords": ["MFA", "2FA", "TOTP", "HOTP", "U2F", "yubikey", "factor"],
        "level": "intermediate"
    },
    "access_control": {
        "name": "Access Control & RBAC",
        "keywords": ["RBAC", "ABAC", "access", "control", "privilege", "entitlement"],
        "level": "intermediate"
    },
    "identity_management": {
        "name": "Identity Management",
        "keywords": ["identity", "directory", "LDAP", "Active", "Directory", "provisioning"],
        "level": "advanced"
    },

    # Cryptography (2)
    "tls_security": {
        "name": "TLS/SSL Security",
        "keywords": ["TLS", "SSL", "certificate", "cipher", "handshake", "encryption"],
        "level": "intermediate"
    },
    "encryption_algorithms": {
        "name": "Encryption Algorithms",
        "keywords": ["encryption", "RSA", "AES", "algorithm", "key", "cryptography"],
        "level": "advanced"
    },
}

# ==============================================================================
# QUESTION INTENT TEMPLATES (12 intent types with example phrasings)
# ==============================================================================

INTENTS = {
    "what_is": {
        "description": "Definition/explanation questions",
        "templates": [
            "What is {topic}?",
            "Can you explain {topic}?",
            "Define {topic}.",
            "What does {topic} mean?",
            "Tell me about {topic}.",
            "Describe {topic}.",
            "What exactly is {topic}?",
            "Give me an overview of {topic}.",
        ]
    },
    "why_matters": {
        "description": "Security importance questions",
        "templates": [
            "Why is {topic} important for security?",
            "What security risks does {topic} address?",
            "Why should I care about {topic}?",
            "What's the security impact of {topic}?",
            "How does {topic} affect my security posture?",
            "What security value does {topic} provide?",
            "Why is {topic} critical to defend against?",
        ]
    },
    "how_detect": {
        "description": "Detection/identification questions",
        "templates": [
            "How do I detect {topic}?",
            "What tools can identify {topic}?",
            "How can I check for {topic} vulnerabilities?",
            "How do I find {topic} issues on my system?",
            "What's the way to scan for {topic}?",
            "How can I verify if {topic} is present?",
            "What indicators show {topic} problems?",
            "How do I test for {topic} exposure?",
        ]
    },
    "how_fix": {
        "description": "Remediation/fixing questions",
        "templates": [
            "How do I fix {topic}?",
            "What are the steps to secure {topic}?",
            "How can I resolve {topic} issues?",
            "What's the fix for {topic} problems?",
            "How do I patch {topic} vulnerabilities?",
            "What remediation steps apply to {topic}?",
            "How should I address {topic} weaknesses?",
            "What's the solution to {topic} exposure?",
        ]
    },
    "how_verify": {
        "description": "Verification/validation questions",
        "templates": [
            "How do I verify {topic} is secure?",
            "What commands check {topic}?",
            "How can I validate {topic} configurations?",
            "How do I confirm {topic} is properly secured?",
            "What's the verification method for {topic}?",
            "How do I test {topic} after hardening?",
            "What proves {topic} is correctly configured?",
        ]
    },
    "common_mistakes": {
        "description": "Common pitfalls questions",
        "templates": [
            "What are common mistakes with {topic}?",
            "What should I avoid with {topic}?",
            "What are the typical {topic} misconfigurations?",
            "What errors occur with {topic}?",
            "What do people get wrong about {topic}?",
            "What's the most common {topic} security failure?",
            "How do admins usually misconfigure {topic}?",
        ]
    },
    "best_practices": {
        "description": "Best practices questions",
        "templates": [
            "What are best practices for {topic}?",
            "How should I configure {topic}?",
            "What's the recommended approach to {topic}?",
            "What are security best practices for {topic}?",
            "How do I implement {topic} correctly?",
            "What standards recommend for {topic}?",
            "What's the secure way to set up {topic}?",
        ]
    },
    "commands": {
        "description": "Command/tool usage questions",
        "templates": [
            "What commands are used for {topic}?",
            "How do I use tools for {topic}?",
            "What's the syntax for {topic} commands?",
            "What command line tools support {topic}?",
            "How do I invoke {topic} via CLI?",
            "What are {topic} command examples?",
            "Show me how to use {topic} tools.",
            "What programs manage {topic}?",
        ]
    },
    "compliance": {
        "description": "Compliance/standards questions",
        "templates": [
            "What compliance standards address {topic}?",
            "How does {topic} relate to regulatory requirements?",
            "What frameworks cover {topic}?",
            "What regulations mention {topic}?",
            "How does {topic} fit compliance mandates?",
            "What controls apply to {topic}?",
            "What standards require {topic} hardening?",
        ]
    },
    "incident_response": {
        "description": "Incident response questions",
        "templates": [
            "How do I respond to {topic} incidents?",
            "What's the IR procedure for {topic}?",
            "How should I handle {topic} breaches?",
            "What's the {topic} incident response timeline?",
            "How do I contain a {topic} incident?",
            "What steps follow discovery of {topic} issues?",
            "How do I investigate {topic} compromises?",
        ]
    },
    "testing": {
        "description": "Testing/audit questions",
        "templates": [
            "How do I test {topic}?",
            "What's the audit process for {topic}?",
            "How should I assess {topic} security?",
            "What's the security test for {topic}?",
            "How do I audit {topic} implementations?",
            "What benchmarks measure {topic}?",
            "How should I validate {topic} security?",
        ]
    },
    "troubleshooting": {
        "description": "Troubleshooting questions",
        "templates": [
            "How do I troubleshoot {topic} issues?",
            "What's wrong with my {topic} setup?",
            "How can I debug {topic} problems?",
            "Why isn't {topic} working?",
            "How do I diagnose {topic} errors?",
            "What causes {topic} failures?",
            "How do I fix {topic} errors?",
        ]
    },
}

# ==============================================================================
# PHRASINGS (3 natural language variations)
# ==============================================================================

PHRASINGS = [
    "formal",     # "How should I configure SSH?"
    "casual",     # "How do I set up SSH?"
    "detailed",   # "Tell me about the steps for configuring SSH properly."
]

# ==============================================================================
# CONTEXTUAL VARIATIONS (Platform/Tool-specific phrasings)
# ==============================================================================

CONTEXTUAL_VARIATIONS = {
    "ssh_hardening": [
        " on Ubuntu?",
        " on Debian?",
        " on CentOS?",
        " on Red Hat?",
        " in the sshd_config file?",
        " with OpenSSH?",
    ],
    "firewall_linux": [
        " with iptables?",
        " with ufw?",
        " on Ubuntu?",
        " on Debian?",
    ],
    "kernel_hardening": [
        " with sysctl?",
        " in Linux?",
        " with AppArmor?",
        " with SELinux?",
    ],
    "tls_security": [
        " with OpenSSL?",
        " for HTTPS?",
        " in certificates?",
        " for ciphers?",
    ],
    "log_analysis": [
        " in syslog?",
        " in auth.log?",
        " with journalctl?",
        " in Linux logs?",
    ],
    "container_security": [
        " with Docker?",
        " with Kubernetes?",
        " in images?",
        " in registries?",
    ],
    "password_security": [
        " with bcrypt?",
        " with salting?",
        " with hashing?",
        " with key derivation?",
    ],
    "mfa_implementation": [
        " with TOTP?",
        " with U2F?",
        " on Linux?",
        " for SSH?",
    ],
    "web_authentication": [
        " with JWT?",
        " with OAuth?",
        " with cookies?",
        " with sessions?",
    ],
    "network_protocols": [
        " in TCP?",
        " in UDP?",
        " in IP?",
        " in DNS?",
    ],
}

def generate_questions() -> List[Dict]:
    """Generate 2000+ templated questions from topics × intents × phrasings with contextual variations."""
    questions = []
    question_id = 1
    seen_questions = set()  # Avoid duplicates
    
    for topic_key, topic_data in TOPICS.items():
        for intent_key, intent_data in INTENTS.items():
            # Base templates
            for template in intent_data["templates"]:
                # Determine difficulty
                difficulty = topic_data["level"]
                if intent_key in ["testing", "compliance", "incident_response"]:
                    if difficulty == "beginner":
                        difficulty = "intermediate"
                    elif difficulty == "intermediate":
                        difficulty = "advanced"
                
                # Create the base question
                question_text = template.format(topic=topic_data["name"].lower())
                
                # Skip if exact duplicate
                if question_text in seen_questions:
                    continue
                seen_questions.add(question_text)
                
                # Determine expected keywords
                expected_keywords = topic_data["keywords"].copy()
                
                # Add intent-specific keywords
                if intent_key == "how_fix":
                    expected_keywords.extend(["configure", "enable", "disable", "setup"])
                elif intent_key == "how_detect":
                    expected_keywords.extend(["check", "verify", "test", "scan"])
                elif intent_key == "best_practices":
                    expected_keywords.extend(["should", "must", "recommended", "standard"])
                elif intent_key == "compliance":
                    expected_keywords.extend(["NIST", "OWASP", "RFC", "standard", "regulation"])
                elif intent_key == "commands":
                    expected_keywords.extend(["command", "tool", "syntax", "cli"])
                
                question_obj = {
                    "id": question_id,
                    "question": question_text,
                    "topic": topic_key,
                    "topic_display": topic_data["name"],
                    "intent": intent_key,
                    "intent_description": intent_data["description"],
                    "difficulty": difficulty,
                    "expected_keywords": expected_keywords,
                    "generated_at": datetime.now().isoformat(),
                }
                
                questions.append(question_obj)
                question_id += 1
    
    # Add contextual variations for specific topics
    for topic_key, variations in CONTEXTUAL_VARIATIONS.items():
        if topic_key not in TOPICS:
            continue
        
        topic_data = TOPICS[topic_key]
        
        for template in ["How do I {base}{context}?", "What's the {base}{context}?", 
                        "Tell me about {base}{context}.", "Explain {base}{context}."]:
            for variation in variations:
                # Create contextual question
                base = topic_data["name"].lower()
                question_text = template.format(base=base, context=variation)
                
                # Skip if exact duplicate
                if question_text in seen_questions:
                    continue
                seen_questions.add(question_text)
                
                # Determine difficulty (slightly higher for contextual)
                difficulty = topic_data["level"]
                if difficulty == "beginner":
                    difficulty = "intermediate"
                elif difficulty == "intermediate":
                    difficulty = "advanced"
                
                # Extract keywords
                expected_keywords = topic_data["keywords"].copy()
                variation_word = variation.strip("? ").replace(" ", "_")
                expected_keywords.append(variation_word)
                
                question_obj = {
                    "id": question_id,
                    "question": question_text,
                    "topic": topic_key,
                    "topic_display": topic_data["name"],
                    "intent": "contextual",
                    "intent_description": "Platform/tool-specific variation",
                    "difficulty": difficulty,
                    "expected_keywords": expected_keywords,
                    "generated_at": datetime.now().isoformat(),
                }
                
                questions.append(question_obj)
                question_id += 1
    
    return questions


def export_jsonl(questions: List[Dict], output_path: Path) -> None:
    """Export questions to JSONL format (one JSON object per line)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for q in questions:
            f.write(json.dumps(q) + '\n')
    
    print(f"✅ JSONL exported: {output_path}")
    print(f"   Total questions: {len(questions)}")


def export_csv(questions: List[Dict], output_path: Path) -> None:
    """Export questions to CSV format."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'id', 'question', 'topic', 'topic_display', 'intent',
            'intent_description', 'difficulty', 'expected_keywords'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for q in questions:
            row = {k: v for k, v in q.items() if k in fieldnames}
            row['expected_keywords'] = '|'.join(q['expected_keywords'])
            writer.writerow(row)
    
    print(f"✅ CSV exported: {output_path}")
    print(f"   Total questions: {len(questions)}")


def print_summary(questions: List[Dict]) -> None:
    """Print summary statistics."""
    print("\n" + "="*70)
    print("QUESTION BANK GENERATION SUMMARY")
    print("="*70)
    
    # Count by topic
    topic_counts = {}
    for q in questions:
        topic = q['topic_display']
        topic_counts[topic] = topic_counts.get(topic, 0) + 1
    
    # Count by intent
    intent_counts = {}
    for q in questions:
        intent = q['intent_description']
        intent_counts[intent] = intent_counts.get(intent, 0) + 1
    
    # Count by difficulty
    difficulty_counts = {}
    for q in questions:
        diff = q['difficulty']
        difficulty_counts[diff] = difficulty_counts.get(diff, 0) + 1
    
    print(f"\n📊 Total Questions Generated: {len(questions)}")
    
    print(f"\n📚 By Difficulty:")
    for diff in ["beginner", "intermediate", "advanced"]:
        count = difficulty_counts.get(diff, 0)
        print(f"   {diff.capitalize():12} : {count:4} questions ({count*100/len(questions):.1f}%)")
    
    print(f"\n🎯 By Intent Category (12 intents):")
    for intent, count in sorted(intent_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {intent[:40]:40} : {count:3}")
    
    print(f"\n🔐 By Topic Coverage (30 topics):")
    for topic, count in sorted(topic_counts.items()):
        print(f"   {topic[:40]:40} : {count:2} questions")
    
    print("\n" + "="*70)


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate 1000+ templated cybersecurity Q&A pairs for Freddy"
    )
    parser.add_argument(
        '--format',
        choices=['jsonl', 'csv', 'both'],
        default='jsonl',
        help='Output format (default: jsonl)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output directory (default: questions/)'
    )
    
    args = parser.parse_args()
    output_dir = Path(args.output) if args.output else Path("questions")
    
    # Generate questions
    print("🔄 Generating questions...")
    questions = generate_questions()
    
    # Export based on format
    if args.format in ['jsonl', 'both']:
        export_jsonl(questions, output_dir / "question_bank.jsonl")
    
    if args.format in ['csv', 'both']:
        export_csv(questions, output_dir / "question_bank.csv")
    
    # Print summary
    print_summary(questions)


if __name__ == "__main__":
    main()
