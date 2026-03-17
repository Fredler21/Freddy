"""AI engine for Freddy security analysis."""

from __future__ import annotations

import json
import sys

from config import AI_PROVIDER, API_KEY, MAX_TOKENS, MODEL, OLLAMA_BASE_URL, OLLAMA_MODEL, SYSTEM_PROMPT_PATH


def get_client():
    """Create and return an authenticated Anthropic client."""
    if AI_PROVIDER == "ollama":
        return None  # Ollama uses HTTP directly
    from anthropic import Anthropic
    if not API_KEY:
        print("\n[!] ANTHROPIC_API_KEY not set.\n")
        sys.exit(1)
    return Anthropic(api_key=API_KEY)


def _ollama_chat(*, system: str, user_message: str, max_tokens: int = 4096) -> str:
    """Send a chat request to a local Ollama instance."""
    import urllib.request
    import urllib.error

    url = f"{OLLAMA_BASE_URL}/api/chat"
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {"num_predict": max_tokens},
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("message", {}).get("content", "[!] Empty response from Ollama.")
    except urllib.error.URLError as exc:
        return (
            f"[!] Could not connect to Ollama at {OLLAMA_BASE_URL}.\n"
            "    Make sure Ollama is running: ollama serve\n"
            f"    Error: {exc}"
        )
    except Exception as exc:
        return f"[!] Ollama error: {exc}"


def load_system_prompt() -> str:
    """Load the system prompt from disk."""
    try:
        return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"\n[!] System prompt not found: {SYSTEM_PROMPT_PATH}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n[!] Error loading system prompt: {exc}\n")
        sys.exit(1)


def trim_input(data: str, max_chars: int = 50000) -> tuple[str, bool]:
    """Trim very large inputs to fit model limits."""
    if len(data) > max_chars:
        return data[:max_chars] + "\n\n[...Evidence truncated for model limit...]", True
    return data, False


def analyze(
    *,
    raw_evidence: str,
    system_prompt: str,
    rule_findings: str,
    knowledge_context: str,
    command_metadata: dict[str, str] | None = None,
    task_instruction: str = "Perform expert defensive cybersecurity analysis.",
    prior_history: str = "",
) -> str:
    """Send a structured Freddy analysis payload to Claude."""
    if not raw_evidence or not raw_evidence.strip():
        return "[!] No data to analyze — the command produced no output."

    trimmed_evidence, was_trimmed = trim_input(raw_evidence)
    if was_trimmed:
        print("[!] Evidence was truncated to fit model limits.")

    payload = _compose_payload(
        raw_evidence=trimmed_evidence,
        rule_findings=rule_findings,
        knowledge_context=knowledge_context,
        command_metadata=command_metadata or {},
        task_instruction=task_instruction,
        prior_history=prior_history,
    )

    if AI_PROVIDER == "ollama":
        return _ollama_chat(system=system_prompt, user_message=payload, max_tokens=MAX_TOKENS)

    from anthropic import APIConnectionError, APIError
    client = get_client()
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": payload}],
        )
        return response.content[0].text
    except APIConnectionError:
        return "[!] Could not connect to the Anthropic API. Check connectivity and retry."
    except APIError as exc:
        return f"[!] API Error: {exc}"
    except Exception as exc:
        return f"[!] Unexpected error: {exc}"


def answer_question(
    *,
    question: str,
    knowledge_context: str,
) -> str:
    """Return a direct, concise answer grounded in retrieved knowledge context."""
    if not question.strip():
        return "[!] Please provide a non-empty question."
    if not knowledge_context.strip():
        return "[!] No knowledge context available to answer this question."
    if AI_PROVIDER == "anthropic" and not API_KEY:
        return "[!] ANTHROPIC_API_KEY not set. Set it or switch to Ollama: export FREDDY_AI_PROVIDER=ollama"

    payload = (
        "You are Freddy, a defensive cybersecurity assistant.\n"
        "Answer the user's question directly using only the provided context.\n"
        "If context is insufficient, explicitly say so and suggest what to ask next.\n"
        "Keep the answer practical and concise.\n\n"
        f"QUESTION\n{question}\n\n"
        f"RETRIEVED KNOWLEDGE CONTEXT\n{knowledge_context}\n"
    )

    system_msg = (
        "You are Freddy. Provide concise, actionable defensive cybersecurity answers. "
        "Do not invent facts not present in context."
    )

    if AI_PROVIDER == "ollama":
        return _ollama_chat(system=system_msg, user_message=payload, max_tokens=min(MAX_TOKENS, 1200))

    from anthropic import APIConnectionError, APIError
    client = get_client()
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=min(MAX_TOKENS, 1200),
            system=system_msg,
            messages=[{"role": "user", "content": payload}],
        )
        return response.content[0].text
    except APIConnectionError:
        return "[!] Could not connect to the Anthropic API. Check connectivity and retry."
    except APIError as exc:
        return f"[!] API Error: {exc}"
    except Exception as exc:
        return f"[!] Unexpected error: {exc}"


def _compose_payload(
    *,
    raw_evidence: str,
    rule_findings: str,
    knowledge_context: str,
    command_metadata: dict[str, str],
    task_instruction: str,
    prior_history: str = "",
) -> str:
    metadata_blob = json.dumps(command_metadata, indent=2, sort_keys=True)
    history_section = (
        f"PRIOR SCAN HISTORY\n{prior_history}\n\n"
        if prior_history.strip()
        else ""
    )
    return (
        "TASK\n"
        f"{task_instruction}\n\n"
        "COMMAND METADATA\n"
        f"{metadata_blob}\n\n"
        "OBSERVED EVIDENCE\n"
        f"{raw_evidence}\n\n"
        "RULE-BASED FINDINGS\n"
        f"{rule_findings}\n\n"
        "RETRIEVED CYBERSECURITY KNOWLEDGE\n"
        f"{knowledge_context}\n\n"
        f"{history_section}"
        "ANALYSIS REQUIREMENTS\n"
        "- Distinguish confirmed evidence from inferred risk.\n"
        "- Use the rule findings to prioritize inspection areas.\n"
        "- Use the knowledge context to improve remediation specificity.\n"
        "- If prior scan history is provided, note any recurring or unresolved findings.\n"
        "- Keep the output defensive, professional, and actionable.\n"
    )
