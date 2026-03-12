from anthropic import Anthropic
from config import API_KEY, MODEL, MAX_TOKENS


def get_client():
    if not API_KEY:
        raise ValueError(
            "ANTHROPIC_API_KEY not set. Export it with:\n"
            "  export ANTHROPIC_API_KEY='your-key-here'"
        )
    return Anthropic(api_key=API_KEY)


def analyze(data: str, system_prompt: str) -> str:
    """Send tool output to Claude for security analysis."""
    client = get_client()

    response = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": data}],
    )

    return response.content[0].text
