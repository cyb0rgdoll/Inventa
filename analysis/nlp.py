import json
import os
from typing import Dict, List
import requests # type: ignore


def query_network(question: str, assets: List[Dict]) -> str:
    """
    Natural language query over discovered assets using an LLM.
    """
    llm_endpoint = os.environ.get("INVENTA_LLM_ENDPOINT", "http://localhost:11434/v1")

    context = f"""
You are a network security analyst. Here is the current network inventory:

{json.dumps(assets, indent=2)}

User question: {question}

Provide a concise answer with specific asset details (IP, ports, services).
"""

    try:
        response = requests.post(
            f"{llm_endpoint}/chat/completions",
            json={
                "model": "llama2",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity asset analyst."},
                    {"role": "user", "content": context},
                ],
                "max_tokens": 500,
                "temperature": 0.2,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices") or [{}]
        return choices[0].get("message", {}).get(
            "content",
            "No answer returned from the language model.",
        )
    except requests.exceptions.RequestException as e:
        return f"LLM query failed: {e}"
    except Exception as e:
        return f"Unexpected NLP query error: {e}"


def get_query_suggestions(assets: List[Dict]) -> List[str]:
    """
    Return a few useful built-in query suggestions.
    """
    suggestions = [
        "Which assets are externally exposed?",
        "Which hosts have the most open ports?",
        "Which assets look like domain controllers?",
        "Which assets have known vulnerabilities?",
        "Which systems are likely web servers?",
    ]

    if any(a.get("cloud_provider") for a in assets):
        suggestions.append("Which discovered assets are cloud resources?")

    if any(a.get("tls_info") for a in assets):
        suggestions.append("Which hosts have TLS issues or expiring certificates?")

    return suggestions