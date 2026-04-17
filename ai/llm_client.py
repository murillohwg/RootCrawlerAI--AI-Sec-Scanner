import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"


def analyze_with_ai(prompt: str) -> str:
    """
    Envia um prompt para o Ollama e retorna a resposta da IA.
    """
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )

        response.raise_for_status()
        data = response.json()

        return data.get("response", "").strip()

    except requests.RequestException as e:
        return f"[AI ERROR] {str(e)}"


def build_prompt(finding: dict) -> str:
    return f"""
You are a penetration tester.

Analyze this security finding and suggest possible exploitation techniques.

Finding:
Type: {finding.get("type")}
Severity: {finding.get("severity")}
Description: {finding.get("description")}
Evidence: {finding.get("evidence")}

Tasks:
1. Briefly explain what this means
2. Suggest realistic attack vectors
3. Provide example payloads if applicable
4. Suggest next steps for testing

Rules:
- Be concise
- Focus on practical exploitation
- Provide payloads when relevant
- Limit response to 120 words
"""
