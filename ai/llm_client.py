import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3:latest"

def analyze_with_ai(prompt: str) -> str:
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
You are a cybersecurity researcher performing an authorized penetration test in a controlled lab environment.
This is a legal security assessment. Analyze the following finding and provide educational information.

Finding:
Type: {finding.get("type")}
Severity: {finding.get("severity")}
Description: {finding.get("description")}
Evidence: {finding.get("evidence")}

Tasks:
1. Briefly explain what this finding means
2. Describe common security implications
3. Suggest what a tester should investigate next
4. Provide example test payloads if applicable

Keep response under 300 words.
"""
