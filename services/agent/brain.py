# services/agent/brain.py
# The brain of the triage agent.
# Sends the packed prompt to the local Ollama model and turns the
# model's JSON answer into the verdict dict save_verdict expects.
# If the model answer cannot be used, the brain returns a safe
# needs_more_info verdict instead of crashing the agent.

import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

from services.agent.prompts import SYSTEM_PROMPT

# Load the .env file from the project root (two folders up from here)
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = "llama3.1:8b"
VERDICTS = ("true_positive", "false_positive", "needs_more_info")


def parse_verdict(text):
    # Turn the model's answer text into a verdict dict.
    # Raises ValueError if the answer breaks the contract.
    verdict = json.loads(text)
    if verdict.get("verdict") not in VERDICTS:
        raise ValueError("verdict word is not one of the three")
    if not verdict.get("summary"):
        raise ValueError("summary is missing")
    return verdict


def think(prompt_text):
    # Ask the local model to judge one packed alert prompt.
    # Returns a verdict dict in all cases: a real one when the
    # model behaves, a needs_more_info fallback when it does not.
    try:
        response = httpx.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt_text},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            },
            timeout=300,
        )
        response.raise_for_status()
        text = response.json()["message"]["content"]
        return parse_verdict(text)
    except (httpx.HTTPError, ValueError) as error:
        return {
            "verdict": "needs_more_info",
            "confidence": 0,
            "summary": f"The model answer could not be used: {error}",
            "recommended_action": "Review this alert manually",
        }
