# services/agent/brain.py
# ollama triage calls and verdict parsing

import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

from services.agent.prompts import SYSTEM_PROMPT

# load .env from project root
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = "llama3.1:8b"
VERDICTS = ("true_positive", "false_positive", "needs_more_info")

LEVELS = ("high", "medium", "low")


def parse_verdict(text):
    # parse model JSON, return validated verdict dict
    verdict = json.loads(text)
    if verdict.get("verdict") not in VERDICTS:
        raise ValueError("verdict word is not one of the three")
    if not verdict.get("summary"):
        raise ValueError("summary is missing")
    return verdict


def think(prompt_text):
    # send prompt to ollama, return verdict dict or needs_more_info fallback
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



def parse_level(answer):
    # parse model JSON, return validated scan judgment dict
    judgment = json.loads(answer)
    if judgment.get("level") not in LEVELS:
        raise ValueError("level word is not one of the three")
    if not judgment.get("summary"):
        raise ValueError("summary is missing")
    return judgment


def think_scan(prompt_text, system_prompt):
    # send scan prompt to ollama, return judgment dict or needs_more_info fallback
    try:
        response = httpx.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt_text},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            },
            timeout=300,
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        return parse_level(content)
    except (httpx.HTTPError, ValueError) as error:
        return {
            "level": "needs_more_info",
            "confidence": 0,
            "summary": f"The model answer could not be used: {error}",
            "recommended_action": "Review this scan manually",
        }

# Phising verdicts

PHISH_VERDICTS = ("phishing", "suspicious", "safe", "needs_more_info")


def parse_phishing(answer):
    # parse model JSON, return validated phishing verdict dict
    verdict = json.loads(answer)
    if verdict.get("verdict") not in PHISH_VERDICTS:
        raise ValueError("verdict word is not one of the three")
    if not verdict.get("summary"):
        raise ValueError("summary is missing")
    return verdict


def think_phishing(prompt_text, system_prompt):
    # send phishing prompt to ollama, return verdict dict or needs_more_info fallback
    try:
        response = httpx.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt_text},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            },
            timeout=300,
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        return parse_phishing(content)
    except (httpx.HTTPError, ValueError) as error:
        return {
            "verdict": "needs_more_info",
            "confidence": 0,
            "summary": f"The model answer could not be used: {error}",
        }
