"""Multi-provider AI client for log analysis.

Supports Anthropic (Claude) and OpenAI-compatible APIs (OpenAI, Ollama, local LLMs).
Uses httpx (already a dependency) — no additional packages needed.
"""

import json
import logging

import httpx

from app import config

logger = logging.getLogger("trapstack.ai")

SYSTEM_PROMPT = """\
You are a CrowdSec security analyst. You analyze nginx reverse proxy access logs and generate CrowdSec scenario YAML files to detect and ban malicious traffic patterns.

CrowdSec scenarios use the "leaky bucket" type. Available filter fields:
- evt.Meta.service == "http"
- evt.Meta.http_status (string: "200", "400", "404", etc.)
- evt.Parsed.request (the full HTTP request line, e.g. "GET /path HTTP/1.1")
- evt.Parsed.target_fqdn (the hostname from the Host header)

Filter operators: ==, !=, contains, startsWith, endsWith, matches (regex)
Logical operators: &&, ||

Example scenario:
  type: leaky
  name: crowdsec/npmplus-wordpress-scan
  description: Detect IPs scanning for WordPress installations
  filter: >-
    evt.Meta.service == "http" &&
    (evt.Parsed.request contains "/wp-login" ||
     evt.Parsed.request contains "/wp-admin" ||
     evt.Parsed.request contains "/xmlrpc.php")
  capacity: 3
  leakspeed: "30m"
  blackhole: "1h"
  labels:
    remediation: true
    service: http
    confidence: 7

You must respond ONLY with valid JSON. Keep the structure FLAT — no nested objects.
Use this exact format:
{
  "recommendations": [
    {
      "id": "kebab-case-id",
      "title": "short title",
      "severity": "critical or high or medium or low",
      "hits_count": 42,
      "unique_ips": 3,
      "attacker_ips": "1.2.3.4, 5.6.7.8, 9.10.11.12",
      "reasoning": "why this pattern is dangerous",
      "evidence": "example requests that triggered this",
      "scenario_name": "crowdsec/npmplus-example",
      "scenario_description": "what this scenario detects",
      "filter": "evt.Meta.service == http && evt.Parsed.request contains /example",
      "capacity": 3,
      "leakspeed": "30m",
      "blackhole": "1h",
      "confidence": 7
    }
  ],
  "summary": "2-3 sentence overall assessment"
}

Rules:
- Only recommend scenarios for patterns NOT already covered by existing scenarios
- Each scenario must have a valid CrowdSec filter expression
- Set capacity based on suspiciousness (1 for definite attacks, 3-5 for ambiguous probing)
- Use confidence 8-10 for clear attacks, 5-7 for likely probes, 3-4 for uncertain
- Keep filter expressions specific to avoid false positives
- If no new scenarios are needed, return empty recommendations with a summary explaining why
- Output ONLY the JSON object, nothing else"""


class AIClient:
    def __init__(self, http_client: httpx.AsyncClient):
        self.provider = config.AI_PROVIDER.lower().strip()
        self.api_key = config.AI_API_KEY
        self.api_url = config.AI_API_URL.rstrip("/") if config.AI_API_URL else self._default_url()
        self.model = config.AI_MODEL or self._default_model()
        self._http = http_client

    def _default_url(self) -> str:
        if self.provider == "anthropic":
            return "https://api.anthropic.com"
        return "https://api.openai.com/v1"

    def _default_model(self) -> str:
        if self.provider == "anthropic":
            return "claude-sonnet-4-20250514"
        return "gpt-4o"

    def is_configured(self) -> bool:
        if not self.provider:
            return False
        # Anthropic always needs an API key; local/openai-compatible may not
        if self.provider == "anthropic":
            return bool(self.api_key)
        return True

    async def analyze(self, user_prompt: str) -> str:
        if self.provider == "anthropic":
            return await self._call_anthropic(user_prompt)
        return await self._call_openai(user_prompt)

    async def _call_anthropic(self, user_prompt: str) -> str:
        resp = await self._http.post(
            f"{self.api_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": 4096,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=90.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]

    async def _call_openai(self, user_prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = await self._http.post(
            f"{self.api_url}/chat/completions",
            headers=headers,
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=300.0,
        )
        if resp.status_code >= 400:
            body = resp.text[:500]
            logger.error(f"OpenAI API error {resp.status_code}: {body}")
            raise Exception(f"AI API error {resp.status_code}: {body}")
        data = resp.json()
        return data["choices"][0]["message"]["content"]
