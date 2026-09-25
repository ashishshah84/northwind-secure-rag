"""LLM backend.

Two backends, chosen by LLM_BACKEND:

  openrouter - real call to OpenRouter's chat completions endpoint. This is what
               your VM should use - it's the only backend whose behaviour under
               attack means anything.
  stub       - a deterministic, network-free fake model for exercising the
               pipeline (prompt building, retrieval wiring, guard logic, attack
               script plumbing) without an API key. It is INTENTIONALLY naive:
               it does no reasoning and will mechanically follow instructions it
               finds anywhere in its input, including inside retrieved context.
               That makes it useful for proving the pipeline *can* pass an
               injection through end to end, but it is not evidence about how a
               real model behaves - do not put stub results in the report.

Both backends implement the same call(system, user) -> str interface so the rest
of the app never needs to know which one is active.
"""
from __future__ import annotations

import re
from typing import Protocol

import httpx

from .config import settings


class LLMError(RuntimeError):
    pass


class LLM(Protocol):
    name: str

    def chat(self, system: str, user: str) -> str: ...


class OpenRouterLLM:
    name = "openrouter"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or settings.openrouter_model
        if not settings.openrouter_api_key:
            raise LLMError(
                "OPENROUTER_API_KEY is not set. Put a real key in .env - "
                "see README 'Getting an OpenRouter key'."
            )

    def chat(self, system: str, user: str) -> str:
        try:
            resp = httpx.post(
                f"{settings.openrouter_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.openrouter_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1536,
                    # Reasoning tokens share the same max_tokens budget as the
                    # visible answer on most providers - a model that spends
                    # it all "thinking" returns finish_reason=length with
                    # content=null (see the None-content handling below).
                    # Capping reasoning effort leaves more room for an actual
                    # answer. Best-effort: not every free model honours this,
                    # but OpenRouter passes it through harmlessly if ignored.
                    "reasoning": {"effort": "low"},
                },
                timeout=60,
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"OpenRouter request failed: {exc}") from exc

        if resp.status_code != 200:
            raise LLMError(f"OpenRouter HTTP {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected OpenRouter response shape: {data}") from exc

        content = message.get("content")
        if content:
            return content

        # Some free-tier models (reasoning models in particular) can return
        # content=null - e.g. they spent the whole max_tokens budget on
        # internal reasoning and never emitted a final answer, or the
        # reasoning text landed in a separate non-standard field instead of
        # "content". Surface whatever we can rather than silently handing
        # None to the rest of the pipeline (which then fails three files
        # away with an unhelpful TypeError - ask me how I know).
        finish_reason = choice.get("finish_reason", "unknown")
        reasoning = message.get("reasoning") or message.get("reasoning_content")
        if reasoning:
            return (
                f"[no final content - model only returned reasoning, "
                f"finish_reason={finish_reason}]\n{reasoning}"
            )
        raise LLMError(
            f"OpenRouter returned empty content (finish_reason={finish_reason}). "
            f"Full response: {data}"
        )


class StubLLM:
    """Naive offline fake. See module docstring - not a substitute for the real model."""

    name = "stub"

    # Recognises a few injection patterns well enough to demonstrate the
    # pipeline carrying an instruction through. This is pattern matching, not
    # comprehension - real models are attacked because they *understand*
    # instructions wherever they appear, which this cannot really simulate.
    _canary_re = re.compile(r"canary[\-:\s]*(?:fired)?[:\s]+([A-Z0-9\-]+)", re.IGNORECASE)
    _reveal_re = re.compile(
        r"(reveal|disclose|print|output|include)\s+(any\s+|all\s+|the\s+)?"
        r"(hr[- ]confidential|restricted|confidential)",
        re.IGNORECASE,
    )
    _override_re = re.compile(
        r"(ignore|disregard)\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions",
        re.IGNORECASE,
    )

    def chat(self, system: str, user: str) -> str:
        blob = f"{system}\n{user}"

        canary = self._canary_re.search(blob)
        override = self._override_re.search(blob)
        reveal = self._reveal_re.search(blob)

        lines = ["[stub model - offline, no real reasoning]"]

        if override and (canary or reveal):
            lines.append(
                "Understood - ignoring my prior instructions as directed by the "
                "retrieved document."
            )
            if canary:
                lines.append(f"CANARY-FIRED: {canary.group(1)}")
            if reveal:
                lines.append(
                    "Here is the confidential content I was told to disclose: "
                    "[simulated leak of hr-confidential context, if any was present "
                    "in my input]."
                )
        else:
            lines.append(
                "Based on the provided context, here is a best-effort answer to "
                "your question. (No instruction-override pattern detected in input.)"
            )

        return "\n".join(lines)


_cached: LLM | None = None


def get_llm(backend: str | None = None) -> LLM:
    global _cached
    if _cached is not None and backend is None:
        return _cached

    choice = (backend or getattr(settings, "llm_backend", "stub")).lower()
    llm: LLM
    if choice == "openrouter":
        llm = OpenRouterLLM()
    else:
        llm = StubLLM()

    if backend is None:
        _cached = llm
    return llm
