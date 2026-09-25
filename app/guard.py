"""Output Guard - trust boundary #4: model output -> user.

Independent of the prompt builder on purpose. A structural prompt is a strong
mitigation but not a proof - the guard re-checks what the model actually said,
after the fact, against the ground truth of what it was and wasn't entitled to
return. Defence in depth: if the prompt-level defence fails, this is the backstop.

Three checks:
  1. classification leak    - did the answer surface hr-confidential material
                               (doc_ids or namesake content) to a role not
                               entitled to it?
  2. injection compliance   - does the answer show signs of having followed an
                               instruction embedded in retrieved content (a
                               canary string firing, an explicit acknowledgement
                               of "ignoring instructions", etc.)?
  3. verbatim dump           - did the model paste back a large unbroken slice of
                               retrieved text rather than answering in its own
                               words (a common exfiltration shape)?

Only runs in secure mode by design - in vulnerable mode we want the raw,
unguarded output so the attack scripts capture what an undefended app would
actually have sent to the user.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .config import settings

CANARY_RE = re.compile(r"CANARY-FIRED:\s*([A-Z0-9\-]+)", re.IGNORECASE)
ACK_OVERRIDE_RE = re.compile(
    r"(ignoring|disregard(ed|ing)?)\s+(my|prior|previous|the)\s+instructions",
    re.IGNORECASE,
)
# A model reaching for an encode/exfil tool in its *output* is acting on an
# instruction it read somewhere. Observed in the wild during testing as:
#   <|tool_call_start|>[base64_encode(content='...')]<|tool_call_end|>
# Worth catching even though this app exposes no tools to call - the attempt
# is the signal, and an app that later adds tool use inherits the exposure.
TOOL_CALL_ATTEMPT_RE = re.compile(
    r"(<\|tool_call|tool_call_start|\bbase64_encode\s*\(|\bb64encode\s*\()",
    re.IGNORECASE,
)


@dataclass
class GuardResult:
    safe: bool
    findings: list[str] = field(default_factory=list)
    redacted_text: str | None = None


def _classification_leak(
    answer: str, role: str, retrieved: list[dict[str, Any]]
) -> list[str]:
    entitlements = settings.entitlements_for(role)
    findings = []
    for c in retrieved:
        m = c["metadata"]
        if m["classification"] in entitlements:
            continue
        # This chunk should never have reached the prompt in secure mode; if it
        # did (retriever bug) and its doc_id or a long substring shows up in the
        # answer, that's a confirmed leak through the model as well.
        if m["doc_id"] in answer:
            findings.append(f"unauthorised doc_id '{m['doc_id']}' present in answer")
        else:
            snippet = " ".join(m.get("title", "").split())
            if snippet and snippet in answer:
                findings.append(f"unauthorised document title '{snippet}' present in answer")
    return findings


def _injection_compliance(answer: str) -> list[str]:
    findings = []
    canary = CANARY_RE.search(answer)
    if canary:
        findings.append(f"canary fired: {canary.group(1)} (embedded instruction was executed)")
    if ACK_OVERRIDE_RE.search(answer):
        findings.append("model explicitly acknowledged disregarding its instructions")
    if TOOL_CALL_ATTEMPT_RE.search(answer):
        findings.append(
            "answer contains an attempted tool call (encode/exfil shape) - the model "
            "acted on an instruction rather than answering"
        )
    return findings


def _verbatim_dump(answer: str, retrieved: list[dict[str, Any]], min_run: int = 200) -> list[str]:
    findings = []
    for c in retrieved:
        text = c["text"]
        for i in range(0, max(len(text) - min_run, 0) + 1, min_run):
            window = text[i : i + min_run]
            if window and window in answer:
                findings.append(
                    f"answer contains a {min_run}+ char verbatim run from {c['metadata']['doc_id']}"
                )
                break
    return findings


def check_output(
    answer: str,
    role: str,
    retrieved: list[dict[str, Any]],
    mode: str | None = None,
) -> GuardResult:
    mode = (mode or settings.security_mode).lower()
    if mode != "secure":
        return GuardResult(safe=True, findings=["guard not active in vulnerable mode"])

    findings: list[str] = []
    findings += _classification_leak(answer, role, retrieved)
    findings += _injection_compliance(answer)
    findings += _verbatim_dump(answer, retrieved)

    if not findings:
        return GuardResult(safe=True, redacted_text=answer)

    redacted = (
        "[response withheld by output guard - the draft answer triggered one or "
        "more security checks and was not returned to the user]"
    )
    return GuardResult(safe=False, findings=findings, redacted_text=redacted)
