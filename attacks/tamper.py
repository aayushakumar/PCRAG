"""
PCRAG Attack Harness — tamper transformations for evaluation.

Implements attacks A1–A6 from PRD §11.2:
  A1: citation swap
  A2: span substitution (edit span text)
  A3: claim edit (negation flip, quantifier flip)
  A4: reorder/drop evidence
  A5: UI tamper simulation (label verified without verification)
  A6: replay (old cert for new query — enforce nonce/time window)
"""

from __future__ import annotations

import copy
import random
import uuid
from datetime import datetime, timezone


def a1_citation_swap(cert_dict: dict, seed: int = 42) -> dict:
    """
    A1: Citation swap — keep answer text, swap cited source doc_ids.
    Swaps doc_ids among evidence spans while keeping span text unchanged.
    This should cause span_hash to still match, but doc provenance is wrong.
    """
    tampered = copy.deepcopy(cert_dict)
    rng = random.Random(seed)

    claims = tampered.get("claims", [])
    all_doc_ids = list({
        span["doc_id"]
        for claim in claims
        for span in claim.get("evidence_spans", [])
    })

    if len(all_doc_ids) < 2:
        # Can't swap with fewer than 2 doc_ids — just change the one we have
        for claim in claims:
            for span in claim.get("evidence_spans", []):
                span["doc_id"] = "fake_doc_" + uuid.uuid4().hex[:8]
        return tampered

    for claim in claims:
        for span in claim.get("evidence_spans", []):
            original = span["doc_id"]
            others = [d for d in all_doc_ids if d != original]
            if others:
                span["doc_id"] = rng.choice(others)

    return tampered


def a2_span_substitution(cert_dict: dict, mode: str = "insert") -> dict:
    """
    A2: Span substitution — edit the quoted evidence span text.
    Modes: 'insert' (add text), 'paraphrase' (alter words), 'numbers' (change digits).
    This MUST cause span_hash mismatch.
    """
    tampered = copy.deepcopy(cert_dict)

    for claim in tampered.get("claims", []):
        for span in claim.get("evidence_spans", []):
            original = span.get("span_text", "")
            if not original:
                continue

            if mode == "insert":
                # Insert extra whitespace and a word
                span["span_text"] = original + " [TAMPERED]"
            elif mode == "paraphrase":
                # Replace a common word
                words = original.split()
                if len(words) > 2:
                    words[1] = "ALTERED"
                span["span_text"] = " ".join(words)
            elif mode == "numbers":
                # Flip digits; if no digits, append noise
                has_digits = any(ch.isdigit() for ch in original)
                if has_digits:
                    new_text = ""
                    for ch in original:
                        if ch.isdigit():
                            new_text += str((int(ch) + 1) % 10)
                        else:
                            new_text += ch
                    span["span_text"] = new_text
                else:
                    span["span_text"] = original + " 999"
            else:
                span["span_text"] = original + " [modified]"
            # NOTE: we deliberately do NOT update span_hash — that's the attack

    return tampered


def a3_claim_edit(cert_dict: dict, mode: str = "negate") -> dict:
    """
    A3: Claim edit — modify claim text after signing.
    Modes: 'negate' (flip meaning), 'quantifier' (change quantities).
    This MUST cause claim_hash mismatch.
    """
    tampered = copy.deepcopy(cert_dict)

    negation_words = {
        "is": "is not",
        "are": "are not",
        "was": "was not",
        "has": "has not",
        "can": "cannot",
        "does": "does not",
        "will": "will not",
    }

    for claim in tampered.get("claims", []):
        original = claim.get("claim_text", "")
        if not original:
            continue

        if mode == "negate":
            words = original.split()
            modified = False
            new_words = []
            for w in words:
                lw = w.lower().rstrip(".,;:!?")
                if lw in negation_words and not modified:
                    # Preserve trailing punctuation
                    trail = w[len(lw):]
                    new_words.append(negation_words[lw] + trail)
                    modified = True
                else:
                    new_words.append(w)
            if not modified:
                new_words.insert(1, "NOT")
            claim["claim_text"] = " ".join(new_words)

        elif mode == "quantifier":
            # Change numbers; if no digits, alter text anyway
            has_digits = any(ch.isdigit() for ch in original)
            if has_digits:
                new_text = ""
                for ch in original:
                    if ch.isdigit():
                        new_text += str((int(ch) + 3) % 10)
                    else:
                        new_text += ch
                claim["claim_text"] = new_text
            else:
                # No digits — change a word to alter semantics
                claim["claim_text"] = original + " approximately"

        # NOTE: do NOT update claim_hash — that's the attack

    return tampered


def a4_reorder_drop(cert_dict: dict, action: str = "drop") -> dict:
    """
    A4: Reorder evidence or drop evidence spans.
    Actions: 'drop' (remove first span), 'reorder' (reverse spans), 'drop_all' (remove all).
    """
    tampered = copy.deepcopy(cert_dict)

    for claim in tampered.get("claims", []):
        spans = claim.get("evidence_spans", [])
        if not spans:
            continue

        if action == "drop" and len(spans) > 0:
            claim["evidence_spans"] = spans[1:]
        elif action == "reorder" and len(spans) > 1:
            claim["evidence_spans"] = list(reversed(spans))
        elif action == "drop_all":
            claim["evidence_spans"] = []

    return tampered


def a5_ui_tamper(cert_dict: dict) -> dict:
    """
    A5: UI tamper simulation — mark all claims as rendered/entailed
    without actually verifying. Changes render_decision and verification labels.
    """
    tampered = copy.deepcopy(cert_dict)

    for claim in tampered.get("claims", []):
        claim["render_decision"] = {
            "rendered": True,
            "reason_code": None,
        }
        claim["verification"]["label"] = "entailed"
        claim["verification"]["confidence"] = 0.99
        # Always change verifier_id to ensure the cert differs
        claim["verification"]["verifier_id"] = "ui-fake-bypass"
        claim["verification"]["verifier_version"] = "0.0.0"

    return tampered


def a6_replay(cert_dict: dict, new_query: str = "different query entirely") -> dict:
    """
    A6: Replay attack — reuse a previously valid certificate for a new query.

    The certificate itself is NOT modified (signature remains valid).
    Instead, the attacker presents this certificate as the answer to a
    *different* query.  The verifier detects this by checking whether
    query_commitment.query_hash matches the SHA-256 of the actual
    (presented) query.

    Returns the *unchanged* certificate dict together with a side-channel
    ``_replay_context`` that carries the new query for evaluation code.
    ``_replay_context`` is stripped before signature verification so it
    does not accidentally invalidate the signature.
    """
    # The certificate body is purposefully NOT altered — that is the
    # whole point of a replay attack.  Detection must happen by comparing
    # the cert's query_hash against the hash of the *actual* query the
    # user asked.
    replayed = copy.deepcopy(cert_dict)

    # Store the replay context in a side-channel key that evaluation
    # code knows to strip before signature verification.
    replayed["_replay_context"] = {
        "original_query_hash": replayed.get("query_commitment", {}).get("query_hash", ""),
        "presented_query": new_query,
    }
    return replayed


def a7_equivocation(cert_dict: dict) -> dict:
    """
    A7: Equivocation attack — provider issues a second, different
    certificate for the *same* query (same query_hash, different answer).

    This models a malicious or compromised provider that gives user A
    one answer and user B a different answer for the same question.

    Without a transparency log, neither user can discover the other
    certificate exists.  With a transparency log, an auditor can query
    all certificates for a given query_hash and discover the duplicate.

    The attack produces a VALID, correctly-structured certificate
    (unlike A1–A5 which tamper post-hoc).  Detection requires the
    transparency log to reveal multiple entries for the same query.

    We simulate this by modifying the answer text and claim text,
    then re-computing all hashes (but NOT re-signing — the cert
    is "as if" signed by the provider who chose to equivocate).

    The ``_equivocation_context`` side-channel carries metadata
    for evaluation code: this is a legitimately-formed cert that
    can only be detected via transparency log cross-referencing.
    """
    from core.crypto import sha256_hex as _sha256_hex

    equivocated = copy.deepcopy(cert_dict)

    # Change the answer text (provider gives a different answer)
    ac = equivocated.get("answer_commitment", {})
    original_answer = ac.get("answer_text", "")
    new_answer = f"[Equivocated] {original_answer} This alternative response was generated by the provider for a different audience."
    ac["answer_text"] = new_answer
    ac["answer_text_hash"] = _sha256_hex(new_answer)

    # Modify claim texts and recompute their hashes (provider-side)
    for claim in equivocated.get("claims", []):
        original_claim = claim.get("claim_text", "")
        claim["claim_text"] = f"Alternatively, {original_claim.lower()}"
        claim["claim_hash"] = _sha256_hex(claim["claim_text"])

        # Span hashes stay valid (same evidence, different interpretation)
        # This is realistic: same documents, different synthesis

    # The equivocated cert has consistent internal hashes — it is
    # internally valid.  Only the transparency log reveals duplicates.
    equivocated["_equivocation_context"] = {
        "original_answer_hash": _sha256_hex(original_answer),
        "equivocated_answer_hash": ac["answer_text_hash"],
        "same_query_hash": equivocated.get("query_commitment", {}).get("query_hash", ""),
        "detection_requires": "transparency_log",
    }

    return equivocated


# ---------------------------------------------------------------------------
# Attack registry
# ---------------------------------------------------------------------------

# Standard attacks: post-hoc tampering (A1–A6)
ATTACKS = {
    "A1_citation_swap": lambda c: a1_citation_swap(c),
    "A2_span_insert": lambda c: a2_span_substitution(c, mode="insert"),
    "A2_span_paraphrase": lambda c: a2_span_substitution(c, mode="paraphrase"),
    "A2_span_numbers": lambda c: a2_span_substitution(c, mode="numbers"),
    "A3_claim_negate": lambda c: a3_claim_edit(c, mode="negate"),
    "A3_claim_quantifier": lambda c: a3_claim_edit(c, mode="quantifier"),
    "A4_drop_span": lambda c: a4_reorder_drop(c, action="drop"),
    "A4_reorder_spans": lambda c: a4_reorder_drop(c, action="reorder"),
    "A4_drop_all_spans": lambda c: a4_reorder_drop(c, action="drop_all"),
    "A5_ui_tamper": lambda c: a5_ui_tamper(c),
    "A6_replay": lambda c: a6_replay(c),
}

# Transparency-dependent attacks (A7)
# These are kept separate because they require cross-certificate
# analysis via the transparency log, not single-cert verification.
TRANSPARENCY_ATTACKS = {
    "A7_equivocation": lambda c: a7_equivocation(c),
}

# Combined registry
ALL_ATTACKS = {**ATTACKS, **TRANSPARENCY_ATTACKS}


def run_all_attacks(cert_dict: dict) -> dict[str, dict]:
    """Run all standard attacks (A1-A6) and return {attack_name: tampered_cert_dict}."""
    results = {}
    for name, attack_fn in ATTACKS.items():
        results[name] = attack_fn(cert_dict)
    return results


def run_all_attacks_with_transparency(cert_dict: dict) -> dict[str, dict]:
    """Run ALL attacks including transparency-dependent (A1-A7)."""
    results = {}
    for name, attack_fn in ALL_ATTACKS.items():
        results[name] = attack_fn(cert_dict)
    return results
