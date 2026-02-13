"""
PCRAG CLI Verifier — independent certificate verification tool.

Usage:
    python -m verifier_cli.cli verify cert.json --public-key <base64>
    python -m verifier_cli.cli inspect cert.json
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.canonicalize import canonicalize
from core.crypto import load_public_key_b64, sha256_hex, verify_bytes


console = Console()


def _load_certificate(path: str) -> dict:
    """Load a signed certificate JSON file."""
    with open(path) as f:
        data = json.load(f)

    # Support both wrapped (SignedCertificate) and bare formats
    if "certificate" in data and "signature" in data:
        return data
    else:
        raise click.ClickException(
            "Invalid format: expected JSON with 'certificate' and 'signature' fields"
        )


def _verify_signature(cert_dict: dict, signature_b64: str, pk_b64: str) -> bool:
    """Verify Ed25519 signature over JCS-canonical certificate bytes."""
    pk = load_public_key_b64(pk_b64)
    canonical = canonicalize(cert_dict)
    sig = base64.b64decode(signature_b64)
    return verify_bytes(canonical, sig, pk)


def _verify_commitments(cert_dict: dict) -> tuple[bool, list[str]]:
    """Verify all internal hash commitments. Returns (ok, errors)."""
    errors: list[str] = []

    # Answer text hash
    ac = cert_dict.get("answer_commitment", {})
    if ac.get("answer_text") and ac.get("answer_text_hash"):
        actual = sha256_hex(ac["answer_text"])
        if actual != ac["answer_text_hash"]:
            errors.append(f"Answer text hash MISMATCH (expected {ac['answer_text_hash'][:16]}..., got {actual[:16]}...)")

    # Claim and span hashes
    for i, claim in enumerate(cert_dict.get("claims", [])):
        cid = claim.get("claim_id", f"claim_{i}")

        if claim.get("claim_text") and claim.get("claim_hash"):
            actual = sha256_hex(claim["claim_text"])
            if actual != claim["claim_hash"]:
                errors.append(f"Claim {cid}: text hash MISMATCH")

        for j, span in enumerate(claim.get("evidence_spans", [])):
            sid = span.get("span_id", f"span_{j}")
            if span.get("span_text") and span.get("span_hash"):
                actual = sha256_hex(span["span_text"])
                if actual != span["span_hash"]:
                    errors.append(f"Span {sid} in claim {cid}: hash MISMATCH")

    return len(errors) == 0, errors


@click.group()
def main():
    """PCRAG Certificate Verifier — independent verification tool."""
    pass


@main.command()
@click.argument("cert_file", type=click.Path(exists=True))
@click.option("--public-key", "-k", required=True, help="Base64 Ed25519 public key")
@click.option("--strict/--no-strict", default=True, help="Fail-closed mode (default: strict)")
def verify(cert_file: str, public_key: str, strict: bool):
    """Verify a signed PCRAG certificate."""
    data = _load_certificate(cert_file)
    cert_dict = data["certificate"]
    signature = data["signature"]

    console.print(Panel("PCRAG Certificate Verification", style="bold blue"))

    # 1. Signature verification
    console.print("\n[bold]1. Signature Verification[/bold]")
    try:
        sig_ok = _verify_signature(cert_dict, signature, public_key)
    except Exception as e:
        sig_ok = False
        console.print(f"  [red]ERROR: {e}[/red]")

    if sig_ok:
        console.print("  [green]✓ Ed25519 signature is VALID[/green]")
    else:
        console.print("  [red]✗ Ed25519 signature is INVALID[/red]")
        if strict:
            console.print("\n[red]FAIL-CLOSED: Certificate rejected.[/red]")
            sys.exit(1)

    # 2. Hash commitment verification
    console.print("\n[bold]2. Hash Commitments[/bold]")
    commitments_ok, errors = _verify_commitments(cert_dict)

    if commitments_ok:
        console.print("  [green]✓ All hash commitments are VALID[/green]")
    else:
        for err in errors:
            console.print(f"  [red]✗ {err}[/red]")
        if strict:
            console.print("\n[red]FAIL-CLOSED: Certificate rejected due to hash mismatch.[/red]")
            sys.exit(1)

    # 3. Claim render decisions
    console.print("\n[bold]3. Claim Verification Summary[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Claim ID", width=14)
    table.add_column("Label", width=14)
    table.add_column("Confidence", width=12)
    table.add_column("Rendered", width=10)
    table.add_column("Reason", width=16)

    policy = cert_dict.get("policy", {})
    claims = cert_dict.get("claims", [])

    rendered_count = 0
    blocked_count = 0

    for claim in claims:
        cid = claim.get("claim_id", "?")
        verif = claim.get("verification", {})
        rd = claim.get("render_decision", {})

        label = verif.get("label", "?")
        conf = verif.get("confidence", 0.0)
        rendered = rd.get("rendered", False)
        reason = rd.get("reason_code", "")

        if rendered:
            rendered_count += 1
            status = "[green]YES[/green]"
        else:
            blocked_count += 1
            status = "[red]NO[/red]"

        table.add_row(
            cid,
            label,
            f"{conf:.4f}",
            status,
            reason or "-",
        )

    console.print(table)
    console.print(f"\n  Rendered: {rendered_count}/{len(claims)}  |  Blocked: {blocked_count}/{len(claims)}")

    # 4. Overall verdict
    all_ok = sig_ok and commitments_ok
    if all_ok:
        console.print("\n[bold green]✓ CERTIFICATE VERIFIED SUCCESSFULLY[/bold green]")
    else:
        console.print("\n[bold red]✗ CERTIFICATE VERIFICATION FAILED[/bold red]")
        sys.exit(1)


@main.command()
@click.argument("cert_file", type=click.Path(exists=True))
def inspect(cert_file: str):
    """Inspect a PCRAG certificate without verification."""
    data = _load_certificate(cert_file)
    cert = data["certificate"]

    console.print(Panel("PCRAG Certificate Inspection", style="bold cyan"))

    console.print(f"  Schema:    {cert.get('schema_version', '?')}")
    console.print(f"  ID:        {cert.get('certificate_id', '?')}")
    console.print(f"  Issued:    {cert.get('issued_at', '?')}")
    console.print(f"  Issuer:    {cert.get('issuer', {}).get('issuer_id', '?')}")
    console.print(f"  Key ID:    {cert.get('issuer', {}).get('public_key_id', '?')}")

    claims = cert.get("claims", [])
    console.print(f"\n  Claims:    {len(claims)}")
    for i, c in enumerate(claims, 1):
        ct = c.get("claim_text", "")[:80]
        label = c.get("verification", {}).get("label", "?")
        rendered = c.get("render_decision", {}).get("rendered", False)
        marker = "[green]✓[/green]" if rendered else "[red]✗[/red]"
        console.print(f"    {marker} [{label}] {ct}")

    ret = cert.get("retrieval_commitment", {})
    items = ret.get("retrieved_items", [])
    console.print(f"\n  Retrieved: {len(items)} items")
    for item in items:
        console.print(f"    - {item.get('doc_id', '?')}: {item.get('content_excerpt', '')[:60]}...")


if __name__ == "__main__":
    main()
