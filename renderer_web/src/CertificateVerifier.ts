/**
 * PCRAG Certificate Verifier — client-side verification logic.
 *
 * Implements:
 *  1. SHA-256 hash commitment checks (claim_hash, span_hash, answer_text_hash)
 *  2. Ed25519 signature verification over JCS-canonical certificate bytes
 *  3. Fail-closed render policy evaluation
 *
 * Uses tweetnacl for Ed25519 and js-sha256 for hashing (both pure JS, no WASM).
 */

import nacl from 'tweetnacl';
import { sha256 } from 'js-sha256';

// ---------------------------------------------------------------------------
// JCS Canonicalization (RFC 8785) — minimal TypeScript implementation
// ---------------------------------------------------------------------------

function jcsSerializeString(s: string): string {
  let buf = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const cp = s.charCodeAt(i);
    if (ch === '\\') buf += '\\\\';
    else if (ch === '"') buf += '\\"';
    else if (ch === '\b') buf += '\\b';
    else if (ch === '\f') buf += '\\f';
    else if (ch === '\n') buf += '\\n';
    else if (ch === '\r') buf += '\\r';
    else if (ch === '\t') buf += '\\t';
    else if (cp < 0x20) buf += '\\u' + cp.toString(16).padStart(4, '0');
    else buf += ch;
  }
  return buf + '"';
}

function jcsSerialize(obj: any): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') {
    if (!isFinite(obj)) throw new Error('NaN/Infinity not allowed in JCS');
    if (Number.isInteger(obj)) return obj.toString();
    if (obj === Math.trunc(obj) && Math.abs(obj) < 2 ** 53) return Math.trunc(obj).toString();
    return JSON.stringify(obj);
  }
  if (typeof obj === 'string') return jcsSerializeString(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(jcsSerialize).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => jcsSerializeString(k) + ':' + jcsSerialize(obj[k]));
    return '{' + pairs.join(',') + '}';
  }
  throw new Error(`Cannot JCS-serialize type ${typeof obj}`);
}

export function canonicalize(obj: any): Uint8Array {
  const str = jcsSerialize(obj);
  return new TextEncoder().encode(str);
}

// ---------------------------------------------------------------------------
// Verification types
// ---------------------------------------------------------------------------

export interface ClaimVerification {
  claimId: string;
  claimText: string;
  rendered: boolean;
  reasonCode: string | null;
  label: string;
  confidence: number;
  hashValid: boolean;
  spans: SpanVerification[];
}

export interface SpanVerification {
  spanId: string;
  docId: string;
  spanText: string;
  hashValid: boolean;
}

export interface CertificateVerificationResult {
  signatureValid: boolean;
  commitmentsValid: boolean;
  answerHashValid: boolean;
  claims: ClaimVerification[];
  errors: string[];
  certId: string;
  issuedAt: string;
  schemaVersion: string;
  answerText: string;
}

// ---------------------------------------------------------------------------
// SHA-256 helper
// ---------------------------------------------------------------------------

function sha256Hex(text: string): string {
  return sha256(text);
}

// ---------------------------------------------------------------------------
// Main verification function
// ---------------------------------------------------------------------------

export function verifyCertificate(
  certificate: any,
  signatureB64: string,
  publicKeyB64: string,
  confidenceThreshold: number = 0.5,
): CertificateVerificationResult {
  const errors: string[] = [];
  let signatureValid = false;
  let commitmentsValid = true;

  // 1. Verify Ed25519 signature
  try {
    const canonicalBytes = canonicalize(certificate);
    const sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
    const pkBytes = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0));
    signatureValid = nacl.sign.detached.verify(canonicalBytes, sigBytes, pkBytes);
  } catch (e: any) {
    errors.push(`Signature verification error: ${e.message}`);
    signatureValid = false;
  }

  if (!signatureValid) {
    errors.push('Ed25519 signature is INVALID');
  }

  // 2. Verify answer text hash
  const ac = certificate.answer_commitment || {};
  let answerHashValid = true;
  if (ac.answer_text && ac.answer_text_hash) {
    const actual = sha256Hex(ac.answer_text);
    if (actual !== ac.answer_text_hash) {
      answerHashValid = false;
      commitmentsValid = false;
      errors.push('Answer text hash mismatch');
    }
  }

  // 3. Verify claims
  const policy = certificate.policy || {};
  const threshold = policy.confidence_threshold || confidenceThreshold;
  const claims: ClaimVerification[] = [];

  for (const claim of (certificate.claims || [])) {
    const claimHashValid = claim.claim_text && claim.claim_hash
      ? sha256Hex(claim.claim_text) === claim.claim_hash
      : true;

    if (!claimHashValid) {
      commitmentsValid = false;
      errors.push(`Claim ${claim.claim_id}: hash mismatch`);
    }

    const spans: SpanVerification[] = [];
    let allSpansValid = true;

    for (const span of (claim.evidence_spans || [])) {
      const spanHashValid = span.span_text && span.span_hash
        ? sha256Hex(span.span_text) === span.span_hash
        : true;

      if (!spanHashValid) {
        allSpansValid = false;
        commitmentsValid = false;
        errors.push(`Span ${span.span_id}: hash mismatch`);
      }

      spans.push({
        spanId: span.span_id,
        docId: span.doc_id,
        spanText: span.span_text || '',
        hashValid: spanHashValid,
      });
    }

    const verif = claim.verification || {};
    const rd = claim.render_decision || {};
    const label = verif.label || 'not_supported';
    const confidence = verif.confidence || 0;

    // Fail-closed: only render if everything checks out
    const shouldRender = signatureValid
      && claimHashValid
      && allSpansValid
      && label === 'entailed'
      && confidence >= threshold
      && rd.rendered === true;

    let reasonCode = rd.reason_code || null;
    if (!signatureValid) reasonCode = 'SIGNATURE_INVALID';
    else if (!claimHashValid || !allSpansValid) reasonCode = 'HASH_MISMATCH';
    else if (!rd.rendered) reasonCode = rd.reason_code || 'NOT_SUPPORTED';

    claims.push({
      claimId: claim.claim_id,
      claimText: claim.claim_text,
      rendered: shouldRender,
      reasonCode: shouldRender ? null : reasonCode,
      label,
      confidence,
      hashValid: claimHashValid,
      spans,
    });
  }

  return {
    signatureValid,
    commitmentsValid,
    answerHashValid,
    claims,
    errors,
    certId: certificate.certificate_id || '',
    issuedAt: certificate.issued_at || '',
    schemaVersion: certificate.schema_version || '',
    answerText: ac.answer_text || '',
  };
}
