import React from 'react';
import { CertificateVerificationResult } from '../CertificateVerifier';
import ClaimCard from './ClaimCard';

const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '800px',
    margin: '0 auto',
    padding: '20px',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '24px',
    padding: '16px',
    background: '#161b22',
    borderRadius: '8px',
    border: '1px solid #30363d',
  },
  shield: {
    fontSize: '48px',
  },
  statusValid: {
    color: '#3fb950',
    fontSize: '20px',
    fontWeight: 700,
  },
  statusInvalid: {
    color: '#f85149',
    fontSize: '20px',
    fontWeight: 700,
  },
  meta: {
    fontSize: '13px',
    color: '#8b949e',
    marginTop: '4px',
  },
  section: {
    marginBottom: '20px',
  },
  sectionTitle: {
    fontSize: '16px',
    fontWeight: 600,
    marginBottom: '12px',
    color: '#c9d1d9',
  },
  errorBox: {
    background: '#1c1210',
    border: '1px solid #f85149',
    borderRadius: '6px',
    padding: '12px',
    marginBottom: '16px',
    fontSize: '13px',
    color: '#f85149',
  },
  answerBox: {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '6px',
    padding: '16px',
    marginBottom: '20px',
    lineHeight: 1.6,
  },
  stats: {
    display: 'flex',
    gap: '16px',
    marginBottom: '20px',
  },
  stat: {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '6px',
    padding: '12px 16px',
    flex: 1,
    textAlign: 'center' as const,
  },
  statValue: {
    fontSize: '24px',
    fontWeight: 700,
  },
  statLabel: {
    fontSize: '12px',
    color: '#8b949e',
    marginTop: '4px',
  },
};

interface Props {
  result: CertificateVerificationResult;
}

export default function CertificateView({ result }: Props) {
  const allValid = result.signatureValid && result.commitmentsValid;
  const renderedCount = result.claims.filter(c => c.rendered).length;
  const blockedCount = result.claims.filter(c => !c.rendered).length;

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.shield}>
          {allValid ? '🛡️' : '⚠️'}
        </div>
        <div>
          <div style={allValid ? styles.statusValid : styles.statusInvalid}>
            {allValid
              ? 'Certificate Verified — Fail-Closed Rendering Active'
              : 'CERTIFICATE VERIFICATION FAILED — Content Blocked'}
          </div>
          <div style={styles.meta}>
            ID: {result.certId} &nbsp;|&nbsp;
            Issued: {result.issuedAt} &nbsp;|&nbsp;
            Schema: {result.schemaVersion}
          </div>
          <div style={styles.meta}>
            Signature: {result.signatureValid ? '✓ Valid' : '✗ INVALID'} &nbsp;|&nbsp;
            Commitments: {result.commitmentsValid ? '✓ Valid' : '✗ INVALID'}
          </div>
        </div>
      </div>

      {/* Errors */}
      {result.errors.length > 0 && (
        <div style={styles.errorBox}>
          <strong>Verification Errors:</strong>
          <ul style={{ margin: '8px 0 0 16px' }}>
            {result.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Stats */}
      <div style={styles.stats}>
        <div style={styles.stat}>
          <div style={{ ...styles.statValue, color: '#3fb950' }}>{renderedCount}</div>
          <div style={styles.statLabel}>Verified Claims</div>
        </div>
        <div style={styles.stat}>
          <div style={{ ...styles.statValue, color: '#f85149' }}>{blockedCount}</div>
          <div style={styles.statLabel}>Blocked Claims</div>
        </div>
        <div style={styles.stat}>
          <div style={styles.statValue}>{result.claims.length}</div>
          <div style={styles.statLabel}>Total Claims</div>
        </div>
      </div>

      {/* Answer Text */}
      <div style={styles.section}>
        <div style={styles.sectionTitle}>Answer (raw)</div>
        <div style={styles.answerBox}>
          {result.answerText}
        </div>
      </div>

      {/* Claims */}
      <div style={styles.section}>
        <div style={styles.sectionTitle}>
          Claims — Fail-Closed Rendering
        </div>
        {result.claims.map(claim => (
          <ClaimCard key={claim.claimId} claim={claim} />
        ))}
      </div>
    </div>
  );
}
