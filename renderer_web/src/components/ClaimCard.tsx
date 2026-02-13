import React from 'react';
import { ClaimVerification } from '../CertificateVerifier';

const styles: Record<string, React.CSSProperties> = {
  card: {
    border: '1px solid #30363d',
    borderRadius: '8px',
    padding: '16px',
    marginBottom: '12px',
    background: '#161b22',
  },
  cardBlocked: {
    border: '1px solid #f85149',
    borderRadius: '8px',
    padding: '16px',
    marginBottom: '12px',
    background: '#1c1210',
    opacity: 0.7,
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '8px',
  },
  badge: {
    padding: '2px 8px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: 600,
  },
  badgeVerified: {
    background: '#238636',
    color: '#fff',
  },
  badgeBlocked: {
    background: '#da3633',
    color: '#fff',
  },
  claimText: {
    fontSize: '15px',
    lineHeight: 1.5,
    marginBottom: '8px',
  },
  claimTextBlocked: {
    fontSize: '15px',
    lineHeight: 1.5,
    marginBottom: '8px',
    textDecoration: 'line-through',
    color: '#8b949e',
  },
  meta: {
    fontSize: '12px',
    color: '#8b949e',
    marginBottom: '8px',
  },
  spanBox: {
    background: '#0d1117',
    border: '1px solid #21262d',
    borderRadius: '4px',
    padding: '8px 12px',
    marginTop: '6px',
    fontSize: '13px',
  },
  spanInvalid: {
    background: '#1c1210',
    border: '1px solid #f85149',
    borderRadius: '4px',
    padding: '8px 12px',
    marginTop: '6px',
    fontSize: '13px',
  },
  reasonTag: {
    display: 'inline-block',
    background: '#30363d',
    color: '#f85149',
    padding: '2px 6px',
    borderRadius: '4px',
    fontSize: '11px',
    marginLeft: '8px',
  },
};

interface Props {
  claim: ClaimVerification;
}

export default function ClaimCard({ claim }: Props) {
  const isRendered = claim.rendered;

  return (
    <div style={isRendered ? styles.card : styles.cardBlocked}>
      <div style={styles.header}>
        <span style={{ ...styles.badge, ...(isRendered ? styles.badgeVerified : styles.badgeBlocked) }}>
          {isRendered ? '✓ VERIFIED' : '✗ BLOCKED'}
        </span>
        {claim.reasonCode && (
          <span style={styles.reasonTag}>{claim.reasonCode}</span>
        )}
      </div>

      <p style={isRendered ? styles.claimText : styles.claimTextBlocked}>
        {isRendered ? claim.claimText : `[Blocked] ${claim.claimText}`}
      </p>

      <div style={styles.meta}>
        Label: <strong>{claim.label}</strong> &nbsp;|&nbsp;
        Confidence: <strong>{(claim.confidence * 100).toFixed(1)}%</strong> &nbsp;|&nbsp;
        Hash: {claim.hashValid ? '✓' : '✗'}
      </div>

      {claim.spans.length > 0 && (
        <div>
          <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '4px' }}>
            Evidence ({claim.spans.length} span{claim.spans.length > 1 ? 's' : ''}):
          </div>
          {claim.spans.map((span) => (
            <div key={span.spanId} style={span.hashValid ? styles.spanBox : styles.spanInvalid}>
              <span style={{ color: '#58a6ff', fontSize: '11px' }}>
                [{span.docId}] {span.hashValid ? '✓' : '✗ HASH MISMATCH'}
              </span>
              <div style={{ marginTop: '4px', color: '#c9d1d9' }}>
                "{span.spanText}"
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
