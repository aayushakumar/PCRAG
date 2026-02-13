import React, { useState } from 'react';
import { verifyCertificate, CertificateVerificationResult } from './CertificateVerifier';
import CertificateView from './components/CertificateView';

const styles: Record<string, React.CSSProperties> = {
  app: {
    minHeight: '100vh',
    background: '#0d1117',
    color: '#c9d1d9',
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  },
  nav: {
    background: '#161b22',
    borderBottom: '1px solid #30363d',
    padding: '12px 24px',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  logo: {
    fontSize: '20px',
    fontWeight: 700,
    color: '#58a6ff',
  },
  subtitle: {
    fontSize: '13px',
    color: '#8b949e',
  },
  main: {
    maxWidth: '900px',
    margin: '0 auto',
    padding: '24px',
  },
  querySection: {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '8px',
    padding: '20px',
    marginBottom: '24px',
  },
  label: {
    fontSize: '14px',
    fontWeight: 600,
    marginBottom: '8px',
    display: 'block',
  },
  input: {
    width: '100%',
    padding: '10px 14px',
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '6px',
    color: '#c9d1d9',
    fontSize: '14px',
    outline: 'none',
  },
  textarea: {
    width: '100%',
    padding: '10px 14px',
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '6px',
    color: '#c9d1d9',
    fontSize: '13px',
    fontFamily: 'monospace',
    outline: 'none',
    resize: 'vertical' as const,
    minHeight: '120px',
  },
  buttonRow: {
    display: 'flex',
    gap: '12px',
    marginTop: '16px',
  },
  button: {
    padding: '10px 20px',
    background: '#238636',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    fontSize: '14px',
    fontWeight: 600,
    cursor: 'pointer',
  },
  buttonSecondary: {
    padding: '10px 20px',
    background: '#30363d',
    color: '#c9d1d9',
    border: '1px solid #484f58',
    borderRadius: '6px',
    fontSize: '14px',
    cursor: 'pointer',
  },
  tabs: {
    display: 'flex',
    gap: '4px',
    marginBottom: '20px',
  },
  tab: {
    padding: '8px 16px',
    borderRadius: '6px 6px 0 0',
    cursor: 'pointer',
    fontSize: '14px',
    border: '1px solid #30363d',
    borderBottom: 'none',
    background: '#0d1117',
    color: '#8b949e',
  },
  tabActive: {
    padding: '8px 16px',
    borderRadius: '6px 6px 0 0',
    cursor: 'pointer',
    fontSize: '14px',
    border: '1px solid #30363d',
    borderBottom: '2px solid #58a6ff',
    background: '#161b22',
    color: '#c9d1d9',
    fontWeight: 600,
  },
  loading: {
    textAlign: 'center' as const,
    padding: '40px',
    color: '#8b949e',
    fontSize: '16px',
  },
};

type Tab = 'query' | 'paste';

export default function App() {
  const [tab, setTab] = useState<Tab>('query');
  const [query, setQuery] = useState('What is Python and who created it?');
  const [pasteJson, setPasteJson] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [result, setResult] = useState<CertificateVerificationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiUrl, setApiUrl] = useState('http://localhost:8000');

  async function handleQuery() {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const resp = await fetch(`${apiUrl}/pcrag/answer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });

      if (!resp.ok) throw new Error(`API error: ${resp.status}`);
      const data = await resp.json();

      const verificationResult = verifyCertificate(
        data.certificate,
        data.signature,
        data.public_key,
      );

      setResult(verificationResult);
      setPublicKey(data.public_key);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleVerifyPaste() {
    setError(null);
    setResult(null);

    try {
      const data = JSON.parse(pasteJson);
      const cert = data.certificate;
      const sig = data.signature;
      const pk = data.public_key || publicKey;

      if (!cert || !sig || !pk) {
        setError('JSON must contain "certificate", "signature", and "public_key" fields.');
        return;
      }

      const verificationResult = verifyCertificate(cert, sig, pk);
      setResult(verificationResult);
    } catch (e: any) {
      setError(`Parse error: ${e.message}`);
    }
  }

  return (
    <div style={styles.app}>
      <nav style={styles.nav}>
        <span style={styles.logo}>PCRAG</span>
        <span style={styles.subtitle}>Proof-Carrying RAG — Fail-Closed Verifying Renderer</span>
      </nav>

      <div style={styles.main}>
        {/* Tabs */}
        <div style={styles.tabs}>
          <div
            style={tab === 'query' ? styles.tabActive : styles.tab}
            onClick={() => setTab('query')}
          >
            Query API
          </div>
          <div
            style={tab === 'paste' ? styles.tabActive : styles.tab}
            onClick={() => setTab('paste')}
          >
            Verify Certificate
          </div>
        </div>

        {/* Query Tab */}
        {tab === 'query' && (
          <div style={styles.querySection}>
            <label style={styles.label}>API Server</label>
            <input
              style={{ ...styles.input, marginBottom: '12px' }}
              value={apiUrl}
              onChange={e => setApiUrl(e.target.value)}
              placeholder="http://localhost:8000"
            />
            <label style={styles.label}>Query</label>
            <input
              style={styles.input}
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Ask a question..."
              onKeyDown={e => e.key === 'Enter' && handleQuery()}
            />
            <div style={styles.buttonRow}>
              <button style={styles.button} onClick={handleQuery} disabled={loading}>
                {loading ? 'Generating...' : 'Generate & Verify'}
              </button>
            </div>
          </div>
        )}

        {/* Paste Tab */}
        {tab === 'paste' && (
          <div style={styles.querySection}>
            <label style={styles.label}>
              Paste signed certificate JSON (with "certificate", "signature", "public_key")
            </label>
            <textarea
              style={styles.textarea}
              value={pasteJson}
              onChange={e => setPasteJson(e.target.value)}
              placeholder='{"certificate": {...}, "signature": "...", "public_key": "..."}'
            />
            <div style={styles.buttonRow}>
              <button style={styles.button} onClick={handleVerifyPaste}>
                Verify Certificate
              </button>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{
            background: '#1c1210',
            border: '1px solid #f85149',
            borderRadius: '6px',
            padding: '12px',
            marginBottom: '16px',
            color: '#f85149',
          }}>
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && <div style={styles.loading}>Generating certificate and verifying...</div>}

        {/* Result */}
        {result && <CertificateView result={result} />}
      </div>
    </div>
  );
}
