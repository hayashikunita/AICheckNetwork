import React, { useState } from 'react';
import axios from 'axios';

function NetworkDiagnostics() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const startDiagnostics = async () => {
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const res = await axios.get('/api/diagnostics');
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="network-diagnostics">
      <h2>🧰 ネットワーク診断コマンド</h2>
      <p>主要なネットワーク診断コマンドの結果（read-only）を取得して表示します。</p>
      <div className="controls">
        <button onClick={startDiagnostics} disabled={loading}>{loading ? '実行中...' : '診断実行'}</button>
      </div>

      {error && <div className="error">エラー: {JSON.stringify(error)}</div>}

      {results && (
        <div className="diagnostics-results">
          <h3>実行結果 (system: {results.system})</h3>
          {Object.entries(results.results || {}).map(([name, out]) => (
            <section key={name} className="diag-item">
              <h4>{name}</h4>
              {out.error ? (
                <pre className="diag-output">Error: {out.error}</pre>
              ) : (
                <>
                  <div className="diag-meta">returncode: {out.returncode}</div>
                  <div className="diag-section">
                    <strong>stdout</strong>
                    <pre className="diag-output">{out.stdout || '(empty)'}</pre>
                  </div>
                  <div className="diag-section">
                    <strong>stderr</strong>
                    <pre className="diag-output">{out.stderr || '(empty)'}</pre>
                  </div>
                </>
              )}
            </section>
          ))}
        </div>
      )}

    </div>
  );
}

export default NetworkDiagnostics;
