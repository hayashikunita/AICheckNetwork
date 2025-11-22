import React, { useState } from 'react';
import axios from 'axios';

function NetworkDevices() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);
  const [ports, setPorts] = useState('22,80,443');
  const [limit, setLimit] = useState(256);

  const startScan = async () => {
    setLoading(true);
    setError(null);
    setResults([]);
    try {
      const res = await axios.get('/api/network/scan', {
        params: { ports, limit }
      });
      setResults(res.data.results || []);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="network-devices">
      <h2>🔎 ネットワークデバイススキャン</h2>
      <p>ローカルネットワーク上の機器を自動検出し、IP / MAC / 簡易ポート情報を表示します。</p>

      <div className="controls">
        <label>チェックするポート (カンマ区切り): </label>
        <input value={ports} onChange={(e) => setPorts(e.target.value)} />
        <label style={{ marginLeft: 16 }}>ホスト上限 (1インターフェース当たり): </label>
        <input type="number" value={limit} onChange={(e) => setLimit(Number(e.target.value))} style={{ width: 100 }} />
        <button onClick={startScan} disabled={loading} style={{ marginLeft: 12 }}>{loading ? 'スキャン中...' : 'スキャン開始'}</button>
      </div>

      {error && <div className="error">エラー: {error}</div>}

      {results.length === 0 && !loading && <div className="hint">スキャン結果がまだありません — 「スキャン開始」を押してください。</div>}

      {results.map((iface) => (
        <section key={iface.interface} className="scan-interface">
          <h3>{iface.interface} — {iface.address} ({iface.network})</h3>
          {iface.discovered.length === 0 ? (
            <div>検出されたデバイスはありません。</div>
          ) : (
            <table className="devices-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>MAC</th>
                  <th>開いているポート</th>
                </tr>
              </thead>
              <tbody>
                {iface.discovered.map((d) => (
                  <tr key={d.ip}>
                    <td>{d.ip}</td>
                    <td>{d.mac}</td>
                    <td>{d.open_ports && d.open_ports.length ? d.open_ports.join(', ') : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ))}

    </div>
  );
}

export default NetworkDevices;
