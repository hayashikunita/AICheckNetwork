import React, { useState, useEffect } from 'react';
import axios from 'axios';

function NetworkStats() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('/api/network-stats');
      setStats(response.data);
    } catch (err) {
      setError('統計情報の取得に失敗しました: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000); // 5秒ごとに更新
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) return <div className="loading">読み込み中...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!stats) return <div className="error">データがありません</div>;

  return (
    <div className="card">
      <h2>📊 ネットワークトラフィック統計</h2>
      
      <div className="packet-explanation" style={{ marginBottom: '1.5rem' }}>
        💡 <strong>解説:</strong> このページでは、PCがネットワークを通じて送受信したデータの総量を確認できます。
        データは起動時からの累積値です。定期的に自動更新されます。
      </div>

      <div className="stats-grid">
        <div className="stat-box">
          <h4>📤 送信データ</h4>
          <div className="value">{formatBytes(stats.bytes_sent)}</div>
          <div className="unit">総送信量</div>
        </div>

        <div className="stat-box">
          <h4>📥 受信データ</h4>
          <div className="value">{formatBytes(stats.bytes_recv)}</div>
          <div className="unit">総受信量</div>
        </div>

        <div className="stat-box">
          <h4>📦 送信パケット</h4>
          <div className="value">{stats.packets_sent.toLocaleString()}</div>
          <div className="unit">個</div>
        </div>

        <div className="stat-box">
          <h4>📦 受信パケット</h4>
          <div className="value">{stats.packets_recv.toLocaleString()}</div>
          <div className="unit">個</div>
        </div>

        <div className="stat-box" style={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
          <h4>⚠️ 送信エラー</h4>
          <div className="value">{stats.errout.toLocaleString()}</div>
          <div className="unit">回</div>
        </div>

        <div className="stat-box" style={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
          <h4>⚠️ 受信エラー</h4>
          <div className="value">{stats.errin.toLocaleString()}</div>
          <div className="unit">回</div>
        </div>

        <div className="stat-box" style={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)' }}>
          <h4>📉 送信ドロップ</h4>
          <div className="value">{stats.dropout.toLocaleString()}</div>
          <div className="unit">個</div>
        </div>

        <div className="stat-box" style={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)' }}>
          <h4>📉 受信ドロップ</h4>
          <div className="value">{stats.dropin.toLocaleString()}</div>
          <div className="unit">個</div>
        </div>
      </div>

      <div className="info-item" style={{ marginTop: '2rem' }}>
        <h4 style={{ color: '#667eea', marginBottom: '1rem' }}>📚 用語解説</h4>
        <div style={{ lineHeight: '1.8' }}>
          <p><strong>送信/受信データ:</strong> PCがネットワークを通じて送受信したデータの総量です。</p>
          <p><strong>パケット:</strong> ネットワークで転送されるデータの単位。データは小さなパケットに分割されて送信されます。</p>
          <p><strong>エラー:</strong> 通信中に発生したエラーの回数。多い場合はネットワークに問題がある可能性があります。</p>
          <p><strong>ドロップ:</strong> 処理できずに破棄されたパケット数。多い場合は回線が混雑している可能性があります。</p>
        </div>
      </div>

      <button className="button" onClick={fetchStats}>
        🔄 手動更新
      </button>
    </div>
  );
}

export default NetworkStats;
