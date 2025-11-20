import React, { useState, useEffect } from 'react';
import axios from 'axios';

function NetworkInfo() {
  const [networkInfo, setNetworkInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchNetworkInfo = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('/api/network-info');
      setNetworkInfo(response.data);
    } catch (err) {
      setError('ネットワーク情報の取得に失敗しました: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNetworkInfo();
  }, []);

  if (loading) return <div className="loading">読み込み中...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!networkInfo) return <div className="error">データがありません</div>;

  return (
    <div className="card">
      <h2>💻 ネットワーク情報</h2>
      
      <div className="info-item">
        <strong>ホスト名:</strong> {networkInfo.hostname}
      </div>
      
      <div className="info-item">
        <strong>プラットフォーム:</strong> {networkInfo.platform}
      </div>

      <h3>🔌 ネットワークインターフェース</h3>
      
      {networkInfo.interfaces && networkInfo.interfaces.map((iface, index) => (
        <div key={index} style={{ marginBottom: '2rem' }}>
          <h4 style={{ color: '#764ba2', marginTop: '1rem' }}>
            📡 {iface.name}
          </h4>
          
          {iface.ipv4 && iface.ipv4.length > 0 && (
            <div>
              <h5 style={{ color: '#667eea', marginTop: '1rem' }}>IPv4アドレス</h5>
              {iface.ipv4.map((ip, idx) => (
                <div key={idx} className="info-item">
                  <div><strong>IPアドレス:</strong> {ip.address}</div>
                  <div><strong>サブネットマスク:</strong> {ip.netmask}</div>
                  {ip.broadcast && <div><strong>ブロードキャスト:</strong> {ip.broadcast}</div>}
                  <div className="packet-explanation" style={{ marginTop: '0.5rem' }}>
                    💡 <strong>解説:</strong> このIPアドレスはあなたのPCがネットワーク内で識別されるための番号です。
                    サブネットマスクは同じネットワーク内のデバイスを特定するために使用されます。
                  </div>
                </div>
              ))}
            </div>
          )}

          {iface.ipv6 && iface.ipv6.length > 0 && (
            <div>
              <h5 style={{ color: '#667eea', marginTop: '1rem' }}>IPv6アドレス</h5>
              {iface.ipv6.map((ip, idx) => (
                <div key={idx} className="info-item">
                  <div><strong>IPアドレス:</strong> {ip.address}</div>
                  <div><strong>サブネットマスク:</strong> {ip.netmask}</div>
                  <div className="packet-explanation" style={{ marginTop: '0.5rem' }}>
                    💡 <strong>解説:</strong> IPv6は次世代のインターネットプロトコルで、
                    より多くのデバイスに対応できる長いアドレス形式です。
                  </div>
                </div>
              ))}
            </div>
          )}

          {iface.mac && iface.mac.length > 0 && (
            <div className="info-item">
              <strong>MACアドレス:</strong> {iface.mac.join(', ')}
              <div className="packet-explanation" style={{ marginTop: '0.5rem' }}>
                💡 <strong>解説:</strong> MACアドレスは各ネットワークカードに固有の識別番号で、
                製造時に割り当てられます。ローカルネットワーク内での通信に使用されます。
              </div>
            </div>
          )}
        </div>
      ))}

      <button className="button" onClick={fetchNetworkInfo}>
        🔄 更新
      </button>
    </div>
  );
}

export default NetworkInfo;
