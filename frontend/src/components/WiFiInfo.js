import React, { useState, useEffect } from 'react';
import axios from 'axios';

function WiFiInfo() {
  const [wifiInfo, setWifiInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchWiFiInfo = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('/api/wifi-info');
      setWifiInfo(response.data);
    } catch (err) {
      setError('WiFi情報の取得に失敗しました: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWiFiInfo();
  }, []);

  if (loading) return <div className="loading">読み込み中...</div>;
  if (error) return <div className="error">{error}</div>;

  return (
    <div className="card">
      <h2>📶 WiFi情報</h2>

      {wifiInfo && wifiInfo.permission_error && (
        <div className="error">
          <h4>⚠️ 権限が必要です</h4>
          <p>{wifiInfo.message}</p>
          <div style={{ marginTop: '1rem', lineHeight: '1.8' }}>
            <strong>解決方法：</strong>
            <ol style={{ marginLeft: '1.5rem', marginTop: '0.5rem' }}>
              <li>PowerShellを<strong>管理者として実行</strong>してバックエンドを起動</li>
              <li>Windows設定で<strong>位置情報のアクセス許可</strong>を有効化
                <ul style={{ marginLeft: '1rem', marginTop: '0.3rem' }}>
                  <li>設定 → プライバシーとセキュリティ → 位置情報</li>
                  <li>「位置情報サービス」をオンにする</li>
                </ul>
              </li>
            </ol>
          </div>
        </div>
      )}

      {wifiInfo && wifiInfo.note && (
        <div style={{ 
          background: '#fff3cd', 
          border: '1px solid #ffc107', 
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '1rem',
          color: '#856404'
        }}>
          ℹ️ {wifiInfo.note}
        </div>
      )}

      {wifiInfo && wifiInfo.error && !wifiInfo.permission_error && (
        <div className="error">
          {wifiInfo.message || wifiInfo.error}
        </div>
      )}

      {wifiInfo && wifiInfo.connected && wifiInfo.connected.length > 0 && (
        <div>
          <h3>✅ 接続中のネットワーク / WiFiアダプター</h3>
          {wifiInfo.connected.map((network, index) => (
            <div key={index} className="wifi-network">
              <h4>📡 {network.ssid || network.interface_name || 'WiFiアダプター'}</h4>
              {network.interface_name && (
                <div className="wifi-detail">
                  <span><strong>インターフェース:</strong></span>
                  <span>{network.interface_name}</span>
                </div>
              )}
              {network.ssid && (
                <div className="wifi-detail">
                  <span><strong>SSID:</strong></span>
                  <span>{network.ssid}</span>
                </div>
              )}
              {network.signal && (
                <div className="wifi-detail">
                  <span><strong>シグナル強度:</strong></span>
                  <span>{network.signal}</span>
                </div>
              )}
              {network.state && (
                <div className="wifi-detail">
                  <span><strong>状態:</strong></span>
                  <span>{network.state}</span>
                </div>
              )}
              {network.channel && (
                <div className="wifi-detail">
                  <span><strong>チャネル:</strong></span>
                  <span>{network.channel}</span>
                </div>
              )}
              {network.radio_type && (
                <div className="wifi-detail">
                  <span><strong>無線タイプ:</strong></span>
                  <span>{network.radio_type}</span>
                </div>
              )}
              {network.speed && (
                <div className="wifi-detail">
                  <span><strong>速度:</strong></span>
                  <span>{network.speed}</span>
                </div>
              )}
              {network.is_up !== undefined && (
                <div className="wifi-detail">
                  <span><strong>状態:</strong></span>
                  <span>{network.is_up ? '有効' : '無効'}</span>
                </div>
              )}
              <div className="packet-explanation">
                💡 <strong>解説:</strong> {network.ssid ? 
                  'このWiFiネットワークに接続されています。' : 
                  'WiFiアダプターが検出されました。詳細情報を表示するには管理者権限が必要です。'}
              </div>
            </div>
          ))}
        </div>
      )}

      {wifiInfo && wifiInfo.available && wifiInfo.available.length > 0 && (
        <div>
          <h3>🔍 {wifiInfo.available[0].saved ? '保存済みのネットワーク' : '利用可能なネットワーク'}</h3>
          {wifiInfo.available.map((network, index) => (
            network.ssid && (
              <div key={index} className="wifi-network available">
                <h4>📶 {network.ssid}</h4>
                {network.signal && (
                  <div className="wifi-detail">
                    <span><strong>シグナル強度:</strong></span>
                    <span>{network.signal}</span>
                  </div>
                )}
                {network.authentication && (
                  <div className="wifi-detail">
                    <span><strong>セキュリティ:</strong></span>
                    <span>{network.authentication}</span>
                  </div>
                )}
                {network.saved && (
                  <div className="wifi-detail">
                    <span><strong>状態:</strong></span>
                    <span>保存済み</span>
                  </div>
                )}
                <div className="packet-explanation">
                  💡 <strong>解説:</strong> {network.saved ? 
                    'このネットワークは以前接続したことがあり、設定が保存されています。' :
                    'このネットワークは接続可能です。'}
                </div>
              </div>
            )
          ))}
        </div>
      )}

      {wifiInfo && (!wifiInfo.connected || wifiInfo.connected.length === 0) && 
       (!wifiInfo.available || wifiInfo.available.length === 0) && !wifiInfo.error && (
        <div className="info-item">
          WiFiネットワークが見つかりませんでした。WiFiアダプターが有効になっているか確認してください。
        </div>
      )}

      <button className="button" onClick={fetchWiFiInfo}>
        🔄 更新
      </button>
    </div>
  );
}

export default WiFiInfo;
