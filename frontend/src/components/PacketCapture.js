import React, { useState, useEffect } from 'react';
import axios from 'axios';

function PacketCapture() {
  const [packets, setPackets] = useState([]);
  const [isCapturing, setIsCapturing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [packetCount, setPacketCount] = useState(100);
  const [sessionId, setSessionId] = useState(null);
  const [pollInterval, setPollInterval] = useState(null);
  const [copiedIndex, setCopiedIndex] = useState(null);

  const fetchPackets = async () => {
    try {
      const response = await axios.get('/api/capture/packets');
      setPackets(response.data.packets || []);
      
      // バックエンドのキャプチャ状態を確認
      const statusResponse = await axios.get('/api/capture/status');
      const backendIsCapturing = statusResponse.data.is_capturing;
      setSessionId(statusResponse.data.session_id);
      setIsCapturing(backendIsCapturing);
      
      // バックエンドでキャプチャが終了していたらポーリングを停止
      if (!backendIsCapturing && pollInterval) {
        console.log('キャプチャが完了したため、ポーリングを停止します');
        clearInterval(pollInterval);
        setPollInterval(null);
      }
    } catch (err) {
      console.error('パケット取得エラー:', err);
    }
  };

  const startCapture = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post('/api/capture/start', {
        interface: null,
        count: parseInt(packetCount)
      });
      setIsCapturing(true);
      setLoading(false);
      
      // キャプチャ開始後、定期的にパケットを取得
      const interval = setInterval(() => {
        fetchPackets();
      }, 1000);
      setPollInterval(interval);
      
    } catch (err) {
      setError('キャプチャの開始に失敗しました: ' + err.message);
      setIsCapturing(false);
      setLoading(false);
    }
  };

  const stopCapture = async () => {
    setLoading(true);
    setError(null);
    
    // ポーリングを停止
    if (pollInterval) {
      clearInterval(pollInterval);
      setPollInterval(null);
    }
    
    try {
      await axios.post('/api/capture/stop');
      setIsCapturing(false);
      await fetchPackets();
    } catch (err) {
      setError('キャプチャの停止に失敗しました: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const exportJSON = async () => {
    try {
      const response = await axios.get('/api/capture/export/json', {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `packet_capture_${Date.now()}.json`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError('JSONエクスポートに失敗しました: ' + err.message);
      console.error('Export error:', err);
    }
  };

  const exportPCAP = async () => {
    try {
      const response = await axios.get('/api/capture/export/pcap', {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `packet_capture_${Date.now()}.pcap`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError('PCAPエクスポートに失敗しました: ' + err.message);
      console.error('Export error:', err);
    }
  };

  const exportCSV = async () => {
    try {
      const response = await axios.get('/api/capture/export/csv', {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `packet_capture_${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError('CSVエクスポートに失敗しました: ' + err.message);
      console.error('Export error:', err);
    }
  };

  useEffect(() => {
    // クリーンアップ時にポーリングを停止
    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [pollInterval]);

  return (
    <div className="card">
      <h2>🔍 パケットキャプチャ</h2>

      <div className="packet-explanation" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '0.8rem' }}>💡 Wireshark不要の簡単パケット解析</h3>
        <p style={{ lineHeight: '1.8' }}>
          <strong>このツールでできること：</strong>
        </p>
        <ul style={{ marginLeft: '1.5rem', lineHeight: '2', marginTop: '0.5rem' }}>
          <li>✅ <strong>専門知識不要</strong> - 各パケットに初心者向けの詳しい解説付き</li>
          <li>✅ <strong>Wireshark不要</strong> - ブラウザだけで簡単にネットワーク監視</li>
          <li>✅ <strong>リアルタイム解析</strong> - TCP/UDP/ICMP/ARPを自動識別</li>
          <li>✅ <strong>セキュリティチェック</strong> - 暗号化の有無を確認</li>
          <li>✅ <strong>ポート番号解説</strong> - 各サービスを自動判別して説明</li>
          <li>✅ <strong>視覚的</strong> - カラーコードでプロトコルを識別</li>
        </ul>
        <p style={{ marginTop: '1rem', fontWeight: '600', color: '#e74c3c' }}>
          ⚠️ <strong>注意:</strong> この機能を使用するには管理者権限が必要です。
          PowerShellを管理者として実行してバックエンドを起動してください。
        </p>
      </div>

      {error && <div className="error">{error}</div>}

      <div style={{ marginBottom: '1.5rem' }}>
        <label htmlFor="packetCount" style={{ marginRight: '1rem', fontWeight: '600' }}>
          キャプチャするパケット数:
        </label>
        <input
          id="packetCount"
          type="number"
          value={packetCount}
          onChange={(e) => setPacketCount(e.target.value)}
          min="10"
          max="1000"
          disabled={isCapturing}
          style={{
            padding: '0.5rem',
            borderRadius: '6px',
            border: '2px solid #667eea',
            fontSize: '1rem',
            width: '100px'
          }}
        />
      </div>

      <div style={{ marginBottom: '1.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <button
          className="button"
          onClick={startCapture}
          disabled={isCapturing || loading}
        >
          {isCapturing ? '🔴 キャプチャ中...' : '▶️ キャプチャ開始'}
        </button>
        <button
          className="button danger"
          onClick={stopCapture}
          disabled={!isCapturing || loading}
        >
          ⏹️ 停止
        </button>
        <button
          className="button"
          onClick={fetchPackets}
          disabled={loading}
        >
          🔄 更新
        </button>
      </div>

      {packets.length > 0 && (
        <div style={{ 
          background: '#f8f9fa', 
          padding: '1rem', 
          borderRadius: '8px',
          marginBottom: '1.5rem'
        }}>
          <h4 style={{ color: '#667eea', marginBottom: '1rem' }}>
            💾 キャプチャデータのエクスポート
          </h4>
          <p style={{ marginBottom: '1rem', fontSize: '0.95rem' }}>
            キャプチャしたパケットを様々な形式でダウンロードできます
          </p>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              className="button"
              onClick={exportJSON}
              style={{ background: '#28a745' }}
            >
              📄 JSON形式でダウンロード
            </button>
            <button
              className="button"
              onClick={exportPCAP}
              style={{ background: '#17a2b8' }}
            >
              📦 PCAP形式でダウンロード (Wireshark対応)
            </button>
            <button
              className="button"
              onClick={exportCSV}
              style={{ background: '#ffc107', color: '#333' }}
            >
              📊 CSV形式でダウンロード (Excel対応)
            </button>
          </div>
          <div style={{ 
            marginTop: '1rem', 
            fontSize: '0.9rem', 
            color: '#666',
            lineHeight: '1.6'
          }}>
            <strong>ファイル形式の説明：</strong>
            <ul style={{ marginLeft: '1.5rem', marginTop: '0.5rem' }}>
              <li><strong>JSON:</strong> 詳細な解説付き、このアプリで再度読み込み可能</li>
              <li><strong>PCAP:</strong> Wiresharkなどの専門ツールで開ける標準形式</li>
              <li><strong>CSV:</strong> ExcelやGoogleスプレッドシートで開ける表形式</li>
            </ul>
          </div>
        </div>
      )}

      <div className="info-item">
        <strong>状態:</strong> {isCapturing ? '🔴 キャプチャ中' : '⚫ 停止中'}
        <span style={{ marginLeft: '2rem' }}>
          <strong>キャプチャ済みパケット数:</strong> {packets.length}
        </span>
      </div>

      {packets.length > 0 && (
        <div>
          <h3 style={{ marginTop: '2rem', marginBottom: '1rem' }}>
            📦 キャプチャしたパケット ({packets.length}個)
          </h3>
          <div className="packet-list">
            {packets.slice().reverse().map((packet, index) => (
              <div 
                key={index} 
                className="packet-item"
                style={{
                  borderLeftColor: 
                    packet.importance === 'high' ? '#e74c3c' :
                    packet.importance === 'medium' ? '#f39c12' :
                    packet.importance === 'low' ? '#95a5a6' : '#667eea',
                  borderLeftWidth: packet.importance === 'high' ? '6px' : '4px'
                }}
              >
                <div className="packet-header">
                  <div>
                    <span className={`packet-type ${packet.type}`}>
                      {packet.type}
                    </span>
                    {packet.importance === 'high' && (
                      <span style={{ 
                        marginLeft: '0.5rem', 
                        fontSize: '0.85rem',
                        background: '#e74c3c',
                        color: 'white',
                        padding: '0.2rem 0.6rem',
                        borderRadius: '12px'
                      }}>
                        重要
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.85rem', color: '#666' }}>
                      {new Date(packet.timestamp).toLocaleTimeString('ja-JP')}
                    </span>
                    <button
                      onClick={async () => {
                        try {
                          const text = JSON.stringify(packet, null, 2);
                          if (navigator.clipboard && navigator.clipboard.writeText) {
                            await navigator.clipboard.writeText(text);
                          } else {
                            // Fallback
                            const ta = document.createElement('textarea');
                            ta.value = text;
                            document.body.appendChild(ta);
                            ta.select();
                            document.execCommand('copy');
                            ta.parentNode.removeChild(ta);
                          }
                          setCopiedIndex(index);
                          setTimeout(() => setCopiedIndex(null), 2000);
                        } catch (e) {
                          console.error('コピーに失敗しました', e);
                        }
                      }}
                      className="button"
                      style={{ padding: '6px 10px', fontSize: '12px' }}
                    >
                      {copiedIndex === index ? '✅ Copied' : '📋 コピー'}
                    </button>
                  </div>
                </div>
                
                <div className="packet-details">
                  <div><strong>パケット長:</strong> {packet.length} bytes</div>
                  <div><strong>概要:</strong> {packet.summary}</div>
                  
                  {packet.ip && (
                    <div style={{ marginTop: '0.5rem' }}>
                      <div>
                        <strong>送信元IP:</strong> {packet.ip.src} → 
                        <strong> 宛先IP:</strong> {packet.ip.dst}
                      </div>
                      <div style={{ fontSize: '0.9rem', color: '#666' }}>
                        <strong>TTL:</strong> {packet.ip.ttl} | 
                        <strong> IPバージョン:</strong> IPv{packet.ip.version}
                      </div>
                    </div>
                  )}
                  
                  {packet.tcp && (
                    <div style={{ marginTop: '0.5rem' }}>
                      <div>
                        <strong>TCPポート:</strong> {packet.tcp.sport} → {packet.tcp.dport}
                      </div>
                      <div style={{ fontSize: '0.9rem', color: '#666' }}>
                        <strong>フラグ:</strong> {packet.tcp.flags} | 
                        <strong> シーケンス:</strong> {packet.tcp.seq} | 
                        <strong> ACK:</strong> {packet.tcp.ack}
                      </div>
                      {packet.payload_length > 0 && (
                        <div style={{ fontSize: '0.9rem', color: '#666' }}>
                          <strong>ペイロード:</strong> {packet.payload_length} bytes
                        </div>
                      )}
                      {packet.http_data && (
                        <div style={{ 
                          background: '#e8f5e9', 
                          padding: '0.5rem', 
                          borderRadius: '4px',
                          marginTop: '0.3rem',
                          fontSize: '0.9rem'
                        }}>
                          <strong>🌐 HTTP:</strong> {packet.http_data}
                        </div>
                      )}
                    </div>
                  )}
                  
                  {packet.udp && (
                    <div style={{ marginTop: '0.5rem' }}>
                      <div>
                        <strong>UDPポート:</strong> {packet.udp.sport} → {packet.udp.dport}
                      </div>
                      <div style={{ fontSize: '0.9rem', color: '#666' }}>
                        <strong>長さ:</strong> {packet.udp.length} bytes
                      </div>
                      {packet.dns_query && (
                        <div style={{ 
                          background: '#e3f2fd', 
                          padding: '0.5rem', 
                          borderRadius: '4px',
                          marginTop: '0.3rem',
                          fontSize: '0.9rem'
                        }}>
                          <strong>🔍 DNSクエリ:</strong> {packet.dns_query}
                        </div>
                      )}
                      {packet.dns_answer && (
                        <div style={{ 
                          background: '#e3f2fd', 
                          padding: '0.5rem', 
                          borderRadius: '4px',
                          marginTop: '0.3rem',
                          fontSize: '0.9rem'
                        }}>
                          <strong>✅ DNS応答:</strong> {packet.dns_answer}
                        </div>
                      )}
                    </div>
                  )}
                  
                  {packet.icmp && (
                    <div style={{ marginTop: '0.5rem' }}>
                      <strong>ICMPタイプ:</strong> {packet.icmp.type}
                      <span style={{ marginLeft: '1rem' }}>
                        <strong>コード:</strong> {packet.icmp.code}
                      </span>
                    </div>
                  )}
                  
                  {packet.arp && (
                    <div style={{ marginTop: '0.5rem' }}>
                      <div>
                        <strong>ARP操作:</strong> {packet.arp.op === 1 ? 'リクエスト' : '応答'}
                      </div>
                      <div style={{ fontSize: '0.9rem' }}>
                        <strong>IP:</strong> {packet.arp.psrc} → {packet.arp.pdst}
                      </div>
                      <div style={{ fontSize: '0.9rem', color: '#666' }}>
                        <strong>MAC:</strong> {packet.arp.hwsrc} → {packet.arp.hwdst}
                      </div>
                    </div>
                  )}
                </div>
                
                {packet.explanation && (
                  <div className="packet-explanation">
                    💡 <strong>詳細解説:</strong>
                    <div style={{ marginTop: '0.5rem', lineHeight: '1.6' }}>
                      {packet.explanation.split(' | ').map((line, idx) => (
                        <div key={idx} style={{ marginTop: idx > 0 ? '0.3rem' : 0 }}>
                          {line}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {packets.length === 0 && !isCapturing && (
        <div className="info-item" style={{ marginTop: '2rem', textAlign: 'center' }}>
          キャプチャを開始すると、ここにパケット情報が表示されます。
        </div>
      )}
    </div>
  );
}

export default PacketCapture;
