import React, { useState, useEffect } from 'react';
import axios from 'axios';

function PacketAnalysis() {
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [copying, setCopying] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');

  const fetchStatistics = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://localhost:5000/api/capture/statistics');
      setStatistics(response.data);
    } catch (err) {
      setError('統計情報の取得に失敗しました: ' + err.message);
      console.error('Statistics fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const exportStatistics = async () => {
    setExporting(true);
    try {
      const response = await axios.get('http://localhost:5000/api/capture/statistics/export', {
        responseType: 'blob'
      });
      
      // Blobからダウンロード
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // ファイル名を取得（Content-Dispositionヘッダーから）
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'packet_statistics.json';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      alert('統計データをエクスポートしました: ' + filename);
    } catch (err) {
      alert('エクスポートに失敗しました: ' + err.message);
      console.error('Export error:', err);
    } finally {
      setExporting(false);
    }
  };

  useEffect(() => {
    fetchStatistics();
  }, []);

  if (loading && !statistics) {
    return (
      <div className="card">
        <h2>📊 パケットキャプチャ統計解析</h2>
        <div className="info-item">読み込み中...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <h2>📊 パケットキャプチャ統計解析</h2>
        <div className="error">{error}</div>
        <button className="button" onClick={fetchStatistics}>
          🔄 再読み込み
        </button>
      </div>
    );
  }

  if (!statistics || statistics.total_packets === 0) {
    return (
      <div className="card">
        <h2>📊 パケットキャプチャ統計解析</h2>
        <div className="packet-explanation" style={{ marginBottom: '1.5rem' }}>
          <h3 style={{ color: '#667eea', marginBottom: '0.8rem' }}>
            💡 パケットキャプチャの統計的分析
          </h3>
          <p style={{ lineHeight: '1.8' }}>
            このページでは、キャプチャしたパケットを統計的に分析し、ネットワークの状況を可視化します。
          </p>
          <ul style={{ marginLeft: '1.5rem', lineHeight: '2', marginTop: '0.5rem' }}>
            <li>✅ <strong>プロトコル分布</strong> - TCP/UDP/ICMPの使用比率</li>
            <li>✅ <strong>ポート分析</strong> - よく使われるポート番号TOP20</li>
            <li>✅ <strong>IPアドレス統計</strong> - 通信相手の分析</li>
            <li>✅ <strong>パケットサイズ分析</strong> - データ量の分布</li>
            <li>✅ <strong>時系列分析</strong> - パケット/秒の計算</li>
            <li>✅ <strong>セキュリティ分析</strong> - 暗号化通信の割合</li>
            <li>✅ <strong>トップトーカー</strong> - 通信量が多いIPアドレス</li>
          </ul>
        </div>
        <div className="info-item" style={{ textAlign: 'center', marginTop: '2rem' }}>
          <p>パケットキャプチャを実行してから、このページで統計情報を確認できます。</p>
          <p style={{ marginTop: '1rem', color: '#666' }}>
            「パケットキャプチャ」タブでパケットを収集してください。
          </p>
        </div>
        <button className="button" onClick={fetchStatistics} style={{ marginTop: '1rem' }}>
          🔄 統計情報を更新
        </button>
      </div>
    );
  }

  const { 
    total_packets, 
    protocol_distribution, 
    port_distribution,
    ip_statistics,
    packet_size_stats,
    time_analysis,
    top_talkers,
    security_analysis,
    tcp_flags,
    anomaly_detection,
    suspicious_ips
  } = statistics;

  // プロトコル分布のパーセンテージ計算
  const protocolPercentages = Object.entries(protocol_distribution).map(([protocol, count]) => ({
    protocol,
    count,
    percentage: ((count / total_packets) * 100).toFixed(1)
  }));

  // セキュリティスコアの計算
  const totalSecurityPackets = security_analysis.encrypted_packets + security_analysis.unencrypted_packets;
  const securityScore = totalSecurityPackets > 0 
    ? ((security_analysis.encrypted_packets / totalSecurityPackets) * 100).toFixed(1)
    : 0;

  return (
    <div className="card">
      <h2>📊 パケットキャプチャ統計解析</h2>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div className="info-item" style={{ margin: 0 }}>
          <strong>総パケット数:</strong> {total_packets.toLocaleString()}
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button 
            className="button" 
            onClick={exportStatistics}
            disabled={exporting}
            style={{ 
              backgroundColor: exporting ? '#95a5a6' : '#28a745',
              cursor: exporting ? 'not-allowed' : 'pointer'
            }}
          >
            {exporting ? '📥 エクスポート中...' : '📥 統計データをエクスポート'}
          </button>
          <button
            className="button"
            onClick={async () => {
              // 一時的な状態制御
              setCopying(true);
              setCopyStatus('');
              try {
                const jsonText = JSON.stringify(statistics, null, 2);
                if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                  await navigator.clipboard.writeText(jsonText);
                } else {
                  // フォールバック: テキストエリアを作って選択・コピー
                  const ta = document.createElement('textarea');
                  ta.value = jsonText;
                  ta.style.position = 'fixed';
                  ta.style.left = '-9999px';
                  document.body.appendChild(ta);
                  ta.select();
                  document.execCommand('copy');
                  ta.remove();
                }
                setCopyStatus('✅ コピーしました');
                // フィードバックを短時間表示
                setTimeout(() => setCopyStatus(''), 2500);
              } catch (err) {
                console.error('Copy statistics error:', err);
                setCopyStatus('✖ コピーに失敗しました');
                setTimeout(() => setCopyStatus(''), 3000);
              } finally {
                setCopying(false);
              }
            }}
            disabled={copying}
            style={{ backgroundColor: copying ? '#95a5a6' : '#007bff' }}
          >
            {copying ? 'コピー中...' : '📋 統計をコピー'}
          </button>
          <button className="button" onClick={fetchStatistics}>
            🔄 更新
          </button>
        </div>
      </div>
      {copyStatus && (
        <div style={{ marginTop: '8px', color: copyStatus.startsWith('✅') ? '#28a745' : '#dc3545' }}>
          {copyStatus}
        </div>
      )}

      {/* 概要カード */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '1rem',
        marginBottom: '2rem'
      }}>
        <div style={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          padding: '1.5rem',
          borderRadius: '12px',
          color: 'white',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            {total_packets.toLocaleString()}
          </div>
          <div style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>総パケット数</div>
        </div>

        <div style={{
          background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
          padding: '1.5rem',
          borderRadius: '12px',
          color: 'white',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            {(packet_size_stats.total_bytes / 1024).toFixed(1)} KB
          </div>
          <div style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>総データ量</div>
        </div>

        <div style={{
          background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
          padding: '1.5rem',
          borderRadius: '12px',
          color: 'white',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            {time_analysis.packets_per_second.toFixed(1)}
          </div>
          <div style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>パケット/秒</div>
        </div>

        <div style={{
          background: securityScore > 50 
            ? 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)'
            : 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
          padding: '1.5rem',
          borderRadius: '12px',
          color: 'white',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            {securityScore}%
          </div>
          <div style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>暗号化率</div>
        </div>
      </div>

      {/* 異常検知セクション */}
      {anomaly_detection && (
        <>
          {anomaly_detection.warnings && anomaly_detection.warnings.length > 0 && (
            <div style={{ 
              padding: '15px', 
              backgroundColor: '#fff3cd', 
              border: '2px solid #ffc107',
              borderRadius: '8px',
              marginBottom: '20px'
            }}>
              <h3 style={{ margin: '0 0 10px 0', color: '#856404' }}>
                ⚠️ セキュリティ警告
              </h3>
              {anomaly_detection.warnings.map((warning, idx) => (
                <div key={idx} style={{ marginBottom: '8px' }}>
                  <strong>{warning.message}</strong>
                  <p style={{ margin: '5px 0 0 0', fontSize: '14px' }}>{warning.details}</p>
                </div>
              ))}
            </div>
          )}

          <div style={{ marginBottom: '2rem' }}>
            <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>🚨 異常検知</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
              {/* ポートスキャン検出 */}
              {anomaly_detection.port_scanning && anomaly_detection.port_scanning.length > 0 && (
                <div style={{ 
                  padding: '15px', 
                  backgroundColor: '#f8d7da', 
                  border: '1px solid #f5c6cb',
                  borderRadius: '8px'
                }}>
                  <h4 style={{ margin: '0 0 10px 0', color: '#721c24' }}>
                    🚨 ポートスキャン検出
                  </h4>
                  {anomaly_detection.port_scanning.map((item, idx) => (
                    <div key={idx} style={{ 
                      backgroundColor: 'white', 
                      padding: '10px', 
                      borderRadius: '5px',
                      marginBottom: '8px'
                    }}>
                      <div style={{ fontWeight: 'bold', color: '#dc3545' }}>
                        IP: {item.ip}
                      </div>
                      <div style={{ fontSize: '13px', marginTop: '5px' }}>
                        {item.ports_accessed}個のポートに接続
                      </div>
                      <div style={{ fontSize: '12px', color: '#666', marginTop: '3px' }}>
                        {item.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* SYNフラッド検出 */}
              {anomaly_detection.syn_flood && anomaly_detection.syn_flood.length > 0 && (
                <div style={{ 
                  padding: '15px', 
                  backgroundColor: '#f8d7da', 
                  border: '1px solid #f5c6cb',
                  borderRadius: '8px'
                }}>
                  <h4 style={{ margin: '0 0 10px 0', color: '#721c24' }}>
                    🚨 SYNフラッド検出
                  </h4>
                  {anomaly_detection.syn_flood.map((item, idx) => (
                    <div key={idx} style={{ 
                      backgroundColor: 'white', 
                      padding: '10px', 
                      borderRadius: '5px',
                      marginBottom: '8px'
                    }}>
                      <div style={{ fontWeight: 'bold', color: '#dc3545' }}>
                        IP: {item.ip}
                      </div>
                      <div style={{ fontSize: '13px', marginTop: '5px' }}>
                        {item.syn_count}個のSYNパケット
                      </div>
                      <div style={{ fontSize: '12px', color: '#666', marginTop: '3px' }}>
                        {item.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* 不審なポート使用 */}
              {anomaly_detection.unusual_ports && anomaly_detection.unusual_ports.length > 0 && (
                <div style={{ 
                  padding: '15px', 
                  backgroundColor: '#fff3cd', 
                  border: '1px solid #ffeaa7',
                  borderRadius: '8px'
                }}>
                  <h4 style={{ margin: '0 0 10px 0', color: '#856404' }}>
                    ⚡ 不審なポート使用
                  </h4>
                  {anomaly_detection.unusual_ports.map((item, idx) => (
                    <div key={idx} style={{ 
                      backgroundColor: 'white', 
                      padding: '10px', 
                      borderRadius: '5px',
                      marginBottom: '8px'
                    }}>
                      <div style={{ fontWeight: 'bold', color: '#856404' }}>
                        ポート: {item.port}
                      </div>
                      <div style={{ fontSize: '13px', marginTop: '5px' }}>
                        {item.count}回の使用
                      </div>
                      <div style={{ fontSize: '12px', color: '#666', marginTop: '3px' }}>
                        {item.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* 高トラフィックIP */}
              {anomaly_detection.high_traffic_ips && anomaly_detection.high_traffic_ips.length > 0 && (
                <div style={{ 
                  padding: '15px', 
                  backgroundColor: '#fff3cd', 
                  border: '1px solid #ffeaa7',
                  borderRadius: '8px'
                }}>
                  <h4 style={{ margin: '0 0 10px 0', color: '#856404' }}>
                    📊 異常な高トラフィック
                  </h4>
                  {anomaly_detection.high_traffic_ips.map((item, idx) => (
                    <div key={idx} style={{ 
                      backgroundColor: 'white', 
                      padding: '10px', 
                      borderRadius: '5px',
                      marginBottom: '8px'
                    }}>
                      <div style={{ fontWeight: 'bold', color: '#856404' }}>
                        IP: {item.ip}
                      </div>
                      <div style={{ fontSize: '13px', marginTop: '5px' }}>
                        {item.packet_count}パケット
                      </div>
                      <div style={{ fontSize: '12px', color: '#666', marginTop: '3px' }}>
                        {item.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* 接続失敗 */}
              {anomaly_detection.failed_connections && anomaly_detection.failed_connections.length > 0 && (
                <div style={{ 
                  padding: '15px', 
                  backgroundColor: '#d1ecf1', 
                  border: '1px solid #bee5eb',
                  borderRadius: '8px'
                }}>
                  <h4 style={{ margin: '0 0 10px 0', color: '#0c5460' }}>
                    🔌 接続失敗の多いIP
                  </h4>
                  {anomaly_detection.failed_connections.map((item, idx) => (
                    <div key={idx} style={{ 
                      backgroundColor: 'white', 
                      padding: '10px', 
                      borderRadius: '5px',
                      marginBottom: '8px'
                    }}>
                      <div style={{ fontWeight: 'bold', color: '#0c5460' }}>
                        IP: {item.ip}
                      </div>
                      <div style={{ fontSize: '13px', marginTop: '5px' }}>
                        {item.rst_count}回の接続失敗
                      </div>
                      <div style={{ fontSize: '12px', color: '#666', marginTop: '3px' }}>
                        {item.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* 不審なIPアドレス分析 */}
      {suspicious_ips && suspicious_ips.length > 0 && (
        <div style={{ marginBottom: '2rem' }}>
          <h3 style={{ 
            color: '#dc3545',
            marginBottom: '1rem'
          }}>
            🔍 不審なIPアドレス分析
          </h3>
          <div style={{ display: 'grid', gap: '15px' }}>
            {suspicious_ips.map((item, idx) => {
              const severityColors = {
                high: { bg: '#f8d7da', border: '#dc3545', text: '#721c24' },
                medium: { bg: '#fff3cd', border: '#ffc107', text: '#856404' },
                low: { bg: '#d1ecf1', border: '#17a2b8', text: '#0c5460' }
              };
              const colors = severityColors[item.severity] || severityColors.low;

              return (
                <div key={idx} style={{ 
                  padding: '15px', 
                  backgroundColor: colors.bg, 
                  border: `2px solid ${colors.border}`,
                  borderRadius: '8px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                    <div>
                      <div style={{ fontSize: '18px', fontWeight: 'bold', color: colors.text }}>
                        {item.ip}
                        {item.is_private && <span style={{ 
                          marginLeft: '10px', 
                          fontSize: '12px', 
                          padding: '2px 8px',
                          backgroundColor: '#6c757d',
                          color: 'white',
                          borderRadius: '4px'
                        }}>プライベートIP</span>}
                      </div>
                      <div style={{ fontSize: '13px', color: '#666', marginTop: '3px' }}>
                        パケット数: {item.packet_count} | 疑わしさスコア: {item.suspicion_score}/10
                      </div>
                    </div>
                    <div style={{ 
                      padding: '5px 12px',
                      backgroundColor: colors.border,
                      color: 'white',
                      borderRadius: '5px',
                      fontSize: '12px',
                      fontWeight: 'bold',
                      textTransform: 'uppercase'
                    }}>
                      {item.severity === 'high' ? '高リスク' : item.severity === 'medium' ? '中リスク' : '低リスク'}
                    </div>
                  </div>
                  
                  <div style={{ marginBottom: '10px' }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '5px', color: colors.text }}>
                      検出された問題:
                    </div>
                    <ul style={{ margin: '0', paddingLeft: '20px' }}>
                      {item.reasons.map((reason, ridx) => (
                        <li key={ridx} style={{ fontSize: '14px', marginBottom: '3px' }}>
                          {reason}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div style={{ 
                    padding: '10px',
                    backgroundColor: 'white',
                    borderRadius: '5px',
                    fontSize: '14px',
                    fontWeight: 'bold',
                    color: colors.text
                  }}>
                    {item.recommendation}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* プロトコル分布 */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>🔗 プロトコル分布</h3>
        <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
          {protocolPercentages.map(({ protocol, count, percentage }) => (
            <div key={protocol} style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                <span><strong>{protocol}</strong></span>
                <span>{count}個 ({percentage}%)</span>
              </div>
              <div style={{ 
                width: '100%', 
                height: '20px', 
                background: '#e0e0e0', 
                borderRadius: '10px',
                overflow: 'hidden'
              }}>
                <div style={{
                  width: `${percentage}%`,
                  height: '100%',
                  background: protocol === 'TCP' ? '#667eea' : 
                             protocol === 'UDP' ? '#f093fb' :
                             protocol === 'ICMP' ? '#4facfe' : '#43e97b',
                  transition: 'width 0.3s ease'
                }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* パケットサイズ統計 */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>📏 パケットサイズ統計</h3>
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: '1rem',
          marginBottom: '1rem'
        }}>
          <div className="info-item">
            <strong>最小:</strong> {packet_size_stats.min} bytes
          </div>
          <div className="info-item">
            <strong>最大:</strong> {packet_size_stats.max} bytes
          </div>
          <div className="info-item">
            <strong>平均:</strong> {packet_size_stats.average.toFixed(1)} bytes
          </div>
        </div>
        
        <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
          <h4 style={{ marginBottom: '1rem' }}>サイズ分布</h4>
          {Object.entries(packet_size_stats.size_distribution).map(([range, count]) => (
            <div key={range} style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                <span>{range} bytes</span>
                <span>{count}個 ({((count / total_packets) * 100).toFixed(1)}%)</span>
              </div>
              <div style={{ 
                width: '100%', 
                height: '15px', 
                background: '#e0e0e0', 
                borderRadius: '8px',
                overflow: 'hidden'
              }}>
                <div style={{
                  width: `${(count / total_packets) * 100}%`,
                  height: '100%',
                  background: '#667eea',
                  transition: 'width 0.3s ease'
                }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* トップポート */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>🔌 よく使われるポート TOP20</h3>
        <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.5rem' }}>
            {port_distribution.top_ports.slice(0, 20).map(({ port, count }) => (
              <div key={port} style={{ 
                padding: '0.5rem',
                background: 'white',
                borderRadius: '6px',
                display: 'flex',
                justifyContent: 'space-between',
                boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
              }}>
                <span><strong>ポート {port}</strong></span>
                <span style={{ color: '#667eea' }}>{count}回</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* トップトーカー */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>💬 トップトーカー（通信量TOP10）</h3>
        <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
          {top_talkers.map(({ ip, bytes, packets }, index) => (
            <div key={ip} style={{ 
              marginBottom: '1rem',
              padding: '1rem',
              background: 'white',
              borderRadius: '8px',
              borderLeft: '4px solid #667eea'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>
                    #{index + 1} {ip}
                  </div>
                  <div style={{ color: '#666', fontSize: '0.9rem', marginTop: '0.3rem' }}>
                    {packets}パケット
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#667eea' }}>
                    {(bytes / 1024).toFixed(1)} KB
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* IPアドレス統計 */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>🌐 IPアドレス統計</h3>
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '1rem'
        }}>
          <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
            <h4>送信元IP TOP10</h4>
            {ip_statistics.top_src_ips.map(([ip, count]) => (
              <div key={ip} style={{ 
                display: 'flex', 
                justifyContent: 'space-between',
                padding: '0.5rem',
                marginTop: '0.5rem',
                background: 'white',
                borderRadius: '6px'
              }}>
                <span>{ip}</span>
                <span style={{ color: '#667eea', fontWeight: 'bold' }}>{count}</span>
              </div>
            ))}
          </div>

          <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
            <h4>宛先IP TOP10</h4>
            {ip_statistics.top_dst_ips.map(([ip, count]) => (
              <div key={ip} style={{ 
                display: 'flex', 
                justifyContent: 'space-between',
                padding: '0.5rem',
                marginTop: '0.5rem',
                background: 'white',
                borderRadius: '6px'
              }}>
                <span>{ip}</span>
                <span style={{ color: '#667eea', fontWeight: 'bold' }}>{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* セキュリティ分析 */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>🔒 セキュリティ分析</h3>
        <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: '1rem',
            marginBottom: '1rem'
          }}>
            <div className="info-item">
              <strong>暗号化通信:</strong> {security_analysis.encrypted_packets}個
            </div>
            <div className="info-item">
              <strong>非暗号化通信:</strong> {security_analysis.unencrypted_packets}個
            </div>
            <div className="info-item">
              <strong>高重要度:</strong> {security_analysis.high_importance}個
            </div>
            <div className="info-item">
              <strong>中重要度:</strong> {security_analysis.medium_importance}個
            </div>
          </div>
          
          {securityScore < 50 && totalSecurityPackets > 0 && (
            <div style={{ 
              background: '#fff3cd', 
              border: '2px solid #ffc107',
              padding: '1rem', 
              borderRadius: '8px',
              marginTop: '1rem'
            }}>
              <strong>⚠️ セキュリティ警告:</strong> 暗号化されていない通信が多く検出されました。
              機密情報を送信する際は、HTTPS、SSH、VPNなどの暗号化通信を使用してください。
            </div>
          )}
          
          {securityScore >= 50 && (
            <div style={{ 
              background: '#d4edda', 
              border: '2px solid #28a745',
              padding: '1rem', 
              borderRadius: '8px',
              marginTop: '1rem'
            }}>
              <strong>✅ セキュリティ良好:</strong> 通信の多くが暗号化されています。
            </div>
          )}
        </div>
      </div>

      {/* 時系列分析 */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>⏱️ 時系列分析</h3>
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem'
        }}>
          <div className="info-item">
            <strong>キャプチャ時間:</strong> {time_analysis.duration_seconds.toFixed(2)}秒
          </div>
          <div className="info-item">
            <strong>平均レート:</strong> {time_analysis.packets_per_second.toFixed(2)} パケット/秒
          </div>
          <div className="info-item">
            <strong>開始時刻:</strong> {time_analysis.start_time 
              ? new Date(time_analysis.start_time).toLocaleTimeString('ja-JP')
              : 'N/A'}
          </div>
          <div className="info-item">
            <strong>終了時刻:</strong> {time_analysis.end_time
              ? new Date(time_analysis.end_time).toLocaleTimeString('ja-JP')
              : 'N/A'}
          </div>
        </div>
      </div>

      {/* TCPフラグ統計 */}
      {Object.keys(tcp_flags).length > 0 && (
        <div style={{ marginBottom: '2rem' }}>
          <h3 style={{ color: '#667eea', marginBottom: '1rem' }}>🚩 TCPフラグ統計</h3>
          <div style={{ background: '#f8f9fa', padding: '1rem', borderRadius: '8px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))', gap: '0.5rem' }}>
              {Object.entries(tcp_flags).map(([flag, count]) => (
                <div key={flag} style={{ 
                  padding: '0.5rem',
                  background: 'white',
                  borderRadius: '6px',
                  textAlign: 'center',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
                }}>
                  <div style={{ fontWeight: 'bold', color: '#667eea' }}>{flag}</div>
                  <div style={{ fontSize: '0.9rem', color: '#666' }}>{count}個</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default PacketAnalysis;
