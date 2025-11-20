import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

function PacketChatbot() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'こんにちは！パケットキャプチャ相談チャットボットです。🤖\n\nネットワークやパケットキャプチャに関する質問にお答えします。例えば:\n\n• パケットキャプチャの使い方\n• 特定のプロトコルについて\n• セキュリティの懸念事項\n• エラーのトラブルシューティング\n• ネットワーク用語の解説\n\n何でもお気軽にお尋ねください！'
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [statistics, setStatistics] = useState(null);
  const messagesEndRef = useRef(null);

  // よくある質問のサンプル
  const quickQuestions = [
    'パケットキャプチャとは何ですか？',
    'TCPとUDPの違いは？',
    'HTTPSは安全ですか？',
    '不審なポートとは？',
    'ポートスキャンとは何ですか？',
    'パケット解析の方法は？'
  ];

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    // 統計データを取得
    fetchStatistics();
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const fetchStatistics = async () => {
    try {
      const response = await axios.get('/api/capture/statistics');
      if (response.data.total_packets > 0) {
        setStatistics(response.data);
      }
    } catch (err) {
      console.error('Statistics fetch error:', err);
    }
  };

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = input.trim();
    setInput('');
    
    // ユーザーメッセージを追加
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      // ボットの応答を生成
      const response = await generateResponse(userMessage);
      
      setTimeout(() => {
        setMessages(prev => [...prev, { role: 'assistant', content: response }]);
        setLoading(false);
      }, 500);
    } catch (err) {
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: '申し訳ございません。エラーが発生しました。もう一度お試しください。' 
      }]);
      setLoading(false);
    }
  };

  const generateResponse = async (question) => {
    const lowerQuestion = question.toLowerCase();

    // パケットキャプチャ基本
    if (lowerQuestion.includes('パケットキャプチャ') && (lowerQuestion.includes('とは') || lowerQuestion.includes('何'))) {
      return `📦 **パケットキャプチャとは**

ネットワーク上を流れるデータパケットを傍受・記録する技術です。

**主な用途:**
• ネットワークのトラブルシューティング
• セキュリティ監視と脅威検出
• 通信プロトコルの分析
• パフォーマンスの最適化

**このアプリでの使い方:**
1. 「🔍 パケットキャプチャ」タブを開く
2. インターフェースとパケット数を選択
3. 「キャプチャ開始」ボタンをクリック
4. 完了したら「📈 統計解析」で結果を確認

注意: 管理者権限が必要です！`;
    }

    // TCP vs UDP
    if ((lowerQuestion.includes('tcp') || lowerQuestion.includes('udp')) && 
        (lowerQuestion.includes('違い') || lowerQuestion.includes('比較'))) {
      return `🔗 **TCPとUDPの違い**

**TCP (Transmission Control Protocol):**
✅ 信頼性が高い - データの到達を保証
✅ 順序保証 - パケットが正しい順番で届く
✅ エラー訂正機能あり
❌ 遅い - 確認応答が必要
🎯 用途: Webブラウジング、メール、ファイル転送

**UDP (User Datagram Protocol):**
✅ 高速 - 確認応答なし
✅ オーバーヘッドが少ない
❌ 信頼性なし - パケット損失の可能性
❌ 順序保証なし
🎯 用途: 動画ストリーミング、オンラインゲーム、DNS

**選択の基準:**
• 正確性重視 → TCP
• 速度重視 → UDP`;
    }

    // HTTPS セキュリティ
    if (lowerQuestion.includes('https') || (lowerQuestion.includes('ssl') || lowerQuestion.includes('tls'))) {
      return `🔒 **HTTPSのセキュリティ**

HTTPSは安全な通信プロトコルです！

**セキュリティ機能:**
✅ 暗号化 - データが読めない形式で送信
✅ 認証 - 正しいサーバーと通信していることを確認
✅ 完全性 - データの改ざんを検出

**仕組み:**
1. SSL/TLS証明書による暗号化
2. 公開鍵暗号方式でセッション鍵を交換
3. すべての通信を暗号化

**確認方法:**
• ブラウザのアドレスバーに🔒マークがある
• URLが "https://" で始まる
• 証明書情報が確認できる

**注意点:**
⚠️ HTTPSでも完全に安全とは限らない
⚠️ フィッシングサイトもHTTPSを使える
⚠️ 証明書の有効性を確認すること`;
    }

    // ポート番号
    if (lowerQuestion.includes('ポート') && (lowerQuestion.includes('何') || lowerQuestion.includes('とは'))) {
      return `🚪 **ポート番号について**

ポート番号は、コンピュータ内のサービスを識別する番号です。

**よく使われるポート:**
• **80** - HTTP (Web)
• **443** - HTTPS (安全なWeb)
• **22** - SSH (リモートログイン)
• **21** - FTP (ファイル転送)
• **25** - SMTP (メール送信)
• **53** - DNS (名前解決)
• **3389** - RDP (リモートデスクトップ)

**範囲:**
• 0-1023: ウェルノウンポート（有名なサービス）
• 1024-49151: 登録済みポート
• 49152-65535: 動的ポート（一時的な使用）

**セキュリティ:**
不要なポートは閉じておくべき！
開いているポートは攻撃の入り口になる可能性があります。`;
    }

    // 不審なポート
    if (lowerQuestion.includes('不審') && lowerQuestion.includes('ポート')) {
      return `⚠️ **不審なポート番号**

以下のポートが検出された場合は注意が必要です：

**ハッカーツール:**
• 1337, 31337 - Leet speak ports
• 12345, 54321 - NetBus (トロイの木馬)

**バックドア:**
• 4444, 5555 - よく使われるバックドア
• 6667-6669 - IRC (ボットネット通信)

**プロキシ/トンネル:**
• 1080 - SOCKS プロキシ
• 3128 - Squid プロキシ
• 8080 - HTTP 代替ポート

**対処方法:**
1. ファイアウォールでブロック
2. 不審なプロセスを終了
3. ウイルススキャンを実行
4. ネットワーク管理者に報告

このアプリの「📈 統計解析」タブで不審なポート使用を自動検出できます！`;
    }

    // ポートスキャン
    if (lowerQuestion.includes('ポートスキャン')) {
      return `🔍 **ポートスキャンとは**

ポートスキャンは、対象システムの開いているポートを探す行為です。

**目的:**
**正当な用途:**
• セキュリティ診断
• ネットワークの健全性チェック
• 脆弱性評価

**悪意ある用途:**
• 攻撃前の偵察
• 脆弱性の発見
• バックドアの探索

**検出方法:**
✅ 短時間に多数の異なるポートへの接続
✅ SYNパケットの大量送信
✅ 順番にポートを試行

**このアプリでの検出:**
「📈 統計解析」タブの「異常検知」セクションで、
同一IPから20以上の異なるポートへの接続を自動検出します。

**対策:**
• ファイアウォールの設定
• IDS/IPS の導入
• 不要なポートを閉じる
• ログの監視`;
    }

    // SYNフラッド
    if (lowerQuestion.includes('syn') && (lowerQuestion.includes('フラッド') || lowerQuestion.includes('攻撃'))) {
      return `🚨 **SYNフラッド攻撃**

SYNフラッド攻撃は、TCPの3ウェイハンドシェイクを悪用したDoS攻撃です。

**攻撃の仕組み:**
1. 攻撃者が大量のSYNパケットを送信
2. サーバーがSYN-ACKで応答して接続待ち状態
3. 攻撃者は最終ACKを送らない
4. サーバーのリソースが枯渇

**影響:**
❌ サーバーの接続リソース枯渇
❌ 正当なユーザーが接続できない
❌ サービス停止（DoS）

**検出方法:**
このアプリでは、同一IPから50回以上のSYNパケットを検出すると警告を表示します。

**対策:**
• SYN Cookies の有効化
• ファイアウォールでのレート制限
• IDS/IPSでの検出とブロック
• タイムアウト値の調整

「📈 統計解析」で自動検出できます！`;
    }

    // プロトコル解説
    if (lowerQuestion.includes('プロトコル') && (lowerQuestion.includes('とは') || lowerQuestion.includes('何'))) {
      return `📡 **ネットワークプロトコル**

プロトコルは、通信のルール・規約です。

**主要プロトコル:**

**TCP (Transmission Control Protocol):**
信頼性の高いデータ転送

**UDP (User Datagram Protocol):**
高速だが信頼性は低い

**ICMP (Internet Control Message Protocol):**
エラー通知、診断（Ping）

**ARP (Address Resolution Protocol):**
IPアドレス → MACアドレス変換

**DNS (Domain Name System):**
ドメイン名 → IPアドレス変換

**HTTP/HTTPS:**
Web通信

**FTP (File Transfer Protocol):**
ファイル転送

**SMTP/POP3/IMAP:**
メール送受信

このアプリの「📈 統計解析」でプロトコル分布を確認できます！`;
    }

    // パケット解析
    if (lowerQuestion.includes('解析') || lowerQuestion.includes('分析')) {
      return `📊 **パケット解析の方法**

このアプリでパケットを効果的に解析する方法：

**1. パケットキャプチャ**
• 「🔍 パケットキャプチャ」タブでパケットを収集
• 適切なインターフェースを選択
• 必要なパケット数を設定（推奨: 100-500）

**2. 基本解析**
• キャプチャ画面でパケット一覧を確認
• 各パケットの詳細情報を表示
• 重要度（high/medium/low）をチェック

**3. 統計解析**
• 「📈 統計解析」タブを開く
• プロトコル分布を確認
• ポート使用状況をチェック
• IPアドレス統計を確認

**4. セキュリティチェック**
• 異常検知セクションを確認
• 不審なIPアドレスをチェック
• ポートスキャンやSYNフラッドを検出

**5. データエクスポート**
• JSON形式で統計データをエクスポート
• PCAP形式でWiresharkで詳細解析
• CSV形式でExcelで分析

**コツ:**
• 通常時のトラフィックを把握しておく
• 異常値に注目する
• 時間帯による変化を観察`;
    }

    // トラブルシューティング
    if (lowerQuestion.includes('エラー') || lowerQuestion.includes('できない') || 
        lowerQuestion.includes('失敗') || lowerQuestion.includes('問題')) {
      return `🔧 **トラブルシューティング**

よくある問題と解決方法：

**1. キャプチャが開始できない**
✅ 管理者権限で実行しているか確認
✅ ネットワークインターフェースが有効か確認
✅ 他のパケットキャプチャツールを終了

**2. パケットが表示されない**
✅ 正しいインターフェースを選択
✅ トラフィックが実際に発生しているか確認
✅ ファイアウォールの設定を確認

**3. エクスポートが失敗する**
✅ ディスク容量を確認
✅ 書き込み権限があるか確認
✅ ファイル名に特殊文字がないか確認

**4. 統計が表示されない**
✅ パケットをキャプチャしたか確認
✅ ブラウザをリフレッシュ
✅ バックエンドが起動しているか確認

**5. 不審なIPが多数検出される**
✅ プライベートIPは通常問題なし
✅ マルチキャストアドレスは正常な場合も
✅ コンテキストを考慮して判断

それでも解決しない場合は、具体的なエラーメッセージを教えてください！`;
    }

    // 統計データがある場合の分析
    if (statistics && (lowerQuestion.includes('分析') || lowerQuestion.includes('統計') || 
        lowerQuestion.includes('結果') || lowerQuestion.includes('データ'))) {
      let analysis = `📊 **現在のキャプチャデータ分析**\n\n`;
      
      analysis += `**基本情報:**\n`;
      analysis += `• 総パケット数: ${statistics.total_packets}\n`;
      analysis += `• キャプチャ時間: ${statistics.time_analysis.duration_seconds.toFixed(1)}秒\n`;
      analysis += `• パケット/秒: ${statistics.time_analysis.packets_per_second.toFixed(1)}\n\n`;

      if (statistics.protocol_distribution) {
        analysis += `**プロトコル分布:**\n`;
        Object.entries(statistics.protocol_distribution).forEach(([protocol, count]) => {
          const percentage = ((count / statistics.total_packets) * 100).toFixed(1);
          analysis += `• ${protocol}: ${count}個 (${percentage}%)\n`;
        });
        analysis += '\n';
      }

      if (statistics.anomaly_detection.warnings.length > 0) {
        analysis += `⚠️ **警告:**\n`;
        statistics.anomaly_detection.warnings.forEach(w => {
          analysis += `${w.message}\n`;
        });
        analysis += '\n';
      }

      if (statistics.suspicious_ips.length > 0) {
        analysis += `🔍 **不審なIP検出:** ${statistics.suspicious_ips.length}件\n`;
        const highRisk = statistics.suspicious_ips.filter(ip => ip.severity === 'high');
        if (highRisk.length > 0) {
          analysis += `⚠️ 高リスクIP: ${highRisk.length}件 - 対処を推奨します\n`;
        }
      }

      analysis += `\n詳細は「📈 統計解析」タブで確認できます！`;
      return analysis;
    }

    // デフォルト応答
    return `ご質問ありがとうございます。

以下のトピックについてお答えできます：

**基礎知識:**
• パケットキャプチャとは？
• TCPとUDPの違い
• プロトコルの種類
• ポート番号について

**セキュリティ:**
• 不審なポート
• ポートスキャン
• SYNフラッド攻撃
• HTTPSの安全性

**使い方:**
• パケット解析の方法
• トラブルシューティング
• エクスポート機能

具体的な質問をしていただくか、上のクイックボタンから選択してください！`;
  };

  const handleQuickQuestion = (question) => {
    setInput(question);
  };

  return (
    <div className="card" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column' }}>
      <h2>💬 パケットキャプチャ相談チャットボット</h2>
      
      <div style={{ 
        marginBottom: '15px', 
        padding: '10px', 
        backgroundColor: '#e3f2fd', 
        borderRadius: '8px',
        fontSize: '14px'
      }}>
        <strong>💡 ヒント:</strong> ネットワークやパケットキャプチャに関する質問にお答えします。
        下のクイックボタンまたは自由に質問を入力してください。
      </div>

      {/* クイックボタン */}
      <div style={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        gap: '8px', 
        marginBottom: '15px',
        padding: '10px',
        backgroundColor: '#f5f5f5',
        borderRadius: '8px'
      }}>
        <div style={{ width: '100%', marginBottom: '5px', fontSize: '13px', fontWeight: 'bold' }}>
          よくある質問:
        </div>
        {quickQuestions.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleQuickQuestion(q)}
            style={{
              padding: '6px 12px',
              fontSize: '12px',
              backgroundColor: 'white',
              border: '1px solid #667eea',
              borderRadius: '15px',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => {
              e.target.style.backgroundColor = '#667eea';
              e.target.style.color = 'white';
            }}
            onMouseLeave={(e) => {
              e.target.style.backgroundColor = 'white';
              e.target.style.color = 'black';
            }}
          >
            {q}
          </button>
        ))}
      </div>

      {/* メッセージエリア */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '15px',
        backgroundColor: '#fafafa',
        borderRadius: '8px',
        marginBottom: '15px',
        border: '1px solid #e0e0e0'
      }}>
        {messages.map((msg, idx) => (
          <div
            key={idx}
            style={{
              display: 'flex',
              justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
              marginBottom: '15px'
            }}
          >
            <div
              style={{
                maxWidth: '75%',
                padding: '12px 16px',
                borderRadius: '12px',
                backgroundColor: msg.role === 'user' ? '#667eea' : 'white',
                color: msg.role === 'user' ? 'white' : 'black',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}
            >
              {msg.role === 'assistant' && (
                <div style={{ marginBottom: '8px', fontSize: '20px' }}>🤖</div>
              )}
              {msg.content}
            </div>
          </div>
        ))}
        
        {loading && (
          <div style={{ display: 'flex', justifyContent: 'flex-start', marginBottom: '15px' }}>
            <div style={{
              padding: '12px 16px',
              borderRadius: '12px',
              backgroundColor: 'white',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
            }}>
              <div style={{ fontSize: '20px', marginBottom: '8px' }}>🤖</div>
              <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                <span>考え中</span>
                <span className="loading-dots">...</span>
              </div>
            </div>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* 入力エリア */}
      <div style={{ display: 'flex', gap: '10px' }}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSend()}
          placeholder="質問を入力してください..."
          disabled={loading}
          style={{
            flex: 1,
            padding: '12px 16px',
            fontSize: '14px',
            border: '1px solid #ccc',
            borderRadius: '8px',
            outline: 'none'
          }}
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="button"
          style={{
            padding: '12px 24px',
            fontSize: '14px',
            backgroundColor: loading || !input.trim() ? '#ccc' : '#667eea',
            cursor: loading || !input.trim() ? 'not-allowed' : 'pointer'
          }}
        >
          {loading ? '送信中...' : '📤 送信'}
        </button>
      </div>

      <style>{`
        @keyframes blink {
          0%, 20% { opacity: 0; }
          40% { opacity: 1; }
          100% { opacity: 0; }
        }
        .loading-dots span:nth-child(1) {
          animation: blink 1.4s infinite;
        }
        .loading-dots span:nth-child(2) {
          animation: blink 1.4s infinite 0.2s;
        }
        .loading-dots span:nth-child(3) {
          animation: blink 1.4s infinite 0.4s;
        }
      `}</style>
    </div>
  );
}

export default PacketChatbot;
