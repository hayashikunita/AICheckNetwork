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
      const response = await axios.get('http://localhost:5000/api/capture/statistics');
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
    try {
      const response = await axios.post('http://localhost:5000/api/chatbot', { question });
      return response.data.answer || '回答が取得できませんでした。';
    } catch (err) {
      return 'サーバーとの通信に失敗しました。バックエンドが起動しているか確認してください。';
    }
  };

  const handleQuickQuestion = (question) => {
    setInput(question);
  };

  return (
    <div className="card" style={{ height: '95vh', display: 'flex', flexDirection: 'column' }}>
      <h2>💬 パケットキャプチャ相談チャットボット</h2>
      
      <div style={{ 
        marginBottom: '10px', 
        padding: '8px', 
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
        marginBottom: '6px',
        padding: '8px',
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
        flex: '1 1 auto',
        overflowY: 'auto',
        padding: '6px',
        backgroundColor: '#fafafa',
        borderRadius: '8px',
        marginBottom: '6px',
        border: '1px solid #e0e0e0'
      }}>
        {messages.map((msg, idx) => (
          <div
            key={idx}
            style={{
              display: 'flex',
              justifyContent: 'flex-start',
              marginBottom: '15px',
              width: '100%'
            }}
          >
            <div
              style={{
                maxWidth: 'calc(100% - 40px)',
                width: 'auto',
                padding: '14px 18px',
                borderRadius: '14px',
                backgroundColor: msg.role === 'user' ? '#667eea' : 'white',
                color: msg.role === 'user' ? 'white' : 'black',
                boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontSize: '15px',
                lineHeight: '1.6',
                marginLeft: msg.role === 'user' ? 'auto' : '8px',
                marginRight: msg.role === 'user' ? '8px' : '0'
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
      <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end' }}>
        <textarea
          rows={3}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
          placeholder="質問を入力してください..."
          disabled={loading}
          style={{
            flex: 1,
            padding: '14px 16px',
            fontSize: '15px',
            border: '1px solid #ccc',
            borderRadius: '8px',
            outline: 'none',
            minHeight: '80px',
            resize: 'vertical'
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
          , alignSelf: 'flex-end'
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
