import React, { useState, useEffect } from 'react';
import axios from 'axios';
import NetworkInfo from './components/NetworkInfo';
import WiFiInfo from './components/WiFiInfo';
import NetworkStats from './components/NetworkStats';
import PacketCapture from './components/PacketCapture';
import PacketAnalysis from './components/PacketAnalysis';
import PacketChatbot from './components/PacketChatbot';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('network');

  return (
    <div className="App">
      <header className="App-header">
        <h1>🌐 ネットワーク診断ツール</h1>
        <p className="subtitle">PCのネットワーク情報を確認・監視</p>
      </header>

      <nav className="tab-navigation">
        <button
          className={activeTab === 'network' ? 'active' : ''}
          onClick={() => setActiveTab('network')}
        >
          📡 ネットワーク情報
        </button>
        <button
          className={activeTab === 'wifi' ? 'active' : ''}
          onClick={() => setActiveTab('wifi')}
        >
          📶 WiFi情報
        </button>
        <button
          className={activeTab === 'stats' ? 'active' : ''}
          onClick={() => setActiveTab('stats')}
        >
          📊 トラフィック統計
        </button>
        <button
          className={activeTab === 'capture' ? 'active' : ''}
          onClick={() => setActiveTab('capture')}
        >
          🔍 パケットキャプチャ
        </button>
        <button
          className={activeTab === 'analysis' ? 'active' : ''}
          onClick={() => setActiveTab('analysis')}
        >
          📈 統計解析
        </button>
        <button
          className={activeTab === 'chatbot' ? 'active' : ''}
          onClick={() => setActiveTab('chatbot')}
        >
          💬 相談チャット
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'network' && <NetworkInfo />}
        {activeTab === 'wifi' && <WiFiInfo />}
        {activeTab === 'stats' && <NetworkStats />}
        {activeTab === 'capture' && <PacketCapture />}
        {activeTab === 'analysis' && <PacketAnalysis />}
        {activeTab === 'chatbot' && <PacketChatbot />}
      </main>

      <footer className="App-footer">
        <p>© 2025 ネットワーク診断ツール - 初心者にもわかりやすいネットワーク監視</p>
      </footer>
    </div>
  );
}

export default App;
