from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import socket
import platform
import psutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
import threading
import json
import os
import tempfile

app = FastAPI(title="Network Monitor API", version="1.0.0")

# CORS設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# パケットキャプチャ用のグローバル変数
capture_packets = []
capture_raw_packets = []
is_capturing = False
capture_thread = None
capture_session_id = None
stop_capture_flag = False

# エクスポート用ディレクトリ
EXPORT_DIR = tempfile.gettempdir()

# Pydanticモデル
class CaptureRequest(BaseModel):
    interface: Optional[str] = None
    count: int = 100

def get_network_info():
    """ネットワーク情報を取得"""
    info = {
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'interfaces': []
    }
    
    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addrs in net_if_addrs.items():
            interface_info = {
                'name': interface_name,
                'ipv4': [],
                'ipv6': [],
                'mac': []
            }
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interface_info['ipv4'].append({
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                elif addr.family == socket.AF_INET6:
                    interface_info['ipv6'].append({
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                elif addr.family == psutil.AF_LINK:
                    interface_info['mac'].append(addr.address)
            
            if interface_name in net_if_stats:
                stats = net_if_stats[interface_name]
                interface_info['is_up'] = stats.isup
                interface_info['speed'] = stats.speed
            
            info['interfaces'].append(interface_info)
            
    except Exception as e:
        info['error'] = str(e)
    
    return info

def get_wifi_info():
    """WiFi情報を取得（Windows専用）"""
    wifi_info = {
        'connected': [],
        'available': []
    }
    
    try:
        import subprocess
        import locale
        encoding = locale.getpreferredencoding()
        
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                encoding=encoding,
                errors='ignore'
            )
            
            if 'アクセス許可' in result.stdout or '権限の昇格' in result.stdout or 'permission' in result.stdout.lower():
                wifi_info['permission_error'] = True
                wifi_info['message'] = 'WiFi情報の取得には管理者権限と位置情報のアクセス許可が必要です。'
            elif result.returncode == 0 and result.stdout:
                lines = result.stdout.split('\n')
                current_network = {}
                
                for line in lines:
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            
                            if key in ['Name', '名前', 'name']:
                                if current_network:
                                    wifi_info['connected'].append(current_network)
                                current_network = {'interface_name': value}
                            elif key == 'SSID' and current_network:
                                current_network['ssid'] = value
                            elif key in ['Signal', 'シグナル', 'signal'] and current_network:
                                current_network['signal'] = value
                            elif key in ['State', '状態', 'state'] and current_network:
                                current_network['state'] = value
                            elif key in ['Channel', 'チャネル', 'channel'] and current_network:
                                current_network['channel'] = value
                            elif key in ['Radio type', '無線の種類', 'radio type'] and current_network:
                                current_network['radio_type'] = value
                
                if current_network and len(current_network) > 1:
                    wifi_info['connected'].append(current_network)
        except Exception as e:
            wifi_info['interface_error'] = str(e)
        
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                encoding=encoding,
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout:
                profiles = []
                for line in result.stdout.split('\n'):
                    if 'プロファイル' in line or 'All User Profile' in line or 'Profile' in line:
                        if ':' in line:
                            profile_name = line.split(':', 1)[1].strip()
                            if profile_name:
                                profiles.append(profile_name)
                
                for profile in profiles[:10]:
                    wifi_info['available'].append({
                        'ssid': profile,
                        'saved': True
                    })
        except Exception as e:
            wifi_info['profile_error'] = str(e)
        
        try:
            net_if_stats = psutil.net_if_stats()
            wireless_interfaces = []
            
            for iface_name, stats in net_if_stats.items():
                if any(keyword in iface_name.lower() for keyword in ['wi-fi', 'wifi', 'wlan', 'wireless', '802.11']):
                    if stats.isup:
                        wireless_interfaces.append({
                            'interface_name': iface_name,
                            'is_up': stats.isup,
                            'speed': f"{stats.speed} Mbps" if stats.speed > 0 else "Unknown"
                        })
            
            if wireless_interfaces and not wifi_info['connected']:
                wifi_info['connected'] = wireless_interfaces
                wifi_info['note'] = 'WiFi接続情報は検出されましたが、詳細情報の取得には管理者権限が必要です。'
        except Exception as e:
            wifi_info['psutil_error'] = str(e)
        
        return wifi_info
    
    except Exception as e:
        return {
            'error': str(e), 
            'message': 'WiFi情報の取得に失敗しました。',
            'connected': [],
            'available': []
        }

def get_network_stats():
    """ネットワーク統計情報を取得"""
    stats = psutil.net_io_counters()
    return {
        'bytes_sent': stats.bytes_sent,
        'bytes_recv': stats.bytes_recv,
        'packets_sent': stats.packets_sent,
        'packets_recv': stats.packets_recv,
        'errin': stats.errin,
        'errout': stats.errout,
        'dropin': stats.dropin,
        'dropout': stats.dropout
    }

def packet_callback(packet):
    """パケットキャプチャのコールバック関数"""
    global capture_packets, capture_raw_packets, stop_capture_flag
    
    if stop_capture_flag:
        return True
    
    try:
        capture_raw_packets.append(packet)
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'summary': packet.summary()
        }
        
        if IP in packet:
            packet_info['ip'] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': packet[IP].proto,
                'ttl': packet[IP].ttl,
                'version': packet[IP].version
            }
        
        if TCP in packet:
            packet_info['tcp'] = {
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'flags': str(packet[TCP].flags),
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'window': packet[TCP].window
            }
            packet_info['type'] = 'TCP'
            
            if hasattr(packet[TCP], 'payload'):
                payload = bytes(packet[TCP].payload)
                packet_info['payload_length'] = len(payload)
                if len(payload) > 0 and packet[TCP].dport in [80, 8080]:
                    try:
                        payload_preview = payload[:200].decode('utf-8', errors='ignore')
                        if payload_preview.startswith('GET') or payload_preview.startswith('POST') or payload_preview.startswith('HTTP'):
                            packet_info['http_data'] = payload_preview.split('\r\n')[0]
                    except:
                        pass
                        
        elif UDP in packet:
            packet_info['udp'] = {
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport,
                'length': packet[UDP].len
            }
            packet_info['type'] = 'UDP'
            
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                try:
                    from scapy.all import DNS
                    if DNS in packet:
                        dns = packet[DNS]
                        if dns.qd:
                            packet_info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore')
                        if dns.an:
                            packet_info['dns_answer'] = str(dns.an.rdata) if hasattr(dns.an, 'rdata') else 'Response'
                except:
                    pass
                    
        elif ICMP in packet:
            packet_info['icmp'] = {
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            }
            packet_info['type'] = 'ICMP'
            
        elif ARP in packet:
            packet_info['arp'] = {
                'psrc': packet[ARP].psrc,
                'pdst': packet[ARP].pdst,
                'hwsrc': packet[ARP].hwsrc,
                'hwdst': packet[ARP].hwdst,
                'op': packet[ARP].op
            }
            packet_info['type'] = 'ARP'
        else:
            packet_info['type'] = 'Other'
        
        packet_info['explanation'] = get_packet_explanation(packet_info)
        packet_info['importance'] = determine_packet_importance(packet_info)
        
        capture_packets.append(packet_info)
        
        if len(capture_packets) > 1000:
            capture_packets.pop(0)
        
        if len(capture_packets) >= 1000:
            return True
            
    except Exception as e:
        print(f"パケット処理エラー: {e}")
    
    return False

def determine_packet_importance(packet_info):
    """パケットの重要度を判定"""
    packet_type = packet_info.get('type')
    
    if packet_type == 'TCP':
        tcp = packet_info.get('tcp', {})
        dport = tcp.get('dport', 0)
        if dport in [22, 443, 80, 3389, 21]:
            return 'high'
        if 'R' in tcp.get('flags', '') or 'F' in tcp.get('flags', ''):
            return 'medium'
    
    if packet_type == 'UDP':
        udp = packet_info.get('udp', {})
        dport = udp.get('dport', 0)
        if dport in [53, 67, 68]:
            return 'medium'
    
    if packet_type == 'ICMP':
        return 'medium'
    
    if packet_type == 'ARP':
        return 'low'
    
    return 'normal'

def get_packet_explanation(packet_info):
    """パケットの解説を生成"""
    explanation = []
    
    packet_type = packet_info.get('type', 'Unknown')
    
    if packet_type == 'TCP':
        explanation.append("📌 TCP (Transmission Control Protocol): 信頼性の高いデータ転送を行うプロトコル")
        tcp_info = packet_info.get('tcp', {})
        sport = tcp_info.get('sport')
        dport = tcp_info.get('dport')
        flags = tcp_info.get('flags', '')
        
        if dport == 80:
            explanation.append("🌐 ポート80: HTTP通信（暗号化されていないWeb通信）")
            explanation.append("⚠️ セキュリティ: データが暗号化されていないため、盗聴のリスクがあります")
        elif dport == 443:
            explanation.append("🔒 ポート443: HTTPS通信（暗号化されたWeb通信）")
            explanation.append("✅ セキュリティ: SSL/TLSで暗号化されており安全です")
        elif dport == 22:
            explanation.append("🔐 ポート22: SSH通信（リモートログイン）")
            explanation.append("✅ セキュリティ: サーバーへの安全な接続です")
        elif dport == 21:
            explanation.append("📁 ポート21: FTP通信（ファイル転送）")
            explanation.append("⚠️ セキュリティ: パスワードが平文で送信されるため推奨されません")
        elif dport == 3389:
            explanation.append("🖥️ ポート3389: RDP通信（リモートデスクトップ）")
            explanation.append("💡 用途: Windows PCへのリモート接続です")
        elif dport == 25:
            explanation.append("📧 ポート25: SMTP通信（メール送信）")
        elif dport == 110:
            explanation.append("📬 ポート110: POP3通信（メール受信）")
        elif dport == 143:
            explanation.append("📮 ポート143: IMAP通信（メール受信）")
        elif dport == 993:
            explanation.append("🔒 ポート993: IMAPS通信（暗号化されたメール受信）")
        elif dport == 3306:
            explanation.append("🗄️ ポート3306: MySQL通信（データベース）")
        elif dport == 5432:
            explanation.append("🗄️ ポート5432: PostgreSQL通信（データベース）")
        elif dport == 8080:
            explanation.append("🌐 ポート8080: HTTP代替ポート（開発用Webサーバーなど）")
        
        if 'S' in flags and 'A' not in flags:
            explanation.append("🔄 SYNフラグ: 接続開始リクエスト（3ウェイハンドシェイクの開始）")
        elif 'S' in flags and 'A' in flags:
            explanation.append("🤝 SYN-ACKフラグ: 接続受け入れ応答（3ウェイハンドシェイクの2段階目）")
        elif 'F' in flags:
            explanation.append("👋 FINフラグ: 接続終了リクエスト（正常な切断）")
        elif 'R' in flags:
            explanation.append("⛔ RSTフラグ: 接続リセット（異常な切断または拒否）")
        elif 'P' in flags:
            explanation.append("📤 PSHフラグ: データの即座送信（アプリケーションへすぐに渡す）")
        
    elif packet_type == 'UDP':
        explanation.append("📌 UDP (User Datagram Protocol): 高速だが信頼性は低いプロトコル")
        explanation.append("💡 特徴: 接続確立なし、データ到達保証なし、ストリーミングやゲームに最適")
        udp_info = packet_info.get('udp', {})
        sport = udp_info.get('sport')
        dport = udp_info.get('dport')
        
        if dport == 53 or sport == 53:
            explanation.append("🔍 ポート53: DNS通信（ドメイン名の解決）")
            explanation.append("💡 役割: www.example.com → IPアドレスへの変換")
        elif dport == 67 or dport == 68:
            explanation.append(f"📡 ポート{dport}: DHCP通信（IPアドレスの自動割り当て）")
            explanation.append("💡 役割: ネットワーク参加時に自動でIPアドレスを取得")
        elif dport == 123:
            explanation.append("⏰ ポート123: NTP通信（時刻同期）")
            explanation.append("💡 役割: コンピュータの時計を正確に保つ")
        elif dport == 137 or dport == 138:
            explanation.append(f"🏷️ ポート{dport}: NetBIOSネーム通信")
            explanation.append("💡 役割: Windowsネットワークでのコンピュータ名解決")
        elif dport == 161 or dport == 162:
            explanation.append(f"📊 ポート{dport}: SNMP通信（ネットワーク機器の監視）")
        elif dport >= 5060 and dport <= 5061:
            explanation.append("☎️ ポート5060-5061: SIP通信（VoIP電話）")
        elif dport >= 27000 and dport <= 27050:
            explanation.append("🎮 ポート27000番台: オンラインゲーム通信の可能性")
        
    elif packet_type == 'ICMP':
        explanation.append("📌 ICMP: ネットワーク診断やエラー通知に使用されるプロトコル")
        icmp_info = packet_info.get('icmp', {})
        icmp_type = icmp_info.get('type')
        
        if icmp_type == 8:
            explanation.append("🔔 Pingリクエスト（Echo Request）")
            explanation.append("💡 用途: ネットワーク接続の確認、応答速度の測定")
        elif icmp_type == 0:
            explanation.append("✅ Ping応答（Echo Reply）")
            explanation.append("💡 意味: 相手が正常に応答、ネットワークは正常")
        elif icmp_type == 3:
            explanation.append("⚠️ 到達不可能（Destination Unreachable）")
            explanation.append("💡 原因: ファイアウォール、経路なし、サービス停止など")
        elif icmp_type == 11:
            explanation.append("⏱️ 時間超過（Time Exceeded）")
            explanation.append("💡 原因: パケットが経路上で時間切れ（TTL=0）")
        
    elif packet_type == 'ARP':
        explanation.append("📌 ARP (Address Resolution Protocol): IPアドレスからMACアドレスを解決")
        explanation.append("💡 役割: ローカルネットワーク内でのデバイス通信に必要")
        explanation.append("🔄 動作: 「このIPアドレスのMACアドレスを教えて」と問い合わせ")
        arp_info = packet_info.get('arp', {})
        if arp_info.get('op') == 1:
            explanation.append("❓ ARPリクエスト: 誰かのMACアドレスを探しています")
        elif arp_info.get('op') == 2:
            explanation.append("✅ ARP応答: MACアドレスを返答しています")
    
    if packet_info.get('ip'):
        ip_info = packet_info['ip']
        src = ip_info.get('src', '')
        dst = ip_info.get('dst', '')
        
        if src.startswith('192.168.') or src.startswith('10.') or src.startswith('172.'):
            explanation.append(f"🏠 送信元 {src}: ローカルネットワーク内のデバイス")
        elif src.startswith('127.'):
            explanation.append(f"💻 送信元 {src}: 自分自身（ループバック）")
        
        if dst.startswith('192.168.') or dst.startswith('10.') or dst.startswith('172.'):
            explanation.append(f"🏠 宛先 {dst}: ローカルネットワーク内のデバイス")
        elif dst.startswith('127.'):
            explanation.append(f"💻 宛先 {dst}: 自分自身（ループバック）")
        elif dst.startswith('224.') or dst.startswith('239.'):
            explanation.append(f"📢 宛先 {dst}: マルチキャスト（複数デバイスへの同時配信）")
        elif dst == '255.255.255.255':
            explanation.append("📣 宛先 255.255.255.255: ブロードキャスト（全デバイスへの配信）")
    
    return ' | '.join(explanation) if explanation else 'その他の通信'

def capture_packets_thread(interface, packet_count):
    """パケットキャプチャを別スレッドで実行"""
    global is_capturing, stop_capture_flag
    stop_capture_flag = False
    
    print(f"パケットキャプチャ開始: {packet_count}個のパケットを収集")
    
    def should_stop(packet):
        """停止判定関数（デバッグ出力なし）"""
        return stop_capture_flag
    
    try:
        packets_captured = sniff(
            iface=interface, 
            prn=packet_callback, 
            count=packet_count, 
            store=False,
            timeout=60,
            stop_filter=should_stop
        )
        print(f"パケットキャプチャ終了: {len(capture_packets)}個のパケットを収集しました")
    except KeyboardInterrupt:
        print("パケットキャプチャが中断されました")
    except Exception as e:
        print(f"キャプチャエラー: {e}")
    finally:
        is_capturing = False
        stop_capture_flag = False
        print("キャプチャスレッドが正常に終了しました")

# APIエンドポイント
@app.get("/api/network-info")
async def network_info():
    """ネットワーク情報のエンドポイント"""
    return get_network_info()

@app.get("/api/wifi-info")
async def wifi_info():
    """WiFi情報のエンドポイント"""
    return get_wifi_info()

@app.get("/api/network-stats")
async def network_stats():
    """ネットワーク統計のエンドポイント"""
    return get_network_stats()

@app.post("/api/capture/start")
async def start_capture(request: CaptureRequest):
    """パケットキャプチャを開始"""
    global is_capturing, capture_thread, capture_packets, capture_raw_packets, capture_session_id, stop_capture_flag
    
    if is_capturing:
        raise HTTPException(status_code=400, detail='キャプチャは既に実行中です')
    
    capture_packets = []
    capture_raw_packets = []
    capture_session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    stop_capture_flag = False
    is_capturing = True
    
    capture_thread = threading.Thread(
        target=capture_packets_thread,
        args=(request.interface, request.count)
    )
    capture_thread.start()
    
    return {
        'message': 'キャプチャを開始しました', 
        'status': 'started',
        'session_id': capture_session_id
    }

@app.post("/api/capture/stop")
async def stop_capture():
    """パケットキャプチャを停止"""
    global is_capturing, stop_capture_flag, capture_thread
    
    if not is_capturing:
        return {'message': 'キャプチャは実行されていません', 'status': 'not_running'}
    
    print("停止リクエストを受信しました")
    
    stop_capture_flag = True
    is_capturing = False
    
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2.0)
    
    print(f"キャプチャを停止しました。収集パケット数: {len(capture_packets)}")
    
    return {
        'message': 'キャプチャを停止しました', 
        'status': 'stopped',
        'packet_count': len(capture_packets)
    }

@app.get("/api/capture/packets")
async def get_packets():
    """キャプチャしたパケットを取得"""
    return {
        'packets': capture_packets,
        'count': len(capture_packets),
        'is_capturing': is_capturing
    }

@app.get("/api/capture/status")
async def capture_status():
    """キャプチャの状態を取得"""
    return {
        'is_capturing': is_capturing,
        'packet_count': len(capture_packets),
        'session_id': capture_session_id
    }

@app.get("/api/capture/statistics")
async def get_capture_statistics():
    """キャプチャしたパケットの統計情報を取得"""
    global capture_packets
    
    if not capture_packets:
        return {
            'total_packets': 0,
            'protocol_distribution': {},
            'port_distribution': {},
            'ip_statistics': {},
            'packet_size_stats': {},
            'time_analysis': {},
            'top_talkers': [],
            'security_analysis': {},
            'anomaly_detection': {},
            'suspicious_ips': []
        }
    
    # プロトコル分布
    protocol_counts = {}
    for packet in capture_packets:
        ptype = packet.get('type', 'Unknown')
        protocol_counts[ptype] = protocol_counts.get(ptype, 0) + 1
    
    # ポート番号の使用頻度（上位20個）
    port_counts = {}
    for packet in capture_packets:
        if packet.get('tcp'):
            sport = packet['tcp'].get('sport')
            dport = packet['tcp'].get('dport')
            if sport:
                port_counts[sport] = port_counts.get(sport, 0) + 1
            if dport:
                port_counts[dport] = port_counts.get(dport, 0) + 1
        elif packet.get('udp'):
            sport = packet['udp'].get('sport')
            dport = packet['udp'].get('dport')
            if sport:
                port_counts[sport] = port_counts.get(sport, 0) + 1
            if dport:
                port_counts[dport] = port_counts.get(dport, 0) + 1
    
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    
    # IPアドレス統計
    src_ips = {}
    dst_ips = {}
    for packet in capture_packets:
        if packet.get('ip'):
            src = packet['ip'].get('src')
            dst = packet['ip'].get('dst')
            if src:
                src_ips[src] = src_ips.get(src, 0) + 1
            if dst:
                dst_ips[dst] = dst_ips.get(dst, 0) + 1
    
    # パケットサイズ統計
    packet_sizes = [p.get('length', 0) for p in capture_packets]
    size_stats = {
        'min': min(packet_sizes) if packet_sizes else 0,
        'max': max(packet_sizes) if packet_sizes else 0,
        'average': sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
        'total_bytes': sum(packet_sizes)
    }
    
    # サイズ分布（範囲別）
    size_ranges = {
        '0-100': 0,
        '101-500': 0,
        '501-1000': 0,
        '1001-1500': 0,
        '1501+': 0
    }
    for size in packet_sizes:
        if size <= 100:
            size_ranges['0-100'] += 1
        elif size <= 500:
            size_ranges['101-500'] += 1
        elif size <= 1000:
            size_ranges['501-1000'] += 1
        elif size <= 1500:
            size_ranges['1001-1500'] += 1
        else:
            size_ranges['1501+'] += 1
    
    # 時間分析
    timestamps = [p.get('timestamp') for p in capture_packets if p.get('timestamp')]
    if timestamps and len(timestamps) > 1:
        from datetime import datetime as dt
        start_time = dt.fromisoformat(timestamps[0])
        end_time = dt.fromisoformat(timestamps[-1])
        duration = (end_time - start_time).total_seconds()
        packets_per_second = len(capture_packets) / duration if duration > 0 else 0
    else:
        duration = 0
        packets_per_second = 0
    
    # トップトーカー（通信量が多いIPアドレス）
    ip_bytes = {}
    for packet in capture_packets:
        if packet.get('ip'):
            src = packet['ip'].get('src')
            size = packet.get('length', 0)
            if src:
                ip_bytes[src] = ip_bytes.get(src, 0) + size
    
    top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    top_talkers_list = [{'ip': ip, 'bytes': bytes, 'packets': src_ips.get(ip, 0)} 
                        for ip, bytes in top_talkers]
    
    # セキュリティ分析
    security_info = {
        'encrypted_packets': sum(1 for p in capture_packets 
                                if p.get('tcp', {}).get('dport') in [443, 22, 993, 995]),
        'unencrypted_packets': sum(1 for p in capture_packets 
                                   if p.get('tcp', {}).get('dport') in [80, 21, 23, 110]),
        'high_importance': sum(1 for p in capture_packets if p.get('importance') == 'high'),
        'medium_importance': sum(1 for p in capture_packets if p.get('importance') == 'medium'),
        'low_importance': sum(1 for p in capture_packets if p.get('importance') == 'low')
    }
    
    # TCPフラグ統計
    tcp_flags = {}
    for packet in capture_packets:
        if packet.get('tcp'):
            flags = packet['tcp'].get('flags', '')
            tcp_flags[flags] = tcp_flags.get(flags, 0) + 1
    
    # 異常検知と不審なIP分析
    anomaly_detection = detect_anomalies(capture_packets, src_ips, dst_ips, port_counts)
    suspicious_ips = analyze_suspicious_ips(capture_packets, src_ips, dst_ips)
    
    return {
        'total_packets': len(capture_packets),
        'protocol_distribution': protocol_counts,
        'port_distribution': {
            'top_ports': [{'port': port, 'count': count} for port, count in top_ports]
        },
        'ip_statistics': {
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'top_src_ips': sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_dst_ips': sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        },
        'packet_size_stats': {
            **size_stats,
            'size_distribution': size_ranges
        },
        'time_analysis': {
            'duration_seconds': duration,
            'packets_per_second': packets_per_second,
            'start_time': timestamps[0] if timestamps else None,
            'end_time': timestamps[-1] if timestamps else None
        },
        'top_talkers': top_talkers_list,
        'security_analysis': security_info,
        'tcp_flags': tcp_flags,
        'anomaly_detection': anomaly_detection,
        'suspicious_ips': suspicious_ips
    }

def detect_anomalies(packets, src_ips, dst_ips, port_counts):
    """異常な通信パターンを検出"""
    anomalies = {
        'port_scanning': [],
        'syn_flood': [],
        'unusual_ports': [],
        'high_traffic_ips': [],
        'failed_connections': [],
        'warnings': []
    }
    
    # ポートスキャン検出（同一送信元から多数の異なるポートへの接続）
    ip_port_map = {}
    for packet in packets:
        if packet.get('ip') and packet.get('tcp'):
            src = packet['ip'].get('src')
            dport = packet['tcp'].get('dport')
            if src and dport:
                if src not in ip_port_map:
                    ip_port_map[src] = set()
                ip_port_map[src].add(dport)
    
    for ip, ports in ip_port_map.items():
        if len(ports) > 20:  # 20以上の異なるポートに接続
            anomalies['port_scanning'].append({
                'ip': ip,
                'ports_accessed': len(ports),
                'severity': 'high',
                'description': f'{ip}が{len(ports)}個の異なるポートに接続しています（ポートスキャンの可能性）'
            })
    
    # SYNフラッド検出（大量のSYNパケット）
    syn_counts = {}
    for packet in packets:
        if packet.get('tcp') and packet['tcp'].get('flags') == 'S':
            src = packet.get('ip', {}).get('src')
            if src:
                syn_counts[src] = syn_counts.get(src, 0) + 1
    
    for ip, count in syn_counts.items():
        if count > 50:  # 50回以上のSYNパケット
            anomalies['syn_flood'].append({
                'ip': ip,
                'syn_count': count,
                'severity': 'high',
                'description': f'{ip}から{count}個のSYNパケット（SYNフラッド攻撃の可能性）'
            })
    
    # 異常なポート番号の使用検出
    suspicious_ports = [
        1337, 31337,  # ハッカーツールでよく使われるポート
        4444, 5555,   # バックドアでよく使われるポート
        6667, 6668, 6669,  # IRC（ボットネット通信）
        12345, 54321,  # トロイの木馬
        1234, 3127, 3128, 8080  # プロキシ/トンネル
    ]
    
    for port, count in port_counts.items():
        if port in suspicious_ports:
            anomalies['unusual_ports'].append({
                'port': port,
                'count': count,
                'severity': 'medium',
                'description': f'ポート{port}の使用を検出（不審なポート番号）'
            })
    
    # 異常な通信量のIP検出
    avg_packets = sum(src_ips.values()) / len(src_ips) if src_ips else 0
    for ip, count in src_ips.items():
        if count > avg_packets * 10:  # 平均の10倍以上
            anomalies['high_traffic_ips'].append({
                'ip': ip,
                'packet_count': count,
                'severity': 'medium',
                'description': f'{ip}が異常に多い通信（平均の{(count/avg_packets):.1f}倍）'
            })
    
    # RSTフラグ（接続失敗）の多いIP
    rst_counts = {}
    for packet in packets:
        if packet.get('tcp') and 'R' in packet['tcp'].get('flags', ''):
            src = packet.get('ip', {}).get('src')
            if src:
                rst_counts[src] = rst_counts.get(src, 0) + 1
    
    for ip, count in rst_counts.items():
        if count > 10:
            anomalies['failed_connections'].append({
                'ip': ip,
                'rst_count': count,
                'severity': 'low',
                'description': f'{ip}との接続が{count}回失敗（RSTパケット）'
            })
    
    # 総合的な警告生成
    total_anomalies = (
        len(anomalies['port_scanning']) +
        len(anomalies['syn_flood']) +
        len(anomalies['unusual_ports']) +
        len(anomalies['high_traffic_ips'])
    )
    
    if total_anomalies > 0:
        anomalies['warnings'].append({
            'level': 'warning',
            'message': f'{total_anomalies}件の異常な通信パターンを検出しました',
            'details': '詳細を確認して、必要に応じてファイアウォールの設定を見直してください'
        })
    
    return anomalies

def analyze_suspicious_ips(packets, src_ips, dst_ips):
    """不審なIPアドレスを分析"""
    suspicious_list = []
    
    # 既知の不審なIP範囲（例）
    suspicious_ranges = {
        '0.0.0.0/8': 'ブロードキャスト/予約済みアドレス',
        '169.254.0.0/16': 'APIPAアドレス（自動割り当て失敗）',
        '224.0.0.0/4': 'マルチキャストアドレス',
        '240.0.0.0/4': '予約済み（実験用）'
    }
    
    # 各IPアドレスの分析
    all_ips = set()
    for packet in packets:
        if packet.get('ip'):
            src = packet['ip'].get('src')
            dst = packet['ip'].get('dst')
            if src:
                all_ips.add(src)
            if dst:
                all_ips.add(dst)
    
    for ip in all_ips:
        suspicion_score = 0
        reasons = []
        
        # プライベートIPアドレスの確認
        is_private = (
            ip.startswith('10.') or
            ip.startswith('172.16.') or ip.startswith('172.17.') or
            ip.startswith('172.18.') or ip.startswith('172.19.') or
            ip.startswith('172.20.') or ip.startswith('172.21.') or
            ip.startswith('172.22.') or ip.startswith('172.23.') or
            ip.startswith('172.24.') or ip.startswith('172.25.') or
            ip.startswith('172.26.') or ip.startswith('172.27.') or
            ip.startswith('172.28.') or ip.startswith('172.29.') or
            ip.startswith('172.30.') or ip.startswith('172.31.') or
            ip.startswith('192.168.') or
            ip.startswith('127.')
        )
        
        # 外部IPで高トラフィック
        if not is_private and src_ips.get(ip, 0) > 50:
            suspicion_score += 3
            reasons.append('外部IPからの高トラフィック')
        
        # 特殊なIP範囲
        if ip.startswith('0.'):
            suspicion_score += 5
            reasons.append('無効なIPアドレス範囲')
        elif ip.startswith('169.254.'):
            suspicion_score += 2
            reasons.append('APIPA自動割り当てアドレス')
        elif ip.startswith('224.') or ip.startswith('239.'):
            suspicion_score += 1
            reasons.append('マルチキャストアドレス')
        
        # 異常なポートへのアクセス
        ip_ports = set()
        for packet in packets:
            if packet.get('ip', {}).get('src') == ip and packet.get('tcp'):
                dport = packet['tcp'].get('dport')
                if dport and dport in [1337, 31337, 4444, 5555, 6667]:
                    suspicion_score += 4
                    reasons.append(f'不審なポート{dport}への接続')
                    break
        
        # 大量の接続失敗
        rst_count = sum(1 for p in packets 
                       if p.get('ip', {}).get('src') == ip 
                       and p.get('tcp', {}).get('flags') and 'R' in p['tcp']['flags'])
        if rst_count > 15:
            suspicion_score += 2
            reasons.append(f'{rst_count}回の接続失敗')
        
        # 疑わしいIPをリストに追加
        if suspicion_score >= 3:
            level = 'high' if suspicion_score >= 7 else 'medium' if suspicion_score >= 5 else 'low'
            suspicious_list.append({
                'ip': ip,
                'suspicion_score': suspicion_score,
                'severity': level,
                'reasons': reasons,
                'packet_count': src_ips.get(ip, 0) + dst_ips.get(ip, 0),
                'is_private': is_private,
                'recommendation': get_recommendation(suspicion_score, reasons)
            })
    
    # スコアでソート
    suspicious_list.sort(key=lambda x: x['suspicion_score'], reverse=True)
    
    return suspicious_list[:20]  # TOP20

def get_recommendation(score, reasons):
    """スコアと理由に基づいて推奨アクションを返す"""
    if score >= 7:
        return '⚠️ 高リスク: このIPアドレスをファイアウォールでブロックすることを推奨します'
    elif score >= 5:
        return '⚡ 中リスク: 継続的に監視し、不審な動きがあれば対処してください'
    elif any('ポート' in r for r in reasons):
        return '🔍 注意: 不審なポート使用が検出されました。通信内容を確認してください'
    else:
        return '👀 監視推奨: 異常な通信パターンが見られます'

@app.get("/api/capture/statistics/export")
async def export_statistics():
    """統計データをJSONファイルとしてエクスポート"""
    try:
        # 統計データを取得
        stats = await get_capture_statistics()
        
        # タイムスタンプを追加
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'statistics': stats
        }
        
        # ファイル名を生成
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'packet_statistics_{timestamp}.json'
        filepath = os.path.join(EXPORT_DIR, filename)
        
        # JSONファイルとして保存
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        # ファイルをダウンロードとして返す
        def cleanup():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                print(f"Cleanup error: {e}")
        
        return FileResponse(
            path=filepath,
            media_type='application/json',
            filename=filename,
            background=BackgroundTasks().add_task(cleanup)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"統計データのエクスポートに失敗しました: {str(e)}")

@app.get("/api/capture/export/json")
async def export_json(background_tasks: BackgroundTasks):
    """パケット情報をJSONファイルとしてエクスポート"""
    global capture_packets, capture_session_id
    
    print(f"JSON Export リクエスト受信 - パケット数: {len(capture_packets)}")
    
    if not capture_packets:
        print("エラー: エクスポートするパケットがありません")
        raise HTTPException(status_code=400, detail='エクスポートするパケットがありません')
    
    try:
        temp_dir = tempfile.gettempdir()
        session_id = capture_session_id if capture_session_id else datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'packet_capture_{session_id}.json'
        filepath = os.path.join(temp_dir, filename)
        
        print(f'JSONファイル作成中: {filepath}')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                'session_id': session_id,
                'capture_time': datetime.now().isoformat(),
                'packet_count': len(capture_packets),
                'packets': capture_packets
            }, f, ensure_ascii=False, indent=2)
        
        print(f'JSONファイル作成完了: {filename} (サイズ: {os.path.getsize(filepath)} bytes)')
        
        # ファイル送信後に削除（60秒後）
        def cleanup():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f'クリーンアップ完了: {filename}')
            except:
                pass
        
        background_tasks.add_task(cleanup)
        
        return FileResponse(
            path=filepath,
            media_type='application/json',
            filename=filename
        )
    except Exception as e:
        print(f'JSON Export エラー: {str(e)}')
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f'エクスポートに失敗しました: {str(e)}')

@app.get("/api/capture/export/pcap")
async def export_pcap(background_tasks: BackgroundTasks):
    """パケットをpcapファイルとしてエクスポート"""
    global capture_raw_packets, capture_session_id
    
    print(f"PCAP Export リクエスト受信 - パケット数: {len(capture_raw_packets)}")
    
    if not capture_raw_packets:
        print("エラー: エクスポートするパケットがありません")
        raise HTTPException(status_code=400, detail='エクスポートするパケットがありません')
    
    try:
        temp_dir = tempfile.gettempdir()
        session_id = capture_session_id if capture_session_id else datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'packet_capture_{session_id}.pcap'
        filepath = os.path.join(temp_dir, filename)
        
        print(f'PCAPファイル作成中: {filepath}')
        
        wrpcap(filepath, capture_raw_packets)
        
        print(f'PCAPファイル作成完了: {filename} (サイズ: {os.path.getsize(filepath)} bytes)')
        
        # ファイル送信後に削除
        def cleanup():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f'クリーンアップ完了: {filename}')
            except:
                pass
        
        background_tasks.add_task(cleanup)
        
        return FileResponse(
            path=filepath,
            media_type='application/vnd.tcpdump.pcap',
            filename=filename
        )
    except Exception as e:
        print(f'PCAP Export エラー: {str(e)}')
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f'エクスポートに失敗しました: {str(e)}')

@app.get("/api/capture/export/csv")
async def export_csv(background_tasks: BackgroundTasks):
    """パケット情報をCSVファイルとしてエクスポート"""
    global capture_packets, capture_session_id
    
    print(f"CSV Export リクエスト受信 - パケット数: {len(capture_packets)}")
    
    if not capture_packets:
        print("エラー: エクスポートするパケットがありません")
        raise HTTPException(status_code=400, detail='エクスポートするパケットがありません')
    
    try:
        import csv
        
        temp_dir = tempfile.gettempdir()
        session_id = capture_session_id if capture_session_id else datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'packet_capture_{session_id}.csv'
        filepath = os.path.join(temp_dir, filename)
        
        print(f'CSVファイル作成中: {filepath}')
        
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            
            writer.writerow([
                'Timestamp', 'Type', 'Length', 'Source IP', 'Destination IP',
                'Source Port', 'Destination Port', 'Protocol Info', 'Summary'
            ])
            
            for packet in capture_packets:
                row = [
                    packet.get('timestamp', ''),
                    packet.get('type', ''),
                    packet.get('length', ''),
                    packet.get('ip', {}).get('src', ''),
                    packet.get('ip', {}).get('dst', ''),
                    '',
                    '',
                    '',
                    packet.get('summary', '')
                ]
                
                if packet.get('tcp'):
                    row[5] = packet['tcp'].get('sport', '')
                    row[6] = packet['tcp'].get('dport', '')
                    row[7] = f"Flags: {packet['tcp'].get('flags', '')}"
                elif packet.get('udp'):
                    row[5] = packet['udp'].get('sport', '')
                    row[6] = packet['udp'].get('dport', '')
                elif packet.get('icmp'):
                    row[7] = f"Type: {packet['icmp'].get('type', '')}, Code: {packet['icmp'].get('code', '')}"
                
                writer.writerow(row)
        
        print(f'CSVファイル作成完了: {filename} (サイズ: {os.path.getsize(filepath)} bytes)')
        
        # ファイル送信後に削除
        def cleanup():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f'クリーンアップ完了: {filename}')
            except:
                pass
        
        background_tasks.add_task(cleanup)
        
        return FileResponse(
            path=filepath,
            media_type='text/csv',
            filename=filename
        )
    except Exception as e:
        print(f'CSV Export エラー: {str(e)}')
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f'エクスポートに失敗しました: {str(e)}')

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)
