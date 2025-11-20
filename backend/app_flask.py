from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import socket
import platform
import psutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
import threading
import json
import os
import tempfile

app = Flask(__name__)
CORS(app)

# パケットキャプチャ用のグローバル変数
capture_packets = []
capture_raw_packets = []  # 生のscapyパケットオブジェクトを保存
is_capturing = False
capture_thread = None
capture_session_id = None
stop_capture_flag = False

def get_network_info():
    """ネットワーク情報を取得"""
    info = {
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'interfaces': []
    }
    
    try:
        # psutilを使用してネットワークインターフェース情報を取得
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addrs in net_if_addrs.items():
            interface_info = {
                'name': interface_name,
                'ipv4': [],
                'ipv6': [],
                'mac': []
            }
            
            # 各アドレス情報を処理
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    interface_info['ipv4'].append({
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                elif addr.family == socket.AF_INET6:  # IPv6
                    interface_info['ipv6'].append({
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                elif addr.family == psutil.AF_LINK:  # MAC address
                    interface_info['mac'].append(addr.address)
            
            # インターフェースの状態情報を追加
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
        
        # まず、プロファイル情報から接続中のWiFiを取得
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                encoding=encoding,
                errors='ignore'
            )
            
            # 権限エラーや位置情報エラーをチェック
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
        
        # プロファイルから情報を取得（権限が少なくて済む）
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
                
                # 保存されているプロファイル情報を available に追加
                for profile in profiles[:10]:  # 最大10個まで
                    wifi_info['available'].append({
                        'ssid': profile,
                        'saved': True
                    })
        except Exception as e:
            wifi_info['profile_error'] = str(e)
        
        # psutilで基本的なネットワーク情報を取得
        try:
            net_if_stats = psutil.net_if_stats()
            wireless_interfaces = []
            
            for iface_name, stats in net_if_stats.items():
                # WiFiっぽいインターフェース名を検出
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
    
    # 停止フラグがセットされていたら処理を中断
    if stop_capture_flag:
        return True  # Trueを返すとsniffが停止
    
    try:
        # 生のパケットを保存（pcap出力用）
        capture_raw_packets.append(packet)
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'summary': packet.summary()
        }
        
        # レイヤー情報を追加
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
            
            # ペイロードの長さを取得
            if hasattr(packet[TCP], 'payload'):
                payload = bytes(packet[TCP].payload)
                packet_info['payload_length'] = len(payload)
                # 安全な範囲でペイロードの一部を文字列として取得（HTTPヘッダーなど）
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
            
            # DNSパケットの詳細解析
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                try:
                    from scapy.all import DNS
                    if DNS in packet:
                        dns = packet[DNS]
                        if dns.qd:  # Query
                            packet_info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore')
                        if dns.an:  # Answer
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
        
        # パケット解説を追加
        packet_info['explanation'] = get_packet_explanation(packet_info)
        
        # パケットの重要度を判定
        packet_info['importance'] = determine_packet_importance(packet_info)
        
        capture_packets.append(packet_info)
        
        # 最大1000パケットまで保存
        if len(capture_packets) > 1000:
            capture_packets.pop(0)
        
        # パケット数の上限チェック（停止条件）
        if len(capture_packets) >= 1000:
            return True  # sniffを停止
            
    except Exception as e:
        print(f"パケット処理エラー: {e}")
    
    return False  # 継続

def determine_packet_importance(packet_info):
    """パケットの重要度を判定"""
    packet_type = packet_info.get('type')
    
    # 高優先度
    if packet_type == 'TCP':
        tcp = packet_info.get('tcp', {})
        dport = tcp.get('dport', 0)
        # セキュリティ関連、HTTP/HTTPS
        if dport in [22, 443, 80, 3389, 21]:
            return 'high'
        # RST or FIN（接続終了）
        if 'R' in tcp.get('flags', '') or 'F' in tcp.get('flags', ''):
            return 'medium'
    
    # 中優先度
    if packet_type == 'UDP':
        udp = packet_info.get('udp', {})
        dport = udp.get('dport', 0)
        # DNS, DHCP
        if dport in [53, 67, 68]:
            return 'medium'
    
    if packet_type == 'ICMP':
        return 'medium'
    
    # 低優先度
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
        
        # ポート番号による詳細解説
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
        
        # TCPフラグの解説
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
    
    # プロトコル共通の追加情報
    if packet_info.get('ip'):
        ip_info = packet_info['ip']
        src = ip_info.get('src', '')
        dst = ip_info.get('dst', '')
        
        # プライベートIPアドレスの判定
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
    
    try:
        # sniffを実行
        packets_captured = sniff(
            iface=interface, 
            prn=packet_callback, 
            count=packet_count, 
            store=False,
            timeout=60,  # 60秒でタイムアウト
            stop_filter=lambda x: stop_capture_flag
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

@app.route('/api/network-info', methods=['GET'])
def network_info():
    """ネットワーク情報のエンドポイント"""
    return jsonify(get_network_info())

@app.route('/api/wifi-info', methods=['GET'])
def wifi_info():
    """WiFi情報のエンドポイント"""
    return jsonify(get_wifi_info())

@app.route('/api/network-stats', methods=['GET'])
def network_stats():
    """ネットワーク統計のエンドポイント"""
    return jsonify(get_network_stats())

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """パケットキャプチャを開始"""
    global is_capturing, capture_thread, capture_packets, capture_raw_packets, capture_session_id, stop_capture_flag
    
    if is_capturing:
        return jsonify({'error': 'キャプチャは既に実行中です'}), 400
    
    data = request.json
    interface = data.get('interface', None)
    packet_count = data.get('count', 100)
    
    # 前回のキャプチャをクリア
    capture_packets = []
    capture_raw_packets = []
    capture_session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    stop_capture_flag = False
    is_capturing = True
    
    capture_thread = threading.Thread(
        target=capture_packets_thread,
        args=(interface, packet_count)
    )
    capture_thread.start()
    
    return jsonify({
        'message': 'キャプチャを開始しました', 
        'status': 'started',
        'session_id': capture_session_id
    })

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """パケットキャプチャを停止"""
    global is_capturing, stop_capture_flag, capture_thread
    
    if not is_capturing:
        return jsonify({'message': 'キャプチャは実行されていません', 'status': 'not_running'})
    
    print("停止リクエストを受信しました")
    
    # 停止フラグをセット
    stop_capture_flag = True
    is_capturing = False
    
    # スレッドが終了するまで少し待つ
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2.0)
    
    print(f"キャプチャを停止しました。収集パケット数: {len(capture_packets)}")
    
    return jsonify({
        'message': 'キャプチャを停止しました', 
        'status': 'stopped',
        'packet_count': len(capture_packets)
    })

@app.route('/api/capture/packets', methods=['GET'])
def get_packets():
    """キャプチャしたパケットを取得"""
    return jsonify({
        'packets': capture_packets,
        'count': len(capture_packets),
        'is_capturing': is_capturing
    })

@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    """キャプチャの状態を取得"""
    return jsonify({
        'is_capturing': is_capturing,
        'packet_count': len(capture_packets),
        'session_id': capture_session_id
    })

@app.route('/api/capture/export/json', methods=['GET'])
def export_json():
    """パケット情報をJSONファイルとしてエクスポート"""
    global capture_packets, capture_session_id
    
    if not capture_packets:
        return jsonify({'error': 'エクスポートするパケットがありません'}), 400
    
    try:
        # 一時ファイルを作成
        temp_dir = tempfile.gettempdir()
        filename = f'packet_capture_{capture_session_id}.json'
        filepath = os.path.join(temp_dir, filename)
        
        # JSONファイルに保存
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                'session_id': capture_session_id,
                'capture_time': datetime.now().isoformat(),
                'packet_count': len(capture_packets),
                'packets': capture_packets
            }, f, ensure_ascii=False, indent=2)
        
        return send_file(
            filepath,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': f'エクスポートに失敗しました: {str(e)}'}), 500

@app.route('/api/capture/export/pcap', methods=['GET'])
def export_pcap():
    """パケットをpcapファイルとしてエクスポート（Wiresharkで開ける）"""
    global capture_raw_packets, capture_session_id
    
    if not capture_raw_packets:
        return jsonify({'error': 'エクスポートするパケットがありません'}), 400
    
    try:
        # 一時ファイルを作成
        temp_dir = tempfile.gettempdir()
        filename = f'packet_capture_{capture_session_id}.pcap'
        filepath = os.path.join(temp_dir, filename)
        
        # pcapファイルに保存
        wrpcap(filepath, capture_raw_packets)
        
        return send_file(
            filepath,
            mimetype='application/vnd.tcpdump.pcap',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': f'エクスポートに失敗しました: {str(e)}'}), 500

@app.route('/api/capture/export/csv', methods=['GET'])
def export_csv():
    """パケット情報をCSVファイルとしてエクスポート"""
    global capture_packets, capture_session_id
    
    if not capture_packets:
        return jsonify({'error': 'エクスポートするパケットがありません'}), 400
    
    try:
        import csv
        
        # 一時ファイルを作成
        temp_dir = tempfile.gettempdir()
        filename = f'packet_capture_{capture_session_id}.csv'
        filepath = os.path.join(temp_dir, filename)
        
        # CSVファイルに保存
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            
            # ヘッダー
            writer.writerow([
                'Timestamp', 'Type', 'Length', 'Source IP', 'Destination IP',
                'Source Port', 'Destination Port', 'Protocol Info', 'Summary'
            ])
            
            # データ
            for packet in capture_packets:
                row = [
                    packet.get('timestamp', ''),
                    packet.get('type', ''),
                    packet.get('length', ''),
                    packet.get('ip', {}).get('src', ''),
                    packet.get('ip', {}).get('dst', ''),
                    '',  # Source Port
                    '',  # Destination Port
                    '',  # Protocol Info
                    packet.get('summary', '')
                ]
                
                # ポート情報を追加
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
        
        return send_file(
            filepath,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': f'エクスポートに失敗しました: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
