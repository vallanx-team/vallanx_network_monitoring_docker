#!/usr/bin/env python3
"""
Network Traffic Monitor with Vallanx Universal Blocklist Integration
Standalone version - No Suricata dependencies
All IDS functionality is handled by Vallanx Universal Blocklist
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path

# Import the original network monitor components (except SuricataManager)
from network_monitor import (
    DatabaseManager,
    NetworkMonitor,
    app,
    socketio,
    logger
)

# Import Vallanx components
from vallanx_blocklist_manager import (
    VallanxBlocklistManager,
    VallanxNetworkIntegration,
    VallanxAPIServer,
    BlocklistType,
    ThreatCategory,
    Severity,
    Action,
    VallanxEntry
)

from flask import request, jsonify, render_template
from scapy.all import IP, TCP, UDP, DNS

# Initialize Vallanx Manager
vallanx_manager = VallanxBlocklistManager(base_path='/etc/vallanx')
vallanx_integration = VallanxNetworkIntegration(vallanx_manager)
vallanx_api = VallanxAPIServer(vallanx_manager, app)

# Enhanced Network Monitor with Vallanx
class VallanxNetworkMonitor(NetworkMonitor):
    """Extended Network Monitor with Vallanx blocklist integration"""
    
    def __init__(self, interface='eth0'):
        super().__init__(interface)
        self.vallanx = vallanx_integration
        self.blocked_connections = set()
        self.threat_stats = {
            'blocked_ips': 0,
            'blocked_domains': 0,
            'blocked_urls': 0,
            'auto_blocks': 0
        }
    
    def packet_callback(self, packet):
        """Enhanced packet processing with Vallanx checks"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)
                
                src_port = None
                dst_port = None
                
                # Extract ports
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                
                # Check against Vallanx blocklist
                vallanx_result = self.vallanx.check_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port
                )
                
                if vallanx_result:
                    self.handle_vallanx_match(vallanx_result, packet)
                    
                    # Skip further processing if blocked
                    if vallanx_result['entry'].action == Action.BLOCK:
                        return
                
                # Continue with original packet processing
                super().packet_callback(packet)
                
        except Exception as e:
            logger.error(f"Error in Vallanx packet processing: {e}")
    
    def handle_vallanx_match(self, match_result, packet):
        """Handle Vallanx blocklist match"""
        entry = match_result['entry']
        match_type = match_result['match']
        value = match_result['value']
        
        # Determine action
        action = self.vallanx.get_action_for_match(entry)
        
        # Log the match
        logger.warning(
            f"VALLANX MATCH: {match_type}={value} | "
            f"Category: {entry.category.value} | "
            f"Severity: {entry.severity.value} | "
            f"Action: {action}"
        )
        
        # Update statistics
        if match_type in ['source_ip', 'destination_ip']:
            self.threat_stats['blocked_ips'] += 1
        elif match_type == 'domain':
            self.threat_stats['blocked_domains'] += 1
        
        # Send alert via WebSocket
        alert_data = {
            'type': 'vallanx_match',
            'timestamp': datetime.now().isoformat(),
            'match_type': match_type,
            'value': value,
            'category': entry.category.value,
            'severity': entry.severity.value,
            'action': action,
            'confidence': entry.confidence,
            'tags': entry.tags
        }
        
        socketio.emit('vallanx_alert', alert_data)
        
        # Take action based on severity and action type
        if entry.severity.value >= 4:  # High or Critical
            self.take_blocking_action(entry, packet)
        elif action == 'monitor':
            self.log_for_monitoring(entry, packet)
        elif action == 'rate_limit':
            self.apply_rate_limit(entry, packet)
    
    def take_blocking_action(self, entry: VallanxEntry, packet):
        """Take blocking action for high severity threats"""
        # Add to blocked connections
        if IP in packet:
            conn_id = f"{packet[IP].src}:{packet[IP].dst}"
            self.blocked_connections.add(conn_id)
        
        # Generate dynamic firewall rule
        if entry.type == BlocklistType.IP:
            self.generate_iptables_block(entry.value)
        
        # Log blocking action
        logger.info(f"BLOCKED: {entry.value} ({entry.category.value})")
    
    def generate_iptables_block(self, ip):
        """Generate and apply iptables blocking rule"""
        try:
            import subprocess
            # Add DROP rule for the IP
            subprocess.run([
                'iptables', '-I', 'VALLANX_INPUT', '-s', ip, '-j', 'DROP'
            ], check=False)
            subprocess.run([
                'iptables', '-I', 'VALLANX_OUTPUT', '-d', ip, '-j', 'DROP'
            ], check=False)
            logger.info(f"Applied iptables block for {ip}")
        except Exception as e:
            logger.error(f"Failed to apply iptables rule: {e}")
    
    def log_for_monitoring(self, entry: VallanxEntry, packet):
        """Log packet for monitoring purposes"""
        monitor_data = {
            'timestamp': datetime.now().isoformat(),
            'entry': entry.to_dict(),
            'packet_info': self.extract_packet_info(packet)
        }
        
        # Store in database for analysis
        try:
            db_manager.store_monitoring_data(monitor_data)
        except Exception as e:
            logger.error(f"Failed to store monitoring data: {e}")
    
    def apply_rate_limit(self, entry: VallanxEntry, packet):
        """Apply rate limiting for the connection"""
        # Implementation using iptables hashlimit
        try:
            import subprocess
            if IP in packet:
                src_ip = packet[IP].src
                subprocess.run([
                    'iptables', '-I', 'VALLANX_INPUT',
                    '-s', src_ip,
                    '-m', 'hashlimit',
                    '--hashlimit-name', f'vallanx_{entry.value}',
                    '--hashlimit-above', '10/sec',
                    '-j', 'DROP'
                ], check=False)
                logger.info(f"Applied rate limit for {src_ip}")
        except Exception as e:
            logger.error(f"Failed to apply rate limit: {e}")
    
    def extract_packet_info(self, packet):
        """Extract relevant packet information"""
        info = {}
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
        
        if TCP in packet:
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['flags'] = str(packet[TCP].flags)
        elif UDP in packet:
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
        
        if DNS in packet and packet[DNS].qr == 0:
            info['dns_query'] = packet[DNS].qd.qname.decode() if packet[DNS].qd else None
        
        return info
    
    def process_dns_query(self, packet):
        """Enhanced DNS query processing with Vallanx"""
        dns = packet[DNS]
        query = dns.qd.qname.decode() if dns.qd else None
        
        if query:
            # Check against Vallanx blocklist
            entry = vallanx_manager.check(query, BlocklistType.DOMAIN)
            
            if entry:
                # Block DNS resolution for malicious domains
                threat = {
                    'type': 'DNS_VALLANX_BLOCK',
                    'severity': entry.severity.value,
                    'description': f"Blocked DNS query to {entry.category.value} domain: {query}",
                    'source': packet[IP].src if IP in packet else 'unknown',
                    'domain': query,
                    'timestamp': datetime.now().isoformat()
                }
                
                socketio.emit('threat_detected', threat)
                logger.warning(f"Blocked DNS query to {query} ({entry.category.value})")
                
                # Auto-block the requesting IP if severity is high
                if entry.severity.value >= 4 and IP in packet:
                    vallanx_manager.add_entry(
                        value=packet[IP].src,
                        type_str='ip',
                        category_str=entry.category.value,
                        severity=3,
                        action_str='monitor',
                        source='dns_query_block',
                        tags=['auto_added', 'dns_suspicious'],
                        metadata={'queried_domain': query}
                    )
                    self.threat_stats['auto_blocks'] += 1
                
                return  # Don't process further
        
        # Continue with original DNS processing
        super().process_dns_query(packet)
    
    def check_http_threats(self, http_info):
        """Enhanced HTTP threat checking with Vallanx"""
        # First check URL against Vallanx
        if 'host' in http_info and 'path' in http_info:
            url = f"http://{http_info['host']}{http_info['path']}"
            entry = vallanx_manager.check(url, BlocklistType.URL)
            
            if entry:
                threat = {
                    'type': 'HTTP_VALLANX_BLOCK',
                    'severity': entry.severity.value,
                    'description': f"Blocked HTTP request to {entry.category.value} URL",
                    'source': http_info['src_ip'],
                    'destination': http_info['dst_ip'],
                    'url': url,
                    'timestamp': http_info['timestamp'].isoformat()
                }
                
                socketio.emit('threat_detected', threat)
                
                # Auto-block source IP for high severity
                if entry.severity.value >= 4:
                    vallanx_manager.add_entry(
                        value=http_info['src_ip'],
                        type_str='ip',
                        category_str=entry.category.value,
                        severity=4,
                        action_str='block',
                        source='http_threat',
                        tags=['auto_blocked', 'http_malicious'],
                        metadata={'url': url}
                    )
                    self.threat_stats['auto_blocks'] += 1
                
                return
        
        # Check User-Agent if present
        if 'user_agent' in http_info:
            entry = vallanx_manager.check(http_info['user_agent'], BlocklistType.USER_AGENT)
            
            if entry:
                threat = {
                    'type': 'HTTP_SUSPICIOUS_UA',
                    'severity': entry.severity.value,
                    'description': f"Suspicious User-Agent detected: {entry.category.value}",
                    'source': http_info['src_ip'],
                    'user_agent': http_info['user_agent'],
                    'timestamp': http_info['timestamp'].isoformat()
                }
                
                socketio.emit('threat_detected', threat)
        
        # Continue with original threat checking
        super().check_http_threats(http_info)


# Flask Routes for Web Interface
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    """Get system statistics"""
    stats = {
        'status': 'running',
        'vallanx': vallanx_manager.get_statistics(),
        'uptime': 'running'
    }
    return jsonify(stats)

# Additional Flask Routes for Vallanx Dashboard
@app.route('/vallanx')
def vallanx_dashboard():
    """Vallanx blocklist management dashboard"""
    stats = vallanx_manager.get_statistics()
    return render_template('vallanx_dashboard.html', stats=stats)

@app.route('/api/vallanx/live-blocks')
def vallanx_live_blocks():
    """Get live blocking statistics"""
    monitor = network_monitor if 'network_monitor' in globals() else None
    
    if monitor and isinstance(monitor, VallanxNetworkMonitor):
        return jsonify({
            'blocked_ips': monitor.threat_stats['blocked_ips'],
            'blocked_domains': monitor.threat_stats['blocked_domains'],
            'blocked_urls': monitor.threat_stats['blocked_urls'],
            'auto_blocks': monitor.threat_stats['auto_blocks'],
            'active_blocks': len(monitor.blocked_connections)
        })
    else:
        return jsonify({
            'error': 'Vallanx monitor not initialized'
        }), 500

@app.route('/api/vallanx/threat-feed/import', methods=['POST'])
def import_threat_feed():
    """Import threat intelligence feeds in various formats"""
    feed_type = request.form.get('type', 'auto')
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    content = file.read().decode('utf-8')
    
    imported = 0
    
    if feed_type == 'vallanx':
        # Native Vallanx format
        imported = vallanx_manager.import_vallanx_format(content)
    
    elif feed_type == 'csv':
        # CSV format: value,type,category,severity,action
        import csv
        from io import StringIO
        
        reader = csv.DictReader(StringIO(content))
        for row in reader:
            success = vallanx_manager.add_entry(
                value=row['value'],
                type_str=row['type'],
                category_str=row['category'],
                severity=int(row.get('severity', 3)),
                action_str=row.get('action', 'block'),
                source='csv_import'
            )
            if success:
                imported += 1
    
    elif feed_type == 'json':
        # JSON format
        data = json.loads(content)
        entries = data.get('entries', data if isinstance(data, list) else [])
        
        for entry in entries:
            success = vallanx_manager.add_entry(
                value=entry['value'],
                type_str=entry['type'],
                category_str=entry['category'],
                severity=entry.get('severity', 3),
                action_str=entry.get('action', 'block'),
                source='json_import',
                tags=entry.get('tags', []),
                metadata=entry.get('metadata', {})
            )
            if success:
                imported += 1
    
    elif feed_type == 'ioc':
        # Simple IOC parser for IPs and domains
        import re
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        # Extract IPs
        for ip in re.findall(ip_pattern, content):
            success = vallanx_manager.add_entry(
                value=ip,
                type_str='ip',
                category_str='malware',
                severity=3,
                action_str='block',
                source='ioc_import'
            )
            if success:
                imported += 1
        
        # Extract domains
        for domain in re.findall(domain_pattern, content):
            success = vallanx_manager.add_entry(
                value=domain,
                type_str='domain',
                category_str='malware',
                severity=3,
                action_str='block',
                source='ioc_import'
            )
            if success:
                imported += 1
    
    else:
        # Auto-detect format
        # Try JSON first
        try:
            data = json.loads(content)
            return import_threat_feed()  # Recursive call with json type
        except:
            pass
        
        # Try CSV
        try:
            import csv
            from io import StringIO
            reader = csv.DictReader(StringIO(content))
            next(reader)  # Try to read first row
            return import_threat_feed()  # Recursive call with csv type
        except:
            pass
        
        # Default to IOC
        return import_threat_feed()  # Recursive call with ioc type
    
    return jsonify({
        'success': True,
        'imported': imported,
        'format': feed_type
    })

@app.route('/api/vallanx/export-all')
def export_all_formats():
    """Export Vallanx blocklist in all formats as ZIP"""
    import zipfile
    from io import BytesIO
    
    # Create in-memory ZIP file
    zip_buffer = BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Vallanx native format
        zip_file.writestr('vallanx.vbx', vallanx_manager.export_vallanx_format())
        
        # iptables format
        zip_file.writestr('iptables.sh', vallanx_manager.export_iptables())
        
        # hosts format
        zip_file.writestr('hosts', vallanx_manager.export_hosts_file())
        
        # Suricata rules (for compatibility)
        zip_file.writestr('suricata.rules', vallanx_manager.export_suricata_rules())
        
        # JSON format
        stats = vallanx_manager.get_statistics()
        zip_file.writestr('stats.json', json.dumps(stats, indent=2))
        
        # CSV format
        csv_content = "value,type,category,severity,action,confidence,source\n"
        for blocklist_type in BlocklistType:
            for entry in vallanx_manager.blocklists[blocklist_type]:
                csv_content += f"{entry.value},{entry.type.value},{entry.category.value},{entry.severity.value},{entry.action.value},{entry.confidence},{entry.source}\n"
        zip_file.writestr('blocklist.csv', csv_content)
    
    zip_buffer.seek(0)
    
    from flask import send_file
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'vallanx_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
    )

# WebSocket handlers
@socketio.on('vallanx_stats_request')
def handle_vallanx_stats_request():
    """Handle request for Vallanx statistics"""
    from flask_socketio import emit
    stats = vallanx_manager.get_statistics()
    emit('vallanx_stats_update', stats)

@socketio.on('vallanx_check')
def handle_vallanx_check(data):
    """Check if a value is in the Vallanx blocklist"""
    from flask_socketio import emit
    value = data.get('value')
    type_str = data.get('type', 'ip')
    
    blocklist_type = BlocklistType[type_str.upper()]
    entry = vallanx_manager.check(value, blocklist_type)
    
    if entry:
        emit('vallanx_check_result', {
            'blocked': True,
            'value': value,
            'category': entry.category.value,
            'severity': entry.severity.value,
            'action': entry.action.value,
            'tags': entry.tags
        })
    else:
        emit('vallanx_check_result', {
            'blocked': False,
            'value': value
        })

@socketio.on('vallanx_add_quick')
def handle_vallanx_add_quick(data):
    """Quick add to Vallanx blocklist via WebSocket"""
    from flask_socketio import emit
    
    success = vallanx_manager.add_entry(
        value=data['value'],
        type_str=data['type'],
        category_str=data.get('category', 'malware'),
        severity=data.get('severity', 3),
        action_str=data.get('action', 'block'),
        source='websocket_quick_add'
    )
    
    if success:
        emit('vallanx_add_result', {
            'success': True,
            'message': f"Added {data['value']} to Vallanx blocklist"
        })
        
        # Broadcast stats update to all clients
        socketio.emit('vallanx_stats_update', vallanx_manager.get_statistics())
    else:
        emit('vallanx_add_result', {
            'success': False,
            'error': 'Failed to add entry'
        })

# Main execution with Vallanx (No Suricata)
if __name__ == '__main__':
    # Initialize components
    db_manager = DatabaseManager()
    network_monitor = VallanxNetworkMonitor()  # Use Vallanx-enhanced monitor
    
    logger.info("=" * 60)
    logger.info("Vallanx Network Monitor initialized (Standalone Mode)")
    logger.info("No Suricata dependencies - All IDS functions via Vallanx")
    logger.info("=" * 60)
    logger.info(f"Vallanx Statistics: {vallanx_manager.get_statistics()}")
    
    # Start monitoring - handled by Flask/SocketIO
    # network_monitor.start_monitoring()
    
    # Periodic Vallanx maintenance (No Suricata updates)
    def vallanx_maintenance():
        while True:
            time.sleep(3600)  # Every hour
            vallanx_manager.cleanup_expired()
            logger.info("Vallanx maintenance completed")
    
    import threading
    maintenance_thread = threading.Thread(target=vallanx_maintenance, daemon=True)
    maintenance_thread.start()
    
    # Start Flask app with SocketIO
    logger.info("Starting Vallanx Network Monitor on http://0.0.0.0:5000")
    logger.info("Web Dashboard: http://0.0.0.0:5000")
    logger.info("Vallanx Dashboard: http://0.0.0.0:5000/vallanx")
    logger.info("Vallanx API: http://0.0.0.0:8089")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
