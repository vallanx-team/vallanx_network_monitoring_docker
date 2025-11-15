#!/usr/bin/env python3
"""
Vallanx Network Monitor - Standalone Version
Complete network monitoring solution with Vallanx Universal Blocklist integration
No external dependencies except Python packages

Usage:
    sudo python3 standalone_monitor.py [--interface eth0] [--port 5000]

Requirements:
    - Python 3.8+
    - Root privileges for packet capture
    - See requirements.txt for Python packages
"""

import os
import sys
import re
import json
import time
import sqlite3
import logging
import argparse
import ipaddress
import tldextract
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import urlparse
from collections import defaultdict, deque

# Third-party imports
try:
    from flask import Flask, render_template, jsonify, request, send_file
    from flask_socketio import SocketIO, emit
    from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP
    import psutil
except ImportError as e:
    print(f"ERROR: Missing required package: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    'interface': 'eth0',
    'web_port': 5000,
    'data_dir': './data',
    'vallanx_dir': './data/vallanx',
    'db_path': './data/network_monitor.db',
    'log_file': './network_monitor.log',
    'auto_block': True,
    'packet_limit': 1000,
    'cleanup_days': 30
}

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(DEFAULT_CONFIG['log_file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# VALLANX BLOCKLIST MANAGER
# ============================================================================

class BlocklistType(Enum):
    """Vallanx blocklist types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    CIDR = "cidr"
    ASN = "asn"
    REGEX = "regex"
    WILDCARD = "wildcard"
    TLD = "tld"
    PORT = "port"
    PROTOCOL = "protocol"
    USER_AGENT = "user_agent"
    SSL_FINGERPRINT = "ssl_fingerprint"
    JA3 = "ja3"

class ThreatCategory(Enum):
    """Vallanx threat categories"""
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    BOTNET = "botnet"
    C2 = "command_control"
    CRYPTOMINER = "cryptominer"
    EXPLOIT = "exploit"
    SPAM = "spam"
    SCAM = "scam"
    PUP = "pup"
    ADWARE = "adware"
    TRACKING = "tracking"
    PORN = "pornography"
    GAMBLING = "gambling"
    PIRACY = "piracy"
    DRUGS = "drugs"
    VIOLENCE = "violence"
    HATE = "hate_speech"
    DDOS = "ddos"
    APT = "apt"

class Severity(Enum):
    """Threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class Action(Enum):
    """Actions to take on match"""
    BLOCK = "block"
    ALLOW = "allow"
    MONITOR = "monitor"
    REDIRECT = "redirect"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    LOG = "log"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    SANDBOX = "sandbox"

@dataclass
class VallanxEntry:
    """Single entry in Vallanx blocklist"""
    value: str
    type: BlocklistType
    category: ThreatCategory
    severity: Severity
    action: Action
    confidence: float = 1.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    source: str = "manual"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expire: Optional[datetime] = None
    false_positive_reports: int = 0
    hit_count: int = 0

    def __hash__(self):
        return hash(f"{self.type.value}:{self.value}")

    def __eq__(self, other):
        if isinstance(other, VallanxEntry):
            return self.type == other.type and self.value == other.value
        return False

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'value': self.value,
            'type': self.type.value,
            'category': self.category.value,
            'severity': self.severity.value,
            'action': self.action.value,
            'confidence': self.confidence,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'source': self.source,
            'tags': self.tags,
            'metadata': self.metadata,
            'expire': self.expire.isoformat() if self.expire else None,
            'false_positive_reports': self.false_positive_reports,
            'hit_count': self.hit_count
        }

class VallanxBlocklistManager:
    """Manager for Vallanx Universal Blocklist"""

    def __init__(self, base_path: str = './data/vallanx'):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Separate storage for different types
        self.blocklists: Dict[BlocklistType, Set[VallanxEntry]] = {
            blocklist_type: set() for blocklist_type in BlocklistType
        }

        # Fast lookup caches
        self.ip_cache: Set[str] = set()
        self.domain_cache: Set[str] = set()
        self.cidr_networks: List[ipaddress.IPv4Network] = []
        self.regex_patterns: List[re.Pattern] = []

        # Load existing lists
        self.load_all_lists()

        logger.info(f"Vallanx Blocklist Manager initialized at {self.base_path}")

    def add_entry(self, value: str, type_str: str, category_str: str,
                  severity: int = 3, action_str: str = "block", **kwargs) -> bool:
        """Add entry to blocklist"""
        try:
            entry_type = BlocklistType(type_str.lower())

            if not self.validate_value(value, entry_type):
                logger.error(f"Invalid value {value} for type {entry_type}")
                return False

            entry = VallanxEntry(
                value=self.normalize_value(value, entry_type),
                type=entry_type,
                category=ThreatCategory(category_str.lower()),
                severity=Severity(severity),
                action=Action(action_str.lower()),
                confidence=kwargs.get('confidence', 1.0),
                source=kwargs.get('source', 'manual'),
                tags=kwargs.get('tags', []),
                metadata=kwargs.get('metadata', {})
            )

            self.blocklists[entry_type].add(entry)
            self.update_caches(entry)
            self.save_list(entry_type)

            logger.info(f"Added {entry_type.value}: {value} to blocklist")
            return True

        except Exception as e:
            logger.error(f"Error adding entry: {e}")
            return False

    def validate_value(self, value: str, entry_type: BlocklistType) -> bool:
        """Validate value based on type"""
        try:
            if entry_type == BlocklistType.IP:
                ipaddress.ip_address(value)
                return True
            elif entry_type == BlocklistType.CIDR:
                ipaddress.ip_network(value)
                return True
            elif entry_type == BlocklistType.DOMAIN:
                domain_regex = re.compile(
                    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
                    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                )
                return bool(domain_regex.match(value))
            elif entry_type == BlocklistType.PORT:
                port = int(value)
                return 0 <= port <= 65535
            else:
                return bool(value)
        except:
            return False

    def normalize_value(self, value: str, entry_type: BlocklistType) -> str:
        """Normalize value for consistent storage"""
        if entry_type in [BlocklistType.DOMAIN, BlocklistType.EMAIL,
                          BlocklistType.HASH, BlocklistType.URL]:
            return value.lower().strip()
        return value

    def update_caches(self, entry: VallanxEntry):
        """Update fast lookup caches"""
        if entry.type == BlocklistType.IP:
            self.ip_cache.add(entry.value)
        elif entry.type == BlocklistType.DOMAIN:
            self.domain_cache.add(entry.value)
        elif entry.type == BlocklistType.CIDR:
            try:
                self.cidr_networks.append(ipaddress.ip_network(entry.value))
            except:
                pass
        elif entry.type == BlocklistType.REGEX:
            try:
                self.regex_patterns.append(re.compile(entry.value))
            except:
                pass

    def check(self, value: str, check_type: Optional[BlocklistType] = None) -> Optional[VallanxEntry]:
        """Check if value is in blocklist"""
        if not check_type:
            check_type = self.detect_type(value)

        if not check_type:
            return None

        # Quick cache lookups
        if check_type == BlocklistType.IP and value in self.ip_cache:
            return self.get_entry(value, BlocklistType.IP)

        if check_type == BlocklistType.DOMAIN:
            domain = value.lower()
            while domain:
                if domain in self.domain_cache:
                    return self.get_entry(domain, BlocklistType.DOMAIN)
                parts = domain.split('.', 1)
                domain = parts[1] if len(parts) > 1 else ''

        # Check CIDR ranges for IP
        if check_type == BlocklistType.IP:
            try:
                ip = ipaddress.ip_address(value)
                for network in self.cidr_networks:
                    if ip in network:
                        return self.get_entry(str(network), BlocklistType.CIDR)
            except:
                pass

        return None

    def get_entry(self, value: str, entry_type: BlocklistType) -> Optional[VallanxEntry]:
        """Get specific entry from blocklist"""
        for entry in self.blocklists[entry_type]:
            if entry.value == value:
                entry.hit_count += 1
                entry.last_seen = datetime.now()
                return entry
        return None

    def detect_type(self, value: str) -> Optional[BlocklistType]:
        """Auto-detect the type of value"""
        try:
            ipaddress.ip_address(value)
            return BlocklistType.IP
        except:
            pass

        try:
            ipaddress.ip_network(value)
            return BlocklistType.CIDR
        except:
            pass

        if value.startswith(('http://', 'https://', 'ftp://')):
            return BlocklistType.URL

        if '.' in value:
            return BlocklistType.DOMAIN

        return None

    def save_list(self, list_type: BlocklistType):
        """Save specific blocklist to disk"""
        filename = self.base_path / f'{list_type.value}.json'

        data = {
            'type': list_type.value,
            'updated': datetime.now().isoformat(),
            'entries': [entry.to_dict() for entry in self.blocklists[list_type]]
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def load_all_lists(self):
        """Load all blocklists from disk"""
        for json_file in self.base_path.glob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                for entry_dict in data.get('entries', []):
                    try:
                        entry = VallanxEntry(
                            value=entry_dict['value'],
                            type=BlocklistType(entry_dict['type']),
                            category=ThreatCategory(entry_dict['category']),
                            severity=Severity(entry_dict['severity']),
                            action=Action(entry_dict['action']),
                            confidence=entry_dict.get('confidence', 1.0),
                            source=entry_dict.get('source', 'unknown'),
                            tags=entry_dict.get('tags', []),
                            metadata=entry_dict.get('metadata', {}),
                            hit_count=entry_dict.get('hit_count', 0)
                        )

                        entry.first_seen = datetime.fromisoformat(entry_dict['first_seen'])
                        entry.last_seen = datetime.fromisoformat(entry_dict['last_seen'])

                        self.blocklists[entry.type].add(entry)
                        self.update_caches(entry)
                    except Exception as e:
                        logger.error(f"Error loading entry: {e}")

                logger.info(f"Loaded {len(data.get('entries', []))} entries from {json_file}")
            except Exception as e:
                logger.error(f"Error loading {json_file}: {e}")

    def get_statistics(self) -> Dict:
        """Get blocklist statistics"""
        stats = {
            'total_entries': sum(len(self.blocklists[t]) for t in BlocklistType),
            'by_type': {t.value: len(self.blocklists[t]) for t in BlocklistType},
            'by_category': {},
            'by_severity': {}
        }

        for blocklist_type in BlocklistType:
            for entry in self.blocklists[blocklist_type]:
                cat = entry.category.value
                stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

                sev = f'severity_{entry.severity.value}'
                stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1

        return stats

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    """Manages SQLite database for network monitoring"""

    def __init__(self, db_path: str = './data/network_monitor.db'):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
        logger.info(f"Database initialized at {db_path}")

    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Traffic stats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                direction TEXT
            )
        ''')

        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT,
                severity INTEGER,
                src_ip TEXT,
                dst_ip TEXT,
                description TEXT,
                blocked BOOLEAN
            )
        ''')

        # Blacklist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT UNIQUE,
                type TEXT,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def log_traffic(self, packet_info: Dict):
        """Log traffic to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO traffic_stats
                (src_ip, dst_ip, src_port, dst_port, protocol, packet_size, direction)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info.get('src_ip'),
                packet_info.get('dst_ip'),
                packet_info.get('src_port'),
                packet_info.get('dst_port'),
                packet_info.get('protocol'),
                packet_info.get('size'),
                packet_info.get('direction')
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging traffic: {e}")

    def log_threat(self, threat_info: Dict):
        """Log detected threat"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO threats
                (threat_type, severity, src_ip, dst_ip, description, blocked)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                threat_info.get('type'),
                threat_info.get('severity', 3),
                threat_info.get('src_ip'),
                threat_info.get('dst_ip'),
                threat_info.get('description'),
                threat_info.get('blocked', False)
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging threat: {e}")

# ============================================================================
# NETWORK MONITOR
# ============================================================================

class NetworkMonitor:
    """Network traffic monitor with Vallanx integration"""

    def __init__(self, interface: str = 'eth0', vallanx: VallanxBlocklistManager = None,
                 db: DatabaseManager = None):
        self.interface = interface
        self.vallanx = vallanx
        self.db = db
        self.running = False
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'blocked': 0,
            'allowed': 0,
            'threats': 0
        }
        self.recent_packets = deque(maxlen=100)
        logger.info(f"Network Monitor initialized on interface {interface}")

    def start_monitoring(self):
        """Start packet capture"""
        self.running = True
        logger.info("Starting packet capture...")

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            logger.error("Make sure you run this script with sudo/root privileges")

    def stop_monitoring(self):
        """Stop packet capture"""
        self.running = False
        logger.info("Stopped packet capture")

    def packet_callback(self, packet):
        """Process captured packet"""
        try:
            if not IP in packet:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)

            src_port = None
            dst_port = None

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = 'TCP'
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'

            # Update stats
            self.stats['total_packets'] += 1
            self.stats['total_bytes'] += size

            # Determine direction
            direction = self.determine_direction(src_ip, dst_ip)

            # Create packet info
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'size': size,
                'direction': direction
            }

            # Check against Vallanx blocklist
            if self.vallanx:
                blocked = False

                # Check source IP
                entry = self.vallanx.check(src_ip, BlocklistType.IP)
                if entry and entry.action == Action.BLOCK:
                    self.handle_blocked_packet(packet_info, entry, 'source_ip')
                    blocked = True

                # Check destination IP
                entry = self.vallanx.check(dst_ip, BlocklistType.IP)
                if entry and entry.action == Action.BLOCK:
                    self.handle_blocked_packet(packet_info, entry, 'dest_ip')
                    blocked = True

                # Check DNS queries
                if DNS in packet and packet[DNS].qr == 0:
                    if packet[DNS].qd:
                        domain = packet[DNS].qd.qname.decode().rstrip('.')
                        entry = self.vallanx.check(domain, BlocklistType.DOMAIN)
                        if entry and entry.action == Action.BLOCK:
                            self.handle_blocked_packet(packet_info, entry, 'dns_query', domain)
                            blocked = True

                if blocked:
                    self.stats['blocked'] += 1
                    return
                else:
                    self.stats['allowed'] += 1

            # Add to recent packets
            self.recent_packets.append(packet_info)

            # Log to database
            if self.db:
                self.db.log_traffic(packet_info)

            # Emit to web interface
            if hasattr(self, 'socketio'):
                self.socketio.emit('packet', packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def determine_direction(self, src_ip: str, dst_ip: str) -> str:
        """Determine packet direction"""
        try:
            src = ipaddress.ip_address(src_ip)
            dst = ipaddress.ip_address(dst_ip)

            # Check if private
            src_private = src.is_private
            dst_private = dst.is_private

            if src_private and dst_private:
                return 'internal'
            elif src_private and not dst_private:
                return 'outbound'
            elif not src_private and dst_private:
                return 'inbound'
            else:
                return 'external'
        except:
            return 'unknown'

    def handle_blocked_packet(self, packet_info: Dict, entry: VallanxEntry,
                              match_type: str, domain: str = None):
        """Handle blocked packet"""
        threat_info = {
            'type': f'VALLANX_BLOCK_{match_type.upper()}',
            'severity': entry.severity.value,
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'description': f"Blocked {match_type}: {domain or packet_info.get('src_ip')} - {entry.category.value}",
            'blocked': True
        }

        logger.warning(f"BLOCKED: {threat_info['description']}")

        self.stats['threats'] += 1

        if self.db:
            self.db.log_threat(threat_info)

        if hasattr(self, 'socketio'):
            self.socketio.emit('threat_detected', threat_info)

# ============================================================================
# FLASK WEB APPLICATION
# ============================================================================

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global instances
vallanx_manager = None
network_monitor = None
db_manager = None

@app.route('/')
def index():
    """Main dashboard"""
    try:
        return render_template('index.html')
    except:
        return '''
        <html>
        <head><title>Vallanx Network Monitor</title></head>
        <body>
            <h1>Vallanx Network Monitor</h1>
            <p>Monitor is running. API available at /api/stats</p>
            <p>Templates not found. Using basic HTML.</p>
        </body>
        </html>
        '''

@app.route('/api/stats')
def api_stats():
    """Get system statistics"""
    stats = {
        'status': 'running' if network_monitor and network_monitor.running else 'stopped',
        'network': network_monitor.stats if network_monitor else {},
        'vallanx': vallanx_manager.get_statistics() if vallanx_manager else {},
        'uptime': time.time()
    }
    return jsonify(stats)

@app.route('/api/packets/recent')
def recent_packets():
    """Get recent packets"""
    if network_monitor:
        return jsonify({
            'packets': list(network_monitor.recent_packets)
        })
    return jsonify({'packets': []})

# Vallanx API Routes
@app.route('/api/vallanx/check', methods=['POST'])
def vallanx_check():
    """Check if value is in blocklist"""
    data = request.json
    value = data.get('value')

    if not value:
        return jsonify({'error': 'No value provided'}), 400

    entry = vallanx_manager.check(value) if vallanx_manager else None

    if entry:
        return jsonify({
            'blocked': True,
            'entry': entry.to_dict()
        })
    else:
        return jsonify({'blocked': False})

@app.route('/api/vallanx/add', methods=['POST'])
def vallanx_add():
    """Add entry to blocklist"""
    data = request.json

    if not all(k in data for k in ['value', 'type', 'category']):
        return jsonify({'error': 'Missing required fields'}), 400

    success = vallanx_manager.add_entry(
        value=data['value'],
        type_str=data['type'],
        category_str=data['category'],
        severity=data.get('severity', 3),
        action_str=data.get('action', 'block'),
        tags=data.get('tags', []),
        metadata=data.get('metadata', {})
    ) if vallanx_manager else False

    if success:
        return jsonify({
            'success': True,
            'message': f"Added {data['value']} to blocklist"
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to add entry'
        }), 400

@app.route('/api/vallanx/stats')
def vallanx_stats():
    """Get Vallanx statistics"""
    if vallanx_manager:
        return jsonify(vallanx_manager.get_statistics())
    return jsonify({'error': 'Vallanx not initialized'}), 500

@app.route('/api/vallanx/remove', methods=['DELETE'])
def vallanx_remove():
    """Remove entry from blocklist"""
    data = request.json
    value = data.get('value')
    entry_type = data.get('type')

    if not value or not entry_type:
        return jsonify({'error': 'Both value and type required'}), 400

    try:
        entry_type = BlocklistType(entry_type)

        for entry in vallanx_manager.blocklists[entry_type]:
            if entry.value == value:
                vallanx_manager.blocklists[entry_type].remove(entry)
                vallanx_manager.save_list(entry_type)

                return jsonify({
                    'success': True,
                    'message': f"Removed {value}"
                })

        return jsonify({
            'success': False,
            'error': 'Entry not found'
        }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

# Blacklist/Whitelist compatibility routes
@app.route('/api/blacklist')
def get_blacklist():
    """Get blacklist (compatibility)"""
    ips = []
    domains = []

    if vallanx_manager:
        for entry in vallanx_manager.blocklists[BlocklistType.IP]:
            if entry.action == Action.BLOCK:
                ips.append(entry.value)
        for entry in vallanx_manager.blocklists[BlocklistType.DOMAIN]:
            if entry.action == Action.BLOCK:
                domains.append(entry.value)

    return jsonify({'ips': ips, 'domains': domains})

@app.route('/api/blacklist/add', methods=['POST'])
def add_to_blacklist():
    """Add to blacklist (compatibility)"""
    data = request.json

    if 'ip' in data:
        success = vallanx_manager.add_entry(
            value=data['ip'],
            type_str='ip',
            category_str='malware',
            severity=3,
            action_str='block'
        )
    elif 'domain' in data:
        success = vallanx_manager.add_entry(
            value=data['domain'],
            type_str='domain',
            category_str='malware',
            severity=3,
            action_str='block'
        )
    else:
        return jsonify({'success': False, 'error': 'No IP or domain provided'}), 400

    return jsonify({'success': success})

# WebSocket handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")
    emit('status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnect"""
    logger.info("Client disconnected")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point"""
    global vallanx_manager, network_monitor, db_manager

    parser = argparse.ArgumentParser(description='Vallanx Network Monitor - Standalone')
    parser.add_argument('--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('--port', type=int, default=5000, help='Web interface port')
    parser.add_argument('--data-dir', default='./data', help='Data directory')
    args = parser.parse_args()

    print("=" * 70)
    print("  VALLANX NETWORK MONITOR - STANDALONE VERSION")
    print("=" * 70)
    print(f"  Interface: {args.interface}")
    print(f"  Web Port:  {args.port}")
    print(f"  Data Dir:  {args.data_dir}")
    print("=" * 70)
    print()

    # Create data directories
    Path(args.data_dir).mkdir(parents=True, exist_ok=True)
    Path(args.data_dir, 'vallanx').mkdir(parents=True, exist_ok=True)

    # Initialize components
    logger.info("Initializing components...")

    db_manager = DatabaseManager(f"{args.data_dir}/network_monitor.db")
    vallanx_manager = VallanxBlocklistManager(f"{args.data_dir}/vallanx")
    network_monitor = NetworkMonitor(args.interface, vallanx_manager, db_manager)
    network_monitor.socketio = socketio

    # Add some example blocklist entries
    if vallanx_manager.stats['total_entries'] == 0:
        logger.info("Adding example blocklist entries...")
        vallanx_manager.add_entry("127.0.0.1", "ip", "malware", 5, "block",
                                  tags=["example"], source="default")
        vallanx_manager.add_entry("malware.example.com", "domain", "malware", 5, "block",
                                  tags=["example"], source="default")

    logger.info(f"Vallanx Statistics: {vallanx_manager.get_statistics()}")

    # Start packet capture in background thread
    def monitor_thread():
        network_monitor.start_monitoring()

    monitoring_thread = threading.Thread(target=monitor_thread, daemon=True)
    monitoring_thread.start()

    print()
    print("=" * 70)
    print("  SERVER STARTED")
    print("=" * 70)
    print(f"  Web Dashboard: http://0.0.0.0:{args.port}")
    print(f"  API Endpoint:  http://0.0.0.0:{args.port}/api/stats")
    print()
    print("  Press Ctrl+C to stop")
    print("=" * 70)
    print()

    try:
        # Start Flask with SocketIO
        socketio.run(app, host='0.0.0.0', port=args.port, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        network_monitor.stop_monitoring()
        logger.info("Shutdown complete")

if __name__ == '__main__':
    main()
