#!/usr/bin/env python3
"""
Advanced Network Traffic Monitor with Web Interface and Blacklist/Whitelist Management
Complete integrated version with all features
"""

import os
import sys
import json
import time
import sqlite3
import asyncio
import logging
import subprocess
import threading
import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

# Third-party imports
import psutil
import mysql.connector
from mysql.connector import pooling
import psycopg2
from psycopg2 import pool
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
import pandas as pd
import numpy as np
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Import the Suricata Rules Manager
# from suricata_rules_manager import SuricataRulesManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask application setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self, credentials_file='db-credentials.json'):
        self.credentials_file = credentials_file
        self.connection_pool = None
        self.db_type = None
        self.load_credentials()
        self.initialize_connection_pool()
        self.setup_database()
    
    def load_credentials(self):
        """Load database credentials from JSON file"""
        try:
            with open(self.credentials_file, 'r') as f:
                self.credentials = json.load(f)
                self.db_type = self.credentials.get('type', 'mysql')
                logger.info(f"Loaded database credentials for {self.db_type}")
        except FileNotFoundError:
            logger.error(f"Credentials file {self.credentials_file} not found")
            self.create_default_credentials()
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing credentials file: {e}")
            sys.exit(1)
    
    def create_default_credentials(self):
        """Create a default credentials file template"""
        default_creds = {
            "type": "mysql",
            "host": "localhost",
            "port": 3306,
            "user": "monitor_user",
            "password": "secure_password",
            "database": "network_monitor",
            "ssl": {
                "enabled": True,
                "ca_path": "/path/to/ca.pem",
                "cert_path": "/path/to/client-cert.pem",
                "key_path": "/path/to/client-key.pem"
            },
            "pool_size": 5,
            "pool_name": "monitor_pool"
        }
        
        with open(self.credentials_file, 'w') as f:
            json.dump(default_creds, f, indent=4)
        logger.info(f"Created default credentials file: {self.credentials_file}")
    
    def initialize_connection_pool(self):
        """Initialize database connection pool"""
        try:
            if self.db_type == 'mysql':
                ssl_config = None
                if self.credentials.get('ssl', {}).get('enabled'):
                    ssl_config = {
                        'ca': self.credentials['ssl'].get('ca_path'),
                        'cert': self.credentials['ssl'].get('cert_path'),
                        'key': self.credentials['ssl'].get('key_path')
                    }
                
                dbconfig = {
                    'host': self.credentials['host'],
                    'port': self.credentials.get('port', 3306),
                    'user': self.credentials['user'],
                    'password': self.credentials['password'],
                    'database': self.credentials['database']
                }
                
                if ssl_config:
                    dbconfig['ssl_disabled'] = False
                    dbconfig['ssl_ca'] = ssl_config['ca']
                    if ssl_config.get('cert'):
                        dbconfig['ssl_cert'] = ssl_config['cert']
                    if ssl_config.get('key'):
                        dbconfig['ssl_key'] = ssl_config['key']
                
                self.connection_pool = mysql.connector.pooling.MySQLConnectionPool(
                    pool_name=self.credentials.get('pool_name', 'monitor_pool'),
                    pool_size=self.credentials.get('pool_size', 5),
                    **dbconfig
                )
                
            elif self.db_type == 'postgresql':
                conn_string = f"postgresql://{self.credentials['user']}:{self.credentials['password']}@{self.credentials['host']}:{self.credentials.get('port', 5432)}/{self.credentials['database']}"
                
                if self.credentials.get('ssl', {}).get('enabled'):
                    conn_string += "?sslmode=require"
                    if self.credentials['ssl'].get('ca_path'):
                        conn_string += f"&sslrootcert={self.credentials['ssl']['ca_path']}"
                
                self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                    1,
                    self.credentials.get('pool_size', 5),
                    conn_string
                )
            
            logger.info("Database connection pool initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            # Fallback to SQLite
            self.use_sqlite_fallback()
    
    def use_sqlite_fallback(self):
        """Use SQLite as fallback database"""
        logger.info("Using SQLite as fallback database")
        self.db_type = 'sqlite'
        self.db_path = 'network_monitor.db'
    
    def get_connection(self):
        """Get a database connection from the pool"""
        if self.db_type == 'sqlite':
            return sqlite3.connect(self.db_path)
        elif self.db_type == 'mysql':
            return self.connection_pool.get_connection()
        elif self.db_type == 'postgresql':
            return self.connection_pool.getconn()
    
    def release_connection(self, conn):
        """Release connection back to pool"""
        if self.db_type == 'sqlite':
            conn.close()
        elif self.db_type == 'mysql':
            conn.close()
        elif self.db_type == 'postgresql':
            self.connection_pool.putconn(conn)
    
    def setup_database(self):
        """Create necessary database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Traffic statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol VARCHAR(10),
                    bytes_sent BIGINT,
                    packets_count INTEGER,
                    direction VARCHAR(10),
                    application VARCHAR(50),
                    threat_level INTEGER DEFAULT 0,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_src_ip (src_ip),
                    INDEX idx_dst_ip (dst_ip)
                )
            ''' if self.db_type == 'mysql' else '''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    bytes_sent INTEGER,
                    packets_count INTEGER,
                    direction TEXT,
                    application TEXT,
                    threat_level INTEGER DEFAULT 0
                )
            ''')
            
            # Suricata alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suricata_alerts (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_time DATETIME,
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol VARCHAR(10),
                    signature VARCHAR(255),
                    category VARCHAR(100),
                    severity INTEGER,
                    payload TEXT,
                    INDEX idx_alert_time (alert_time),
                    INDEX idx_severity (severity)
                )
            ''' if self.db_type == 'mysql' else '''
                CREATE TABLE IF NOT EXISTS suricata_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_time DATETIME,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    signature TEXT,
                    category TEXT,
                    severity INTEGER,
                    payload TEXT
                )
            ''')
            
            # Connection logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connection_logs (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    connection_id VARCHAR(100),
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol VARCHAR(10),
                    state VARCHAR(20),
                    duration FLOAT,
                    bytes_to_server BIGINT,
                    bytes_to_client BIGINT,
                    INDEX idx_connection_id (connection_id),
                    INDEX idx_state (state)
                )
            ''' if self.db_type == 'mysql' else '''
                CREATE TABLE IF NOT EXISTS connection_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    connection_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    duration REAL,
                    bytes_to_server INTEGER,
                    bytes_to_client INTEGER
                )
            ''')
            
            conn.commit()
            logger.info("Database tables created successfully")
            
        except Exception as e:
            logger.error(f"Error setting up database tables: {e}")
            conn.rollback()
        finally:
            self.release_connection(conn)

class SuricataManager:
    """Enhanced Suricata IDS integration"""
    
    def __init__(self, config_path='/etc/suricata/suricata.yaml'):
        self.config_path = config_path
        self.eve_log_path = '/var/log/suricata/eve.json'
        self.rules_path = '/etc/suricata/rules'
        self.process = None
        self.monitoring = False
        self.setup_suricata()
    
    def setup_suricata(self):
        """Setup Suricata configuration and rules"""
        # Create rules directory if not exists
        Path(self.rules_path).mkdir(parents=True, exist_ok=True)
        
        # Update Suricata configuration
        self.update_configuration()
    
    def update_configuration(self):
        """Update Suricata configuration for monitoring"""
        config = {
            'vars': {
                'address-groups': {
                    'HOME_NET': '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]',
                    'EXTERNAL_NET': '!$HOME_NET'
                }
            },
            'outputs': {
                'eve-log': {
                    'enabled': 'yes',
                    'filetype': 'regular',
                    'filename': 'eve.json',
                    'types': [
                        {'alert': {'payload': 'yes', 'payload-printable': 'yes'}},
                        {'http': {'extended': 'yes'}},
                        {'dns': {'enabled': 'yes'}},
                        {'tls': {'extended': 'yes'}},
                        {'files': {'force-magic': 'yes'}},
                        {'flow': None},
                        {'netflow': None},
                        {'stats': {'totals': 'yes', 'threads': 'yes'}}
                    ]
                }
            }
        }
        
        # Write minimal config if Suricata is not installed
        if not os.path.exists(self.config_path):
            logger.warning("Suricata not installed, skipping configuration")
            return
    
    def start_monitoring(self, interface='eth0'):
        """Start Suricata monitoring"""
        try:
            cmd = ['suricata', '-c', self.config_path, '-i', interface, '--init-errors-fatal']
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.monitoring = True
            logger.info(f"Started Suricata monitoring on interface {interface}")
            
            # Start EVE log parser
            threading.Thread(target=self.parse_eve_logs, daemon=True).start()
            
        except FileNotFoundError:
            logger.warning("Suricata not found, IDS features disabled")
        except Exception as e:
            logger.error(f"Failed to start Suricata: {e}")
    
    def stop_monitoring(self):
        """Stop Suricata monitoring"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.monitoring = False
            logger.info("Stopped Suricata monitoring")
    
    def parse_eve_logs(self):
        """Parse Suricata EVE JSON logs"""
        if not os.path.exists(self.eve_log_path):
            logger.warning(f"EVE log file not found: {self.eve_log_path}")
            return
        
        with open(self.eve_log_path, 'r') as f:
            # Move to end of file
            f.seek(0, 2)
            
            while self.monitoring:
                line = f.readline()
                if line:
                    try:
                        event = json.loads(line)
                        self.process_event(event)
                    except json.JSONDecodeError:
                        continue
                else:
                    time.sleep(0.1)
    
    def process_event(self, event):
        """Process Suricata event"""
        event_type = event.get('event_type')
        
        if event_type == 'alert':
            self.process_alert(event)
        elif event_type == 'flow':
            self.process_flow(event)
        elif event_type == 'dns':
            self.process_dns(event)
        elif event_type == 'http':
            self.process_http(event)
    
    def process_alert(self, event):
        """Process Suricata alert"""
        alert_data = {
            'timestamp': event.get('timestamp'),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dest_ip'),
            'src_port': event.get('src_port'),
            'dst_port': event.get('dest_port'),
            'protocol': event.get('proto'),
            'signature': event.get('alert', {}).get('signature'),
            'category': event.get('alert', {}).get('category'),
            'severity': event.get('alert', {}).get('severity'),
            'payload': event.get('payload')
        }
        
        # Store in database
        db_manager.store_suricata_alert(alert_data)
        
        # Send real-time alert via WebSocket
        socketio.emit('suricata_alert', alert_data)
        
        # Check if auto-blocking is needed
        if alert_data['severity'] >= 3:
            threat_data = {
                'type': alert_data['category'],
                'src_ip': alert_data['src_ip'],
                'severity': alert_data['severity']
            }
            # Auto-block high severity threats
            if alert_data['src_ip']:
                rules_manager.add_to_blacklist(ip=alert_data['src_ip'])
                logger.warning(f"Auto-blocked IP {alert_data['src_ip']} due to high severity alert")
        
        logger.warning(f"Suricata Alert: {alert_data['signature']} - {alert_data['src_ip']} -> {alert_data['dst_ip']}")
    
    def process_flow(self, event):
        """Process network flow event"""
        flow_data = {
            'timestamp': event.get('timestamp'),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dest_ip'),
            'src_port': event.get('src_port'),
            'dst_port': event.get('dest_port'),
            'protocol': event.get('proto'),
            'bytes_toserver': event.get('flow', {}).get('bytes_toserver'),
            'bytes_toclient': event.get('flow', {}).get('bytes_toclient'),
            'state': event.get('flow', {}).get('state')
        }
        
        # Process and store flow data
        db_manager.store_flow(flow_data)
    
    def process_dns(self, event):
        """Process DNS event"""
        dns_data = {
            'timestamp': event.get('timestamp'),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dest_ip'),
            'query': event.get('dns', {}).get('query'),
            'type': event.get('dns', {}).get('type'),
            'answers': event.get('dns', {}).get('answers', [])
        }
        
        # Check for suspicious DNS queries
        self.check_dns_threats(dns_data)
    
    def process_http(self, event):
        """Process HTTP event"""
        http_data = {
            'timestamp': event.get('timestamp'),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dest_ip'),
            'method': event.get('http', {}).get('http_method'),
            'url': event.get('http', {}).get('url'),
            'hostname': event.get('http', {}).get('hostname'),
            'status': event.get('http', {}).get('status'),
            'length': event.get('http', {}).get('length')
        }
        
        # Analyze HTTP traffic
        self.analyze_http_traffic(http_data)
    
    def check_dns_threats(self, dns_data):
        """Check for DNS-based threats"""
        query = dns_data.get('query', '').lower()
        
        # Check against blacklisted domains
        for domain in rules_manager.blacklist_domains:
            if domain in query:
                alert = {
                    'severity': 'HIGH',
                    'message': f"Blacklisted DNS query detected: {query}",
                    'src_ip': dns_data['src_ip'],
                    'timestamp': dns_data['timestamp']
                }
                socketio.emit('threat_detected', alert)
                logger.warning(f"Blacklisted DNS query: {query}")
                break
    
    def analyze_http_traffic(self, http_data):
        """Analyze HTTP traffic for threats"""
        # Check for suspicious patterns
        suspicious_patterns = [
            '/admin', '/wp-admin', '/phpMyAdmin',
            '.php?cmd=', 'eval(', 'base64_decode'
        ]
        
        url = http_data.get('url', '')
        for pattern in suspicious_patterns:
            if pattern in url:
                alert = {
                    'severity': 'MEDIUM',
                    'message': f"Suspicious HTTP request: {url}",
                    'src_ip': http_data['src_ip'],
                    'dst_ip': http_data['dst_ip'],
                    'timestamp': http_data['timestamp']
                }
                socketio.emit('threat_detected', alert)
                break

class NetworkMonitor:
    """Main network monitoring class"""
    
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.local_networks = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
        self.packet_queue = deque(maxlen=10000)
        self.traffic_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'last_seen': None})
        self.connection_tracker = {}
        self.monitoring = False
        self.start_time = time.time()
        
    def is_local_ip(self, ip):
        """Check if IP is in local network"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.local_networks:
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except:
            pass
        return False
    
    def determine_direction(self, src_ip, dst_ip):
        """Determine traffic direction"""
        src_local = self.is_local_ip(src_ip)
        dst_local = self.is_local_ip(dst_ip)
        
        if src_local and not dst_local:
            return 'outbound'
        elif not src_local and dst_local:
            return 'inbound'
        elif src_local and dst_local:
            return 'internal'
        else:
            return 'external'
    
    def packet_callback(self, packet):
        """Process captured packets"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)
                
                # Check blacklist
                if src_ip in rules_manager.blacklist_ips or dst_ip in rules_manager.blacklist_ips:
                    logger.warning(f"Blacklisted IP detected in traffic: {src_ip} -> {dst_ip}")
                    socketio.emit('blacklisted_traffic', {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'timestamp': datetime.now().isoformat()
                    })
                
                direction = self.determine_direction(src_ip, dst_ip)
                
                # Skip external traffic
                if direction == 'external':
                    return
                
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': self.get_protocol_name(proto),
                    'size': size,
                    'direction': direction,
                    'src_port': None,
                    'dst_port': None,
                    'application': None
                }
                
                # Extract port information
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['application'] = self.identify_application(packet[TCP].dport)
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    packet_info['application'] = self.identify_application(packet[UDP].dport)
                
                # Process HTTP requests
                if HTTPRequest in packet:
                    self.process_http_request(packet)
                
                # Process DNS queries
                if DNS in packet and packet[DNS].qr == 0:
                    self.process_dns_query(packet)
                
                # Update statistics
                self.update_statistics(packet_info)
                
                # Store in queue
                self.packet_queue.append(packet_info)
                
                # Emit real-time update
                if len(self.packet_queue) % 10 == 0:
                    self.emit_traffic_update()
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def get_protocol_name(self, proto):
        """Get protocol name from number"""
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH'}
        return protocols.get(proto, f'Protocol-{proto}')
    
    def identify_application(self, port):
        """Identify application based on port"""
        common_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP',
            443: 'HTTPS', 445: 'SMB', 587: 'SMTP-TLS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        return common_ports.get(port, f'Port-{port}')
    
    def process_http_request(self, packet):
        """Process HTTP requests"""
        http = packet[HTTPRequest]
        http_info = {
            'timestamp': datetime.now(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'method': http.Method.decode() if http.Method else None,
            'host': http.Host.decode() if http.Host else None,
            'path': http.Path.decode() if http.Path else None,
            'user_agent': http.User_Agent.decode() if hasattr(http, 'User_Agent') else None
        }
        
        # Check for suspicious patterns
        self.check_http_threats(http_info)
        
        # Store HTTP request
        db_manager.store_http_request(http_info)
    
    def process_dns_query(self, packet):
        """Process DNS queries"""
        dns = packet[DNS]
        query = dns.qd.qname.decode() if dns.qd else None
        
        dns_info = {
            'timestamp': datetime.now(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'query': query,
            'type': dns.qd.qtype if dns.qd else None
        }
        
        # Check against blacklisted domains
        if query:
            for domain in rules_manager.blacklist_domains:
                if domain in query.lower():
                    threat = {
                        'type': 'DNS_BLACKLIST',
                        'severity': 'HIGH',
                        'description': f"DNS query to blacklisted domain: {query}",
                        'source': dns_info['src_ip'],
                        'timestamp': dns_info['timestamp'].isoformat()
                    }
                    socketio.emit('threat_detected', threat)
                    logger.warning(f"DNS query to blacklisted domain: {query}")
                    break
        
        # Store DNS query
        db_manager.store_dns_query(dns_info)
    
    def check_http_threats(self, http_info):
        """Check for HTTP-based threats"""
        suspicious_patterns = [
            'eval(', 'base64_decode', '<script', 'javascript:',
            '../', 'union select', 'drop table', 'exec('
        ]
        
        path = http_info.get('path', '').lower()
        for pattern in suspicious_patterns:
            if pattern in path:
                threat = {
                    'type': 'HTTP_THREAT',
                    'severity': 'HIGH',
                    'description': f"Suspicious HTTP pattern detected: {pattern}",
                    'source': http_info['src_ip'],
                    'destination': http_info['dst_ip'],
                    'timestamp': http_info['timestamp'].isoformat()
                }
                socketio.emit('threat_detected', threat)
                
                # Auto-block if severity is high
                rules_manager.add_to_blacklist(ip=http_info['src_ip'])
                logger.warning(f"Auto-blocked IP {http_info['src_ip']} due to HTTP threat")
                break
    
    def update_statistics(self, packet_info):
        """Update traffic statistics"""
        key = f"{packet_info['src_ip']}:{packet_info['dst_ip']}"
        self.traffic_stats[key]['bytes'] += packet_info['size']
        self.traffic_stats[key]['packets'] += 1
        self.traffic_stats[key]['last_seen'] = packet_info['timestamp']
        self.traffic_stats[key]['direction'] = packet_info['direction']
        self.traffic_stats[key]['protocol'] = packet_info['protocol']
        self.traffic_stats[key]['application'] = packet_info.get('application')
        
        # Store in database periodically
        if self.traffic_stats[key]['packets'] % 100 == 0:
            db_manager.store_traffic_stats(packet_info)
    
    def emit_traffic_update(self):
        """Emit traffic update via WebSocket"""
        recent_packets = list(self.packet_queue)[-20:]
        update_data = {
            'packets': [
                {
                    'timestamp': p['timestamp'].isoformat(),
                    'src_ip': p['src_ip'],
                    'dst_ip': p['dst_ip'],
                    'protocol': p['protocol'],
                    'size': p['size'],
                    'direction': p['direction'],
                    'application': p.get('application')
                }
                for p in recent_packets
            ],
            'stats': self.get_current_stats()
        }
        socketio.emit('traffic_update', update_data)
    
    def get_current_stats(self):
        """Get current traffic statistics"""
        total_bytes = sum(s['bytes'] for s in self.traffic_stats.values())
        total_packets = sum(s['packets'] for s in self.traffic_stats.values())
        
        # Direction breakdown
        direction_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        for stats in self.traffic_stats.values():
            direction = stats.get('direction', 'unknown')
            direction_stats[direction]['bytes']