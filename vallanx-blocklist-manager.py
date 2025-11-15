#!/usr/bin/env python3
"""
Vallanx Universal Blocklist Manager
Implements the Vallanx Universal Blocklist Syntax for Network Traffic Monitoring
Compatible with multiple security tools and formats
"""

import os
import re
import json
import yaml
import hashlib
import logging
import ipaddress
import tldextract
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

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
    JA3S = "ja3s"

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
    PUP = "pup"  # Potentially Unwanted Program
    ADWARE = "adware"
    TRACKING = "tracking"
    PORN = "pornography"
    GAMBLING = "gambling"
    PIRACY = "piracy"
    DRUGS = "drugs"
    VIOLENCE = "violence"
    HATE = "hate_speech"
    DDOS = "ddos"
    APT = "apt"  # Advanced Persistent Threat

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
    CHALLENGE = "challenge"  # CAPTCHA or similar
    SANDBOX = "sandbox"

@dataclass
class VallanxEntry:
    """Single entry in Vallanx blocklist"""
    value: str
    type: BlocklistType
    category: ThreatCategory
    severity: Severity
    action: Action
    confidence: float = 1.0  # 0.0 to 1.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    source: str = "manual"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expire: Optional[datetime] = None
    false_positive_reports: int = 0
    hit_count: int = 0
    
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
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'VallanxEntry':
        """Create from dictionary"""
        data = data.copy()
        data['type'] = BlocklistType(data['type'])
        data['category'] = ThreatCategory(data['category'])
        data['severity'] = Severity(data['severity'])
        data['action'] = Action(data['action'])
        data['first_seen'] = datetime.fromisoformat(data['first_seen'])
        data['last_seen'] = datetime.fromisoformat(data['last_seen'])
        if data.get('expire'):
            data['expire'] = datetime.fromisoformat(data['expire'])
        return cls(**data)

class VallanxBlocklistManager:
    """Manager for Vallanx Universal Blocklist"""
    
    def __init__(self, base_path: str = '/etc/vallanx'):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Separate storage for different types
        self.blocklists: Dict[BlocklistType, Set[VallanxEntry]] = {
            blocklist_type: set() for blocklist_type in BlocklistType
        }
        
        # Whitelists (exceptions)
        self.whitelists: Dict[BlocklistType, Set[VallanxEntry]] = {
            blocklist_type: set() for blocklist_type in BlocklistType
        }
        
        # Fast lookup caches
        self.ip_cache: Set[str] = set()
        self.domain_cache: Set[str] = set()
        self.cidr_networks: List[ipaddress.IPv4Network] = []
        self.regex_patterns: List[re.Pattern] = []
        
        # Configuration
        self.config = self.load_config()
        
        # Load existing lists
        self.load_all_lists()
        
        # Statistics
        self.stats = {
            'total_entries': 0,
            'blocks_today': 0,
            'false_positives': 0,
            'last_update': datetime.now()
        }
    
    def load_config(self) -> Dict:
        """Load Vallanx configuration"""
        config_file = self.base_path / 'vallanx.yaml'
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            # Create default config
            default_config = {
                'version': '1.0.0',
                'auto_expire_days': 90,
                'confidence_threshold': 0.7,
                'enable_auto_block': True,
                'enable_regex': True,
                'enable_wildcard': True,
                'max_entries': 1000000,
                'update_interval': 3600,
                'sources': [
                    {
                        'name': 'local',
                        'type': 'file',
                        'path': str(self.base_path / 'local.vbx')
                    }
                ],
                'export_formats': ['suricata', 'iptables', 'nginx', 'bind', 'json'],
                'api': {
                    'enabled': True,
                    'port': 8089,
                    'auth_required': True
                }
            }
            
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            
            return default_config
    
    def add_entry(self, value: str, type_str: str, category_str: str, 
                  severity: int = 3, action_str: str = "block", **kwargs) -> bool:
        """Add entry to blocklist using Vallanx syntax"""
        try:
            # Parse and validate entry type
            entry_type = BlocklistType(type_str.lower())
            
            # Validate value based on type
            if not self.validate_value(value, entry_type):
                logger.error(f"Invalid value {value} for type {entry_type}")
                return False
            
            # Create entry
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
            
            # Add to appropriate list
            self.blocklists[entry_type].add(entry)
            
            # Update caches
            self.update_caches(entry)
            
            # Log addition
            logger.info(f"Added {entry_type.value}: {value} to blocklist")
            
            # Save to disk
            self.save_list(entry_type)
            
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
                # Basic domain validation
                domain_regex = re.compile(
                    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
                    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                )
                return bool(domain_regex.match(value))
            
            elif entry_type == BlocklistType.URL:
                result = urlparse(value)
                return all([result.scheme, result.netloc])
            
            elif entry_type == BlocklistType.EMAIL:
                email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
                return bool(email_regex.match(value))
            
            elif entry_type == BlocklistType.HASH:
                # Support MD5, SHA1, SHA256, SHA512
                hash_lengths = [32, 40, 64, 128]
                return len(value) in hash_lengths and all(c in '0123456789abcdef' for c in value.lower())
            
            elif entry_type == BlocklistType.ASN:
                # AS number validation
                return value.upper().startswith('AS') and value[2:].isdigit()
            
            elif entry_type == BlocklistType.PORT:
                port = int(value)
                return 0 <= port <= 65535
            
            elif entry_type == BlocklistType.REGEX:
                re.compile(value)
                return True
            
            elif entry_type == BlocklistType.JA3:
                # JA3 fingerprint format
                return len(value) == 32 and all(c in '0123456789abcdef' for c in value.lower())
            
            else:
                # For other types, basic validation
                return bool(value)
                
        except:
            return False
    
    def normalize_value(self, value: str, entry_type: BlocklistType) -> str:
        """Normalize value for consistent storage"""
        if entry_type == BlocklistType.DOMAIN:
            return value.lower().strip('.')
        elif entry_type == BlocklistType.EMAIL:
            return value.lower()
        elif entry_type == BlocklistType.HASH:
            return value.lower()
        elif entry_type == BlocklistType.URL:
            return value.lower()
        else:
            return value
    
    def update_caches(self, entry: VallanxEntry):
        """Update fast lookup caches"""
        if entry.type == BlocklistType.IP:
            self.ip_cache.add(entry.value)
        elif entry.type == BlocklistType.DOMAIN:
            self.domain_cache.add(entry.value)
        elif entry.type == BlocklistType.CIDR:
            self.cidr_networks.append(ipaddress.ip_network(entry.value))
        elif entry.type == BlocklistType.REGEX:
            self.regex_patterns.append(re.compile(entry.value))
    
    def check(self, value: str, check_type: Optional[BlocklistType] = None) -> Optional[VallanxEntry]:
        """Check if value is in blocklist"""
        # Auto-detect type if not specified
        if not check_type:
            check_type = self.detect_type(value)
        
        # Quick cache lookups
        if check_type == BlocklistType.IP and value in self.ip_cache:
            return self.get_entry(value, BlocklistType.IP)
        
        if check_type == BlocklistType.DOMAIN:
            # Check exact match and parent domains
            domain = value.lower()
            while domain:
                if domain in self.domain_cache:
                    return self.get_entry(domain, BlocklistType.DOMAIN)
                # Check parent domain
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
        
        # Check regex patterns
        for pattern in self.regex_patterns:
            if pattern.match(value):
                # Find the corresponding entry
                for entry in self.blocklists[BlocklistType.REGEX]:
                    if entry.value == pattern.pattern:
                        return entry
        
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
        # Try IP first
        try:
            ipaddress.ip_address(value)
            return BlocklistType.IP
        except:
            pass
        
        # Try CIDR
        try:
            ipaddress.ip_network(value)
            return BlocklistType.CIDR
        except:
            pass
        
        # Check if URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return BlocklistType.URL
        
        # Check if email
        if '@' in value and '.' in value.split('@')[1]:
            return BlocklistType.EMAIL
        
        # Check if hash
        if len(value) in [32, 40, 64, 128] and all(c in '0123456789abcdef' for c in value.lower()):
            return BlocklistType.HASH
        
        # Check if ASN
        if value.upper().startswith('AS') and value[2:].isdigit():
            return BlocklistType.ASN
        
        # Default to domain
        if '.' in value:
            return BlocklistType.DOMAIN
        
        return None
    
    def export_suricata_rules(self) -> str:
        """Export blocklist as Suricata rules"""
        rules = []
        sid = 1000000
        
        # IP rules
        for entry in self.blocklists[BlocklistType.IP]:
            action = "drop" if entry.action == Action.BLOCK else "alert"
            rules.append(
                f'{action} ip {entry.value} any -> any any '
                f'(msg:"VALLANX: {entry.category.value} - {entry.value}"; '
                f'classtype:{entry.category.value}; '
                f'priority:{6 - entry.severity.value}; '
                f'sid:{sid}; rev:1;)'
            )
            sid += 1
        
        # Domain rules
        for entry in self.blocklists[BlocklistType.DOMAIN]:
            action = "drop" if entry.action == Action.BLOCK else "alert"
            rules.append(
                f'{action} dns any any -> any 53 '
                f'(msg:"VALLANX: DNS query for {entry.category.value} domain {entry.value}"; '
                f'dns.query; content:"{entry.value}"; nocase; '
                f'classtype:{entry.category.value}; '
                f'priority:{6 - entry.severity.value}; '
                f'sid:{sid}; rev:1;)'
            )
            sid += 1
        
        # CIDR rules
        for entry in self.blocklists[BlocklistType.CIDR]:
            action = "drop" if entry.action == Action.BLOCK else "alert"
            rules.append(
                f'{action} ip {entry.value} any -> any any '
                f'(msg:"VALLANX: {entry.category.value} network {entry.value}"; '
                f'classtype:{entry.category.value}; '
                f'priority:{6 - entry.severity.value}; '
                f'sid:{sid}; rev:1;)'
            )
            sid += 1
        
        return '\n'.join(rules)
    
    def export_iptables_rules(self) -> str:
        """Export blocklist as iptables rules"""
        rules = []
        
        # IP rules
        for entry in self.blocklists[BlocklistType.IP]:
            if entry.action == Action.BLOCK:
                rules.append(f'iptables -A INPUT -s {entry.value} -j DROP')
                rules.append(f'iptables -A OUTPUT -d {entry.value} -j DROP')
        
        # CIDR rules
        for entry in self.blocklists[BlocklistType.CIDR]:
            if entry.action == Action.BLOCK:
                rules.append(f'iptables -A INPUT -s {entry.value} -j DROP')
                rules.append(f'iptables -A OUTPUT -d {entry.value} -j DROP')
        
        # Port rules
        for entry in self.blocklists[BlocklistType.PORT]:
            if entry.action == Action.BLOCK:
                rules.append(f'iptables -A INPUT -p tcp --dport {entry.value} -j DROP')
                rules.append(f'iptables -A INPUT -p udp --dport {entry.value} -j DROP')
        
        return '\n'.join(rules)
    
    def export_nginx_deny(self) -> str:
        """Export blocklist as nginx deny rules"""
        rules = []
        
        # IP rules
        for entry in self.blocklists[BlocklistType.IP]:
            if entry.action == Action.BLOCK:
                rules.append(f'deny {entry.value};')
        
        # CIDR rules
        for entry in self.blocklists[BlocklistType.CIDR]:
            if entry.action == Action.BLOCK:
                rules.append(f'deny {entry.value};')
        
        # User-Agent rules
        for entry in self.blocklists[BlocklistType.USER_AGENT]:
            if entry.action == Action.BLOCK:
                rules.append(f'if ($http_user_agent ~* "{entry.value}") {{ return 403; }}')
        
        return '\n'.join(rules)
    
    def export_bind_rpz(self) -> str:
        """Export blocklist as BIND RPZ (Response Policy Zone)"""
        rpz = []
        rpz.append('$TTL 300')
        rpz.append('@ IN SOA localhost. root.localhost. (')
        rpz.append(f'    {datetime.now().strftime("%Y%m%d")}01 ; Serial')
        rpz.append('    3600       ; Refresh')
        rpz.append('    300        ; Retry')
        rpz.append('    604800     ; Expire')
        rpz.append('    300 )      ; Negative Cache TTL')
        rpz.append('')
        rpz.append('@ IN NS localhost.')
        rpz.append('')
        
        # Domain rules
        for entry in self.blocklists[BlocklistType.DOMAIN]:
            if entry.action == Action.BLOCK:
                rpz.append(f'{entry.value} CNAME .')
                rpz.append(f'*.{entry.value} CNAME .')
        
        return '\n'.join(rpz)
    
    def export_json(self) -> str:
        """Export blocklist as JSON"""
        export_data = {
            'version': self.config['version'],
            'exported': datetime.now().isoformat(),
            'stats': self.stats,
            'entries': []
        }
        
        for blocklist_type in BlocklistType:
            for entry in self.blocklists[blocklist_type]:
                export_data['entries'].append(entry.to_dict())
        
        return json.dumps(export_data, indent=2)
    
    def import_vallanx_format(self, data: str) -> int:
        """Import Vallanx format blocklist"""
        imported = 0
        
        for line in data.strip().split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse Vallanx syntax: type:value|category|severity|action|tags|metadata
            parts = line.split('|')
            if len(parts) < 3:
                continue
            
            type_value = parts[0].split(':', 1)
            if len(type_value) != 2:
                continue
            
            entry_type, value = type_value
            category = parts[1]
            severity = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 3
            action = parts[3] if len(parts) > 3 else 'block'
            tags = parts[4].split(',') if len(parts) > 4 else []
            metadata = json.loads(parts[5]) if len(parts) > 5 else {}
            
            if self.add_entry(value, entry_type, category, severity, action, 
                            tags=tags, metadata=metadata):
                imported += 1
        
        logger.info(f"Imported {imported} entries from Vallanx format")
        return imported
    
    def save_list(self, list_type: BlocklistType):
        """Save specific blocklist to disk"""
        filename = self.base_path / f'{list_type.value}.vbx'
        
        with open(filename, 'w') as f:
            f.write(f'# Vallanx Universal Blocklist - {list_type.value}\n')
            f.write(f'# Generated: {datetime.now().isoformat()}\n')
            f.write(f'# Format: type:value|category|severity|action|tags|metadata\n\n')
            
            for entry in self.blocklists[list_type]:
                tags_str = ','.join(entry.tags)
                metadata_str = json.dumps(entry.metadata)
                f.write(
                    f'{list_type.value}:{entry.value}|'
                    f'{entry.category.value}|'
                    f'{entry.severity.value}|'
                    f'{entry.action.value}|'
                    f'{tags_str}|'
                    f'{metadata_str}\n'
                )
    
    def load_all_lists(self):
        """Load all blocklists from disk"""
        for vbx_file in self.base_path.glob('*.vbx'):
            try:
                with open(vbx_file, 'r') as f:
                    self.import_vallanx_format(f.read())
                logger.info(f"Loaded blocklist from {vbx_file}")
            except Exception as e:
                logger.error(f"Error loading {vbx_file}: {e}")
    
    def cleanup_expired(self):
        """Remove expired entries"""
        now = datetime.now()
        removed = 0
        
        for blocklist_type in BlocklistType:
            expired = [
                entry for entry in self.blocklists[blocklist_type]
                if entry.expire and entry.expire < now
            ]
            
            for entry in expired:
                self.blocklists[blocklist_type].remove(entry)
                removed += 1
        
        if removed > 0:
            logger.info(f"Removed {removed} expired entries")
            self.rebuild_caches()
    
    def rebuild_caches(self):
        """Rebuild fast lookup caches"""
        self.ip_cache.clear()
        self.domain_cache.clear()
        self.cidr_networks.clear()
        self.regex_patterns.clear()
        
        for blocklist_type in BlocklistType:
            for entry in self.blocklists[blocklist_type]:
                self.update_caches(entry)
    
    def get_statistics(self) -> Dict:
        """Get blocklist statistics"""
        stats = {
            'total_entries': sum(len(self.blocklists[t]) for t in BlocklistType),
            'by_type': {t.value: len(self.blocklists[t]) for t in BlocklistType},
            'by_category': {},
            'by_severity': {},
            'by_action': {},
            'top_sources': {},
            'recent_additions': [],
            'high_false_positives': []
        }
        
        # Aggregate statistics
        for blocklist_type in BlocklistType:
            for entry in self.blocklists[blocklist_type]:
                # By category
                cat = entry.category.value
                stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
                
                # By severity
                sev = f'severity_{entry.severity.value}'
                stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1
                
                # By action
                act = entry.action.value
                stats['by_action'][act] = stats['by_action'].get(act, 0) + 1
                
                # By source
                src = entry.source
                stats['top_sources'][src] = stats['top_sources'].get(src, 0) + 1
                
                # High false positives
                if entry.false_positive_reports > 5:
                    stats['high_false_positives'].append({
                        'value': entry.value,
                        'type': entry.type.value,
                        'reports': entry.false_positive_reports
                    })
        
        # Sort and limit
        stats['top_sources'] = dict(sorted(
            stats['top_sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])
        
        stats['high_false_positives'] = sorted(
            stats['high_false_positives'],
            key=lambda x: x['reports'],
            reverse=True
        )[:10]
        
        return stats


# Integration with Network Monitor
class VallanxNetworkIntegration:
    """Integration layer for Vallanx with Network Monitor"""
    
    def __init__(self, vallanx_manager: VallanxBlocklistManager):
        self.vallanx = vallanx_manager
        self.check_cache = {}  # Cache recent checks
        self.cache_ttl = 300  # 5 minutes
        
    def check_packet(self, src_ip: str, dst_ip: str, src_port: int = None, 
                     dst_port: int = None, domain: str = None) -> Optional[Dict]:
        """Check packet against Vallanx blocklist"""
        results = []
        
        # Check source IP
        if src_ip:
            entry = self.vallanx.check(src_ip, BlocklistType.IP)
            if entry:
                results.append({
                    'match': 'source_ip',
                    'value': src_ip,
                    'entry': entry
                })
        
        # Check destination IP
        if dst_ip:
            entry = self.vallanx.check(dst_ip, BlocklistType.IP)
            if entry:
                results.append({
                    'match': 'destination_ip',
                    'value': dst_ip,
                    'entry': entry
                })
        
        # Check domain if provided
        if domain:
            entry = self.vallanx.check(domain, BlocklistType.DOMAIN)
            if entry:
                results.append({
                    'match': 'domain',
                    'value': domain,
                    'entry': entry
                })
        
        # Check ports if provided
        if src_port:
            entry = self.vallanx.check(str(src_port), BlocklistType.PORT)
            if entry:
                results.append({
                    'match': 'source_port',
                    'value': src_port,
                    'entry': entry
                })
        
        if dst_port:
            entry = self.vallanx.check(str(dst_port), BlocklistType.PORT)
            if entry:
                results.append({
                    'match': 'destination_port',
                    'value': dst_port,
                    'entry': entry
                })
        
        # Return highest severity match
        if results:
            return max(results, key=lambda x: x['entry'].severity.value)
        
        return None
    
    def process_threat(self, threat_data: Dict) -> bool:
        """Process detected threat and add to Vallanx blocklist"""
        # Extract threat information
        threat_type = threat_data.get('type', 'unknown')
        src_ip = threat_data.get('src_ip')
        dst_ip = threat_data.get('dst_ip')
        domain = threat_data.get('domain')
        severity = threat_data.get('severity', 3)
        
        added = False
        
        # Map threat type to Vallanx category
        category_map = {
            'port_scan': ThreatCategory.EXPLOIT,
            'brute_force': ThreatCategory.EXPLOIT,
            'sql_injection': ThreatCategory.EXPLOIT,
            'malware': ThreatCategory.MALWARE,
            'phishing': ThreatCategory.PHISHING,
            'c2': ThreatCategory.C2,
            'ddos': ThreatCategory.DDOS,
            'spam': ThreatCategory.SPAM
        }
        
        category = category_map.get(threat_type, ThreatCategory.MALWARE)
        
        # Add source IP if it's the attacker
        if src_ip and threat_type in ['port_scan', 'brute_force', 'sql_injection', 'ddos']:
            if self.vallanx.add_entry(
                value=src_ip,
                type_str='ip',
                category_str=category.value,
                severity=severity,
                action_str='block',
                source='auto_detection',
                tags=[threat_type, 'auto_blocked'],
                metadata={'threat_type': threat_type, 'detection_time': datetime.now().isoformat()}
            ):
                added = True
                logger.info(f"Auto-blocked IP {src_ip} due to {threat_type}")
        
        # Add malicious domain
        if domain and threat_type in ['phishing', 'malware', 'c2']:
            if self.vallanx.add_entry(
                value=domain,
                type_str='domain',
                category_str=category.value,
                severity=severity,
                action_str='block',
                source='auto_detection',
                tags=[threat_type, 'auto_blocked'],
                metadata={'threat_type': threat_type, 'detection_time': datetime.now().isoformat()}
            ):
                added = True
                logger.info(f"Auto-blocked domain {domain} due to {threat_type}")
        
        return added
    
    def export_for_suricata(self) -> str:
        """Export Vallanx blocklist as Suricata rules"""
        return self.vallanx.export_suricata_rules()
    
    def export_for_iptables(self) -> str:
        """Export Vallanx blocklist as iptables rules"""
        return self.vallanx.export_iptables_rules()
    
    def get_action_for_match(self, entry: VallanxEntry) -> str:
        """Determine action to take based on Vallanx entry"""
        action_map = {
            Action.BLOCK: 'drop',
            Action.ALLOW: 'pass',
            Action.MONITOR: 'alert',
            Action.REDIRECT: 'redirect',
            Action.QUARANTINE: 'quarantine',
            Action.ALERT: 'alert',
            Action.LOG: 'log',
            Action.RATE_LIMIT: 'rate_limit',
            Action.CHALLENGE: 'challenge',
            Action.SANDBOX: 'sandbox'
        }
        return action_map.get(entry.action, 'alert')


class VallanxAPIServer:
    """REST API server for Vallanx blocklist management"""
    
    def __init__(self, vallanx_manager: VallanxBlocklistManager, app):
        self.vallanx = vallanx_manager
        self.app = app
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes for Vallanx API"""
        
        @self.app.route('/api/vallanx/check', methods=['POST'])
        def vallanx_check():
            """Check if value is in blocklist"""
            data = request.json
            value = data.get('value')
            check_type = data.get('type')
            
            if not value:
                return jsonify({'error': 'No value provided'}), 400
            
            # Convert type string to enum if provided
            if check_type:
                try:
                    check_type = BlocklistType(check_type)
                except:
                    return jsonify({'error': f'Invalid type: {check_type}'}), 400
            
            # Check blocklist
            entry = self.vallanx.check(value, check_type)
            
            if entry:
                return jsonify({
                    'blocked': True,
                    'entry': entry.to_dict()
                })
            else:
                return jsonify({
                    'blocked': False
                })
        
        @self.app.route('/api/vallanx/add', methods=['POST'])
        def vallanx_add():
            """Add entry to blocklist"""
            data = request.json
            
            required = ['value', 'type', 'category']
            if not all(k in data for k in required):
                return jsonify({'error': 'Missing required fields: value, type, category'}), 400
            
            success = self.vallanx.add_entry(
                value=data['value'],
                type_str=data['type'],
                category_str=data['category'],
                severity=data.get('severity', 3),
                action_str=data.get('action', 'block'),
                confidence=data.get('confidence', 1.0),
                source=data.get('source', 'api'),
                tags=data.get('tags', []),
                metadata=data.get('metadata', {})
            )
            
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
        
        @self.app.route('/api/vallanx/remove', methods=['DELETE'])
        def vallanx_remove():
            """Remove entry from blocklist"""
            data = request.json
            value = data.get('value')
            entry_type = data.get('type')
            
            if not value or not entry_type:
                return jsonify({'error': 'Both value and type required'}), 400
            
            try:
                entry_type = BlocklistType(entry_type)
                
                # Find and remove entry
                for entry in self.vallanx.blocklists[entry_type]:
                    if entry.value == value:
                        self.vallanx.blocklists[entry_type].remove(entry)
                        self.vallanx.save_list(entry_type)
                        self.vallanx.rebuild_caches()
                        
                        return jsonify({
                            'success': True,
                            'message': f"Removed {value} from blocklist"
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
        
        @self.app.route('/api/vallanx/stats', methods=['GET'])
        def vallanx_stats():
            """Get blocklist statistics"""
            return jsonify(self.vallanx.get_statistics())
        
        @self.app.route('/api/vallanx/export/<format>', methods=['GET'])
        def vallanx_export(format):
            """Export blocklist in specified format"""
            format = format.lower()
            
            if format == 'suricata':
                content = self.vallanx.export_suricata_rules()
                mimetype = 'text/plain'
                filename = 'vallanx.rules'
            elif format == 'iptables':
                content = self.vallanx.export_iptables_rules()
                mimetype = 'text/plain'
                filename = 'vallanx.sh'
            elif format == 'nginx':
                content = self.vallanx.export_nginx_deny()
                mimetype = 'text/plain'
                filename = 'vallanx-deny.conf'
            elif format == 'bind':
                content = self.vallanx.export_bind_rpz()
                mimetype = 'text/plain'
                filename = 'vallanx.rpz'
            elif format == 'json':
                content = self.vallanx.export_json()
                mimetype = 'application/json'
                filename = 'vallanx.json'
            else:
                return jsonify({'error': f'Unsupported format: {format}'}), 400
            
            return content, 200, {
                'Content-Type': mimetype,
                'Content-Disposition': f'attachment; filename={filename}'
            }
        
        @self.app.route('/api/vallanx/import', methods=['POST'])
        def vallanx_import():
            """Import blocklist data"""
            if 'file' in request.files:
                # File upload
                file = request.files['file']
                content = file.read().decode('utf-8')
            elif 'data' in request.json:
                # Direct data
                content = request.json['data']
            else:
                return jsonify({'error': 'No data provided'}), 400
            
            imported = self.vallanx.import_vallanx_format(content)
            
            return jsonify({
                'success': True,
                'imported': imported
            })
        
        @self.app.route('/api/vallanx/search', methods=['GET'])
        def vallanx_search():
            """Search blocklist entries"""
            query = request.args.get('q', '')
            entry_type = request.args.get('type')
            category = request.args.get('category')
            severity = request.args.get('severity')
            limit = int(request.args.get('limit', 100))
            
            results = []
            
            for blocklist_type in BlocklistType:
                # Filter by type if specified
                if entry_type and blocklist_type.value != entry_type:
                    continue
                
                for entry in self.vallanx.blocklists[blocklist_type]:
                    # Filter by query
                    if query and query.lower() not in entry.value.lower():
                        continue
                    
                    # Filter by category
                    if category and entry.category.value != category:
                        continue
                    
                    # Filter by severity
                    if severity and entry.severity.value != int(severity):
                        continue
                    
                    results.append(entry.to_dict())
                    
                    if len(results) >= limit:
                        break
                
                if len(results) >= limit:
                    break
            
            return jsonify({
                'results': results,
                'count': len(results)
            })
        
        @self.app.route('/api/vallanx/report-false-positive', methods=['POST'])
        def report_false_positive():
            """Report a false positive"""
            data = request.json
            value = data.get('value')
            entry_type = data.get('type')
            
            if not value or not entry_type:
                return jsonify({'error': 'Both value and type required'}), 400
            
            try:
                entry_type = BlocklistType(entry_type)
                
                # Find entry and increment false positive counter
                for entry in self.vallanx.blocklists[entry_type]:
                    if entry.value == value:
                        entry.false_positive_reports += 1
                        
                        # Auto-remove if too many false positives
                        if entry.false_positive_reports > 10:
                            self.vallanx.blocklists[entry_type].remove(entry)
                            message = f"Removed {value} due to high false positive reports"
                        else:
                            message = f"Reported false positive for {value} ({entry.false_positive_reports} reports)"
                        
                        self.vallanx.save_list(entry_type)
                        
                        return jsonify({
                            'success': True,
                            'message': message,
                            'reports': entry.false_positive_reports
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
        
        @self.app.route('/api/vallanx/bulk-add', methods=['POST'])
        def vallanx_bulk_add():
            """Bulk add entries to blocklist"""
            data = request.json
            entries = data.get('entries', [])
            
            if not entries:
                return jsonify({'error': 'No entries provided'}), 400
            
            added = 0
            failed = 0
            
            for entry_data in entries:
                try:
                    success = self.vallanx.add_entry(
                        value=entry_data['value'],
                        type_str=entry_data['type'],
                        category_str=entry_data['category'],
                        severity=entry_data.get('severity', 3),
                        action_str=entry_data.get('action', 'block'),
                        confidence=entry_data.get('confidence', 1.0),
                        source=entry_data.get('source', 'bulk_import'),
                        tags=entry_data.get('tags', []),
                        metadata=entry_data.get('metadata', {})
                    )
                    
                    if success:
                        added += 1
                    else:
                        failed += 1
                except:
                    failed += 1
            
            return jsonify({
                'success': True,
                'added': added,
                'failed': failed
            })
        
        @self.app.route('/api/vallanx/cleanup', methods=['POST'])
        def vallanx_cleanup():
            """Cleanup expired entries"""
            self.vallanx.cleanup_expired()
            return jsonify({
                'success': True,
                'message': 'Expired entries cleaned up'
            })


# Example Vallanx blocklist format file
EXAMPLE_VALLANX_BLOCKLIST = """
# Vallanx Universal Blocklist Format
# Format: type:value|category|severity|action|tags|metadata
# Types: ip, domain, url, email, hash, cidr, asn, regex, wildcard, tld, port, protocol, user_agent, ssl_fingerprint, ja3, ja3s
# Categories: malware, phishing, ransomware, botnet, command_control, cryptominer, exploit, spam, scam, pup, adware, tracking, pornography, gambling, piracy, drugs, violence, hate_speech, ddos, apt
# Severity: 1-5 (1=info, 2=low, 3=medium, 4=high, 5=critical)
# Actions: block, allow, monitor, redirect, quarantine, alert, log, rate_limit, challenge, sandbox

# IP addresses
ip:192.0.2.1|malware|5|block|zeus,trojan|{"source":"threatfeed1","confidence":0.95}
ip:198.51.100.5|botnet|4|block|mirai|{"source":"honeypot","first_seen":"2024-01-01"}
ip:203.0.113.10|phishing|4|block|phishing_kit|{"target":"banking"}

# CIDR ranges
cidr:192.0.2.0/24|malware|4|block|malware_hosting|{"asn":"AS12345"}
cidr:198.51.100.0/24|botnet|5|block|botnet_c2|{"country":"XX"}

# Domains
domain:evil.com|malware|5|block|emotet|{"dga":false}
domain:phishing-site.net|phishing|4|block|credential_harvesting|{"target":"microsoft"}
domain:malware-c2.org|command_control|5|block|cobalt_strike|{"port":443}

# Wildcard domains
wildcard:*.evil.com|malware|5|block|malware_family|{}
wildcard:*.tk|spam|2|monitor|suspicious_tld|{}

# URLs
url:http://evil.com/malware.exe|malware|5|block|dropper|{"md5":"abc123"}
url:https://phishing.net/login|phishing|4|block|fake_login|{"target":"paypal"}

# Email addresses
email:spammer@evil.com|spam|3|block|spam_source|{"reports":50}
email:phisher@malicious.net|phishing|4|block|phishing_sender|{}

# File hashes
hash:d41d8cd98f00b204e9800998ecf8427e|malware|5|block|known_malware|{"family":"ransomware"}
hash:e3b0c44298fc1c149afbf4c8996fb924|malware|4|block|trojan|{"variant":"zeus"}

# ASN
asn:AS12345|malware|3|monitor|malware_hosting_asn|{"country":"XX"}
asn:AS67890|spam|2|rate_limit|spam_network|{}

# Ports
port:4444|exploit|4|block|metasploit_default|{}
port:6667|botnet|3|monitor|irc_c2|{}

# User agents
user_agent:BadBot/1.0|bot|3|block|malicious_bot|{}
user_agent:sqlmap|exploit|4|block|sql_injection_tool|{}

# Regular expressions
regex:.*\.exe$|malware|3|monitor|executable_files|{}
regex:(union|select|from|where).*\d+=\d+|exploit|4|block|sql_injection|{}

# JA3 fingerprints
ja3:769,47-53,0-35-16,0-11-10,|malware|4|block|malware_tls_fingerprint|{"family":"trickbot"}

# SSL fingerprints
ssl_fingerprint:aa:bb:cc:dd:ee:ff|phishing|4|block|phishing_cert|{"cn":"*.phishing.com"}
"""


if __name__ == "__main__":
    # Example usage
    import tempfile
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize Vallanx manager
        vallanx = VallanxBlocklistManager(base_path=tmpdir)
        
        # Import example blocklist
        imported = vallanx.import_vallanx_format(EXAMPLE_VALLANX_BLOCKLIST)
        print(f"Imported {imported} entries")
        
        # Test checking
        test_values = [
            "192.0.2.1",          # Should be blocked (IP)
            "evil.com",           # Should be blocked (domain)
            "sub.evil.com",       # Should be blocked (wildcard)
            "8.8.8.8",           # Should not be blocked
            "google.com"          # Should not be blocked
        ]
        
        for value in test_values:
            result = vallanx.check(value)
            if result:
                print(f"✗ BLOCKED: {value} - {result.category.value} ({result.severity.value})")
            else:
                print(f"✓ ALLOWED: {value}")
        
        # Export as Suricata rules
        rules = vallanx.export_suricata_rules()
        print(f"\nGenerated {len(rules.split(chr(10)))} Suricata rules")
        
        # Get statistics
        stats = vallanx.get_statistics()
        print(f"\nStatistics:")
        print(f"  Total entries: {stats['total_entries']}")
        print(f"  By type: {stats['by_type']}")
        print(f"  By category: {stats['by_category']}")
