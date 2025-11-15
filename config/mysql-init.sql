-- MySQL Initialization Script for Network Monitor
-- This script creates the necessary tables and indexes

-- Create database if not exists (should already exist from docker-compose)
CREATE DATABASE IF NOT EXISTS network_monitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE network_monitor;

-- Traffic statistics table
CREATE TABLE IF NOT EXISTS traffic_stats (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED,
    dst_port INT UNSIGNED,
    protocol VARCHAR(10),
    bytes_sent BIGINT UNSIGNED DEFAULT 0,
    packets_count INT UNSIGNED DEFAULT 1,
    direction VARCHAR(10),
    application VARCHAR(50),
    threat_level TINYINT UNSIGNED DEFAULT 0,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_protocol (protocol),
    INDEX idx_direction (direction),
    INDEX idx_threat_level (threat_level),
    INDEX idx_composite (timestamp, src_ip, dst_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Suricata alerts table
CREATE TABLE IF NOT EXISTS suricata_alerts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_time DATETIME NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED,
    dst_port INT UNSIGNED,
    protocol VARCHAR(10),
    signature VARCHAR(500),
    category VARCHAR(100),
    severity TINYINT UNSIGNED,
    payload TEXT,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_alert_time (alert_time),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_severity (severity),
    INDEX idx_category (category),
    INDEX idx_signature (signature(255)),
    INDEX idx_composite (alert_time, severity, src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Connection logs table
CREATE TABLE IF NOT EXISTS connection_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    connection_id VARCHAR(100) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED,
    dst_port INT UNSIGNED,
    protocol VARCHAR(10),
    state VARCHAR(20),
    duration FLOAT,
    bytes_to_server BIGINT UNSIGNED DEFAULT 0,
    bytes_to_client BIGINT UNSIGNED DEFAULT 0,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_connection_id (connection_id),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_state (state),
    INDEX idx_protocol (protocol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- DNS queries table
CREATE TABLE IF NOT EXISTS dns_queries (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    query VARCHAR(255) NOT NULL,
    query_type VARCHAR(10),
    response_code INT,
    answers TEXT,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_query (query),
    INDEX idx_query_type (query_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- HTTP requests table
CREATE TABLE IF NOT EXISTS http_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    method VARCHAR(10),
    host VARCHAR(255),
    path VARCHAR(1000),
    user_agent VARCHAR(500),
    status_code INT,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_host (host),
    INDEX idx_method (method),
    INDEX idx_status_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vallanx blocklist entries (for database storage)
CREATE TABLE IF NOT EXISTS vallanx_entries (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    value VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity TINYINT UNSIGNED NOT NULL,
    action VARCHAR(50) NOT NULL,
    confidence FLOAT DEFAULT 1.0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    source VARCHAR(100),
    tags JSON,
    metadata JSON,
    expire DATETIME,
    false_positive_reports INT UNSIGNED DEFAULT 0,
    hit_count BIGINT UNSIGNED DEFAULT 0,
    
    UNIQUE KEY unique_value_type (value, type),
    INDEX idx_type (type),
    INDEX idx_category (category),
    INDEX idx_severity (severity),
    INDEX idx_action (action),
    INDEX idx_source (source),
    INDEX idx_expire (expire),
    INDEX idx_hit_count (hit_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Statistics summary table (for dashboards)
CREATE TABLE IF NOT EXISTS traffic_summary (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    period_start DATETIME NOT NULL,
    period_end DATETIME NOT NULL,
    total_bytes BIGINT UNSIGNED DEFAULT 0,
    total_packets BIGINT UNSIGNED DEFAULT 0,
    unique_src_ips INT UNSIGNED DEFAULT 0,
    unique_dst_ips INT UNSIGNED DEFAULT 0,
    protocol_distribution JSON,
    direction_distribution JSON,
    top_talkers JSON,
    
    UNIQUE KEY unique_period (period_start),
    INDEX idx_period_start (period_start),
    INDEX idx_period_end (period_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Threat events table
CREATE TABLE IF NOT EXISTS threat_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_type VARCHAR(50) NOT NULL,
    severity TINYINT UNSIGNED NOT NULL,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    description TEXT,
    action_taken VARCHAR(50),
    blocked BOOLEAN DEFAULT FALSE,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_threat_type (threat_type),
    INDEX idx_severity (severity),
    INDEX idx_src_ip (src_ip),
    INDEX idx_blocked (blocked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User sessions table (for future authentication)
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL UNIQUE,
    user_id INT UNSIGNED,
    username VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at DATETIME,
    
    INDEX idx_session_id (session_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create views for common queries

-- View: Recent high severity alerts
CREATE OR REPLACE VIEW v_recent_high_alerts AS
SELECT 
    alert_time,
    src_ip,
    dst_ip,
    signature,
    category,
    severity
FROM suricata_alerts
WHERE 
    alert_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    AND severity >= 4
ORDER BY alert_time DESC;

-- View: Top traffic sources
CREATE OR REPLACE VIEW v_top_traffic_sources AS
SELECT 
    src_ip,
    COUNT(*) as connection_count,
    SUM(bytes_sent) as total_bytes,
    MAX(timestamp) as last_seen
FROM traffic_stats
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY src_ip
ORDER BY total_bytes DESC
LIMIT 100;

-- View: Vallanx blocklist summary
CREATE OR REPLACE VIEW v_vallanx_summary AS
SELECT 
    type,
    category,
    action,
    COUNT(*) as entry_count,
    SUM(hit_count) as total_hits
FROM vallanx_entries
WHERE expire IS NULL OR expire > NOW()
GROUP BY type, category, action;

-- Create stored procedures

DELIMITER $$

-- Procedure: Clean old data
CREATE PROCEDURE IF NOT EXISTS sp_cleanup_old_data(IN days_to_keep INT)
BEGIN
    DECLARE rows_deleted INT DEFAULT 0;
    
    -- Delete old traffic stats
    DELETE FROM traffic_stats 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET rows_deleted = ROW_COUNT();
    
    -- Delete old connection logs
    DELETE FROM connection_logs 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET rows_deleted = rows_deleted + ROW_COUNT();
    
    -- Delete old DNS queries
    DELETE FROM dns_queries 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET rows_deleted = rows_deleted + ROW_COUNT();
    
    -- Delete old HTTP requests
    DELETE FROM http_requests 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET rows_deleted = rows_deleted + ROW_COUNT();
    
    -- Delete expired Vallanx entries
    DELETE FROM vallanx_entries 
    WHERE expire IS NOT NULL AND expire < NOW();
    SET rows_deleted = rows_deleted + ROW_COUNT();
    
    -- Delete expired sessions
    DELETE FROM user_sessions 
    WHERE expires_at < NOW();
    SET rows_deleted = rows_deleted + ROW_COUNT();
    
    SELECT CONCAT('Deleted ', rows_deleted, ' old records') AS result;
END$$

-- Procedure: Generate traffic summary
CREATE PROCEDURE IF NOT EXISTS sp_generate_traffic_summary(IN summary_date DATE)
BEGIN
    INSERT INTO traffic_summary (
        period_start,
        period_end,
        total_bytes,
        total_packets,
        unique_src_ips,
        unique_dst_ips,
        protocol_distribution,
        direction_distribution
    )
    SELECT 
        DATE(summary_date) as period_start,
        DATE_ADD(DATE(summary_date), INTERVAL 1 DAY) as period_end,
        SUM(bytes_sent) as total_bytes,
        SUM(packets_count) as total_packets,
        COUNT(DISTINCT src_ip) as unique_src_ips,
        COUNT(DISTINCT dst_ip) as unique_dst_ips,
        JSON_OBJECTAGG(protocol, protocol_count) as protocol_distribution,
        JSON_OBJECTAGG(direction, direction_count) as direction_distribution
    FROM (
        SELECT 
            protocol,
            direction,
            COUNT(*) as protocol_count,
            COUNT(*) as direction_count
        FROM traffic_stats
        WHERE DATE(timestamp) = summary_date
        GROUP BY protocol, direction
    ) as stats
    ON DUPLICATE KEY UPDATE
        total_bytes = VALUES(total_bytes),
        total_packets = VALUES(total_packets),
        unique_src_ips = VALUES(unique_src_ips),
        unique_dst_ips = VALUES(unique_dst_ips);
END$$

DELIMITER ;

-- Grant permissions to monitor user
GRANT ALL PRIVILEGES ON network_monitor.* TO 'monitor_user'@'%';
FLUSH PRIVILEGES;

-- Insert initial data (optional)
INSERT INTO vallanx_entries (value, type, category, severity, action, source, tags) VALUES
('192.0.2.1', 'ip', 'malware', 5, 'block', 'initial_setup', '["example"]'),
('example-malware.com', 'domain', 'malware', 5, 'block', 'initial_setup', '["example"]')
ON DUPLICATE KEY UPDATE value=value;

-- Optimize tables
OPTIMIZE TABLE traffic_stats;
OPTIMIZE TABLE suricata_alerts;
OPTIMIZE TABLE connection_logs;
OPTIMIZE TABLE vallanx_entries;

-- Show table sizes
SELECT 
    table_name,
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS "Size (MB)"
FROM information_schema.tables
WHERE table_schema = 'network_monitor'
ORDER BY (data_length + index_length) DESC;

SELECT 'Database initialization completed successfully!' AS Status;
