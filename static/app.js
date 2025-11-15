// Vallanx Network Monitor - Frontend JavaScript

// ===== Global Variables =====
let socket;
let trafficChart, directionChart, protocolChart, talkersChart, categoryChart, blockedChart;
let startTime = Date.now();

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    initializeCharts();
    initializeEventListeners();
    loadInitialData();
    startUptimeCounter();
});

// ===== Socket.IO =====
function initializeSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to server');
        updateConnectionStatus(true);
        showToast('Verbindung hergestellt', 'success');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        updateConnectionStatus(false);
        showToast('Verbindung getrennt', 'error');
    });
    
    // Traffic updates
    socket.on('traffic_update', function(data) {
        updateTrafficData(data);
    });
    
    // Threat detected
    socket.on('threat_detected', function(data) {
        displayThreat(data);
    });
    
    // Vallanx alert
    socket.on('vallanx_alert', function(data) {
        displayVallanxAlert(data);
    });
    
    // Suricata alert
    socket.on('suricata_alert', function(data) {
        displaySuricataAlert(data);
    });
    
    // Blacklist updated
    socket.on('blacklist_updated', function(data) {
        loadBlacklist();
        showToast(`Blacklist aktualisiert: ${data.action}`, 'info');
    });
    
    // Whitelist updated
    socket.on('whitelist_updated', function(data) {
        loadWhitelist();
        showToast(`Whitelist aktualisiert: ${data.action}`, 'info');
    });
    
    // Stats update
    socket.on('stats_update', function(data) {
        updateStats(data);
    });
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connectionStatus');
    if (connected) {
        statusEl.innerHTML = '<i class="fas fa-circle"></i> Verbunden';
        statusEl.style.color = '#10b981';
    } else {
        statusEl.innerHTML = '<i class="fas fa-circle"></i> Getrennt';
        statusEl.style.color = '#ef4444';
    }
}

// ===== Charts =====
function initializeCharts() {
    const chartConfig = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                labels: { color: '#f1f5f9' }
            }
        },
        scales: {
            y: {
                ticks: { color: '#94a3b8' },
                grid: { color: '#475569' }
            },
            x: {
                ticks: { color: '#94a3b8' },
                grid: { color: '#475569' }
            }
        }
    };
    
    // Traffic Over Time Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/s',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4
            }]
        },
        options: chartConfig
    });
    
    // Direction Chart
    const directionCtx = document.getElementById('directionChart').getContext('2d');
    directionChart = new Chart(directionCtx, {
        type: 'doughnut',
        data: {
            labels: ['Inbound', 'Outbound', 'Internal'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#3b82f6', '#10b981', '#f59e0b']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#f1f5f9' } }
            }
        }
    });
    
    // Protocol Chart
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: '#2563eb'
            }]
        },
        options: chartConfig
    });
    
    // Top Talkers Chart
    const talkersCtx = document.getElementById('talkersChart').getContext('2d');
    talkersChart = new Chart(talkersCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Bytes',
                data: [],
                backgroundColor: '#10b981'
            }]
        },
        options: chartConfig
    });
    
    // Category Chart
    const categoryCtx = document.getElementById('categoryChart').getContext('2d');
    categoryChart = new Chart(categoryCtx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#f1f5f9' } }
            }
        }
    });
    
    // Blocked Chart
    const blockedCtx = document.getElementById('blockedChart').getContext('2d');
    blockedChart = new Chart(blockedCtx, {
        type: 'doughnut',
        data: {
            labels: ['Blocked', 'Allowed'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#ef4444', '#10b981']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#f1f5f9' } }
            }
        }
    });
}

// ===== Event Listeners =====
function initializeEventListeners() {
    // Tab navigation
    document.querySelectorAll('.nav-item a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const tabId = this.dataset.tab;
            switchTab(tabId);
        });
    });
    
    // Vallanx form
    const vallanxForm = document.getElementById('vallanxAddForm');
    if (vallanxForm) {
        vallanxForm.addEventListener('submit', function(e) {
            e.preventDefault();
            addVallanxEntry();
        });
    }
}

// ===== Tab Switching =====
function switchTab(tabId) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector(`[data-tab="${tabId}"]`).parentElement.classList.add('active');
    
    // Update content
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`${tabId}-tab`).classList.add('active');
    
    // Load data for specific tab
    switch(tabId) {
        case 'vallanx':
            loadVallanxStats();
            break;
        case 'blacklist':
            loadBlacklist();
            loadWhitelist();
            break;
        case 'statistics':
            loadStats(24);
            break;
    }
}

// ===== Load Initial Data =====
function loadInitialData() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => updateStats(data))
        .catch(error => console.error('Error loading stats:', error));
    
    loadBlacklist();
    loadVallanxStats();
}

// ===== Update Functions =====
function updateTrafficData(data) {
    // Update packet table
    const tbody = document.getElementById('recentPackets');
    if (data.packets && data.packets.length > 0) {
        tbody.innerHTML = '';
        data.packets.slice(0, 10).forEach(packet => {
            const row = `
                <tr>
                    <td>${formatTime(packet.timestamp)}</td>
                    <td>${packet.src_ip}</td>
                    <td>${packet.dst_ip}</td>
                    <td><span class="badge badge-${getProtocolColor(packet.protocol)}">${packet.protocol}</span></td>
                    <td>${formatBytes(packet.size)}</td>
                    <td><span class="badge badge-${getDirectionColor(packet.direction)}">${packet.direction}</span></td>
                </tr>
            `;
            tbody.innerHTML += row;
        });
    }
    
    // Update charts
    if (data.stats) {
        updateCharts(data.stats);
    }
}

function updateStats(stats) {
    document.getElementById('totalPackets').textContent = formatNumber(stats.total_packets);
    document.getElementById('totalBytes').textContent = formatBytes(stats.total_bytes);
    
    // Update direction chart
    if (stats.direction_stats) {
        directionChart.data.datasets[0].data = [
            stats.direction_stats.inbound?.packets || 0,
            stats.direction_stats.outbound?.packets || 0,
            stats.direction_stats.internal?.packets || 0
        ];
        directionChart.update();
    }
}

function updateCharts(stats) {
    // Update traffic chart
    const now = new Date().toLocaleTimeString();
    if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(stats.total_packets || 0);
    trafficChart.update();
}

// ===== Threats =====
function displayThreat(threat) {
    const alertsContainer = document.getElementById('threatAlerts');
    const placeholder = alertsContainer.querySelector('.alert-placeholder');
    if (placeholder) {
        placeholder.remove();
    }
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${threat.severity === 'HIGH' ? 'danger' : 'warning'}`;
    alertDiv.innerHTML = `
        <i class="fas fa-exclamation-triangle"></i>
        <div>
            <strong>${threat.type}</strong>
            <p>${threat.description}</p>
            <small>Source: ${threat.source} | ${formatTime(threat.timestamp)}</small>
        </div>
    `;
    
    alertsContainer.insertBefore(alertDiv, alertsContainer.firstChild);
    
    // Update counter
    const currentCount = parseInt(document.getElementById('totalThreats').textContent);
    document.getElementById('totalThreats').textContent = currentCount + 1;
    
    showToast(`Threat detected: ${threat.type}`, 'error');
}

function displayVallanxAlert(alert) {
    displayThreat({
        type: 'Vallanx Match',
        severity: 'HIGH',
        description: `${alert.match_type}: ${alert.value} - ${alert.category}`,
        source: alert.value,
        timestamp: alert.timestamp
    });
    
    // Update blocked counter
    const currentCount = parseInt(document.getElementById('totalBlocked').textContent);
    document.getElementById('totalBlocked').textContent = currentCount + 1;
}

function displaySuricataAlert(alert) {
    const tbody = document.getElementById('suricataAlerts');
    const placeholder = tbody.querySelector('.no-data');
    if (placeholder) {
        placeholder.parentElement.remove();
    }
    
    const row = `
        <tr>
            <td>${formatTime(alert.timestamp)}</td>
            <td>${alert.signature}</td>
            <td>${alert.src_ip}</td>
            <td>${alert.dst_ip}</td>
            <td>${alert.category}</td>
            <td><span class="badge badge-danger">${alert.severity}</span></td>
            <td><button class="btn btn-sm btn-danger" onclick="blockIP('${alert.src_ip}')">Block</button></td>
        </tr>
    `;
    
    tbody.insertAdjacentHTML('afterbegin', row);
}

// ===== Vallanx Functions =====
function loadVallanxStats() {
    fetch('/api/vallanx/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('vallanxTotal').textContent = data.total_entries;
            document.getElementById('vallanxIPs').textContent = data.by_type?.ip || 0;
            document.getElementById('vallanxDomains').textContent = data.by_type?.domain || 0;
            document.getElementById('vallanxURLs').textContent = data.by_type?.url || 0;
        })
        .catch(error => console.error('Error loading Vallanx stats:', error));
}

function addVallanxEntry() {
    const formData = {
        value: document.getElementById('vallanxValue').value,
        type: document.getElementById('vallanxType').value,
        category: document.getElementById('vallanxCategory').value,
        severity: parseInt(document.getElementById('vallanxSeverity').value),
        action: document.getElementById('vallanxAction').value,
        tags: document.getElementById('vallanxTags').value.split(',').map(t => t.trim()).filter(t => t)
    };
    
    fetch('/api/vallanx/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Entry erfolgreich hinzugefügt', 'success');
            document.getElementById('vallanxAddForm').reset();
            loadVallanxStats();
        } else {
            showToast('Fehler beim Hinzufügen: ' + data.error, 'error');
        }
    })
    .catch(error => {
        showToast('Fehler: ' + error.message, 'error');
    });
}

function searchVallanx() {
    const query = document.getElementById('vallanxSearch').value;
    
    fetch(`/api/vallanx/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            displayVallanxResults(data.results);
        })
        .catch(error => console.error('Error searching:', error));
}

function displayVallanxResults(results) {
    const tbody = document.getElementById('vallanxEntries');
    
    if (results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-data">Keine Ergebnisse gefunden</td></tr>';
        return;
    }
    
    tbody.innerHTML = '';
    results.forEach(entry => {
        const row = `
            <tr>
                <td>${entry.value}</td>
                <td><span class="badge">${entry.type}</span></td>
                <td>${entry.category}</td>
                <td><span class="badge badge-danger">${entry.severity}</span></td>
                <td>${entry.action}</td>
                <td>${entry.hit_count || 0}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="removeVallanxEntry('${entry.value}', '${entry.type}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

function removeVallanxEntry(value, type) {
    if (!confirm(`Entry "${value}" wirklich entfernen?`)) return;
    
    fetch('/api/vallanx/remove', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value, type })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Entry entfernt', 'success');
            searchVallanx();
            loadVallanxStats();
        } else {
            showToast('Fehler: ' + data.error, 'error');
        }
    });
}

// ===== Blacklist/Whitelist Functions =====
function loadBlacklist() {
    fetch('/api/blacklist')
        .then(response => response.json())
        .then(data => {
            displayList('blacklist', 'IPs', data.ips);
            displayList('blacklist', 'Domains', data.domains);
        })
        .catch(error => console.error('Error loading blacklist:', error));
}

function loadWhitelist() {
    fetch('/api/whitelist')
        .then(response => response.json())
        .then(data => {
            displayList('whitelist', 'IPs', data.ips);
            displayList('whitelist', 'Domains', data.domains);
        })
        .catch(error => console.error('Error loading whitelist:', error));
}

function displayList(listType, itemType, items) {
    const listId = `${listType}${itemType}`;
    const countId = `${listType}${itemType}Count`;
    const ul = document.getElementById(listId);
    const count = document.getElementById(countId);
    
    count.textContent = items.length;
    
    if (items.length === 0) {
        ul.innerHTML = '<li class="no-items">Keine Items</li>';
        return;
    }
    
    ul.innerHTML = '';
    items.forEach(item => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span>${item}</span>
            <button class="remove-btn" onclick="removeFrom${listType.charAt(0).toUpperCase() + listType.slice(1)}('${item}', '${itemType}')">
                <i class="fas fa-times"></i>
            </button>
        `;
        ul.appendChild(li);
    });
}

function addToBlacklist() {
    const value = document.getElementById('blacklistInput').value.trim();
    if (!value) return;
    
    const data = isValidIP(value) ? { ip: value } : { domain: value };
    
    fetch('/api/blacklist/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Zur Blacklist hinzugefügt', 'success');
            document.getElementById('blacklistInput').value = '';
            loadBlacklist();
        } else {
            showToast('Fehler: ' + data.error, 'error');
        }
    });
}

function addToWhitelist() {
    const value = document.getElementById('whitelistInput').value.trim();
    if (!value) return;
    
    const data = isValidIP(value) ? { ip: value } : { domain: value };
    
    fetch('/api/whitelist/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Zur Whitelist hinzugefügt', 'success');
            document.getElementById('whitelistInput').value = '';
            loadWhitelist();
        } else {
            showToast('Fehler: ' + data.error, 'error');
        }
    });
}

function removeFromBlacklist(value, type) {
    const data = type === 'IPs' ? { ip: value } : { domain: value };
    
    fetch('/api/blacklist/remove', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Von Blacklist entfernt', 'success');
            loadBlacklist();
        }
    });
}

function removeFromWhitelist(value, type) {
    const data = type === 'IPs' ? { ip: value } : { domain: value };
    
    fetch('/api/whitelist/remove', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Von Whitelist entfernt', 'success');
            loadWhitelist();
        }
    });
}

function blockIP(ip) {
    addToBlacklist();
    document.getElementById('blacklistInput').value = ip;
    addToBlacklist();
}

// ===== Statistics =====
function loadStats(hours) {
    fetch(`/api/traffic/summary?hours=${hours}`)
        .then(response => response.json())
        .then(data => {
            // Update charts with data
            console.log('Stats loaded:', data);
        })
        .catch(error => console.error('Error loading stats:', error));
}

// ===== Export Functions =====
function exportData(format) {
    window.location.href = `/api/vallanx/export/${format}`;
    showToast(`Exportiere als ${format}...`, 'info');
}

// ===== Utility Functions =====
function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString('de-DE');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function isValidIP(str) {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    return ipRegex.test(str);
}

function getProtocolColor(protocol) {
    const colors = {
        'TCP': 'primary',
        'UDP': 'success',
        'ICMP': 'warning',
        'DNS': 'info'
    };
    return colors[protocol] || 'secondary';
}

function getDirectionColor(direction) {
    const colors = {
        'inbound': 'primary',
        'outbound': 'success',
        'internal': 'warning'
    };
    return colors[direction] || 'secondary';
}

function startUptimeCounter() {
    setInterval(function() {
        const uptime = Math.floor((Date.now() - startTime) / 1000);
        const hours = Math.floor(uptime / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);
        const seconds = uptime % 60;
        
        const uptimeStr = `${hours}h ${minutes}m ${seconds}s`;
        document.getElementById('uptime').innerHTML = `<i class="far fa-clock"></i> Uptime: ${uptimeStr}`;
        document.getElementById('systemUptime').textContent = uptimeStr;
    }, 1000);
}

// ===== Toast Notifications =====
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icon = type === 'success' ? 'check-circle' : 
                 type === 'error' ? 'exclamation-circle' : 
                 'info-circle';
    
    toast.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ===== Settings =====
function updateInterface() {
    const interface = document.getElementById('interfaceSetting').value;
    showToast('Interface-Änderung erfordert Neustart', 'warning');
}

function applyFilters() {
    const protocol = document.getElementById('protocolFilter').value;
    const direction = document.getElementById('directionFilter').value;
    showToast('Filter angewendet', 'info');
}

console.log('Vallanx Network Monitor initialized');
