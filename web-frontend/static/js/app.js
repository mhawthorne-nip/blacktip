/**
 * Blacktip Web Frontend - JavaScript Application
 */

class BlacktipApp {
    constructor() {
        this.devices = [];
        this.filteredDevices = [];
        this.currentSort = {
            column: 'last_seen',
            direction: 'desc'
        };
        this.currentFilter = 'all';
        this.searchTerm = '';
        this.apiBase = '/api';

        // Timeline
        this.timelineEvents = [];
        this.filteredTimelineEvents = [];
        this.timelineFilter = 'all';
        this.currentView = 'devices';

        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        this.setupEventListeners();
        this.loadData();

        // Auto-refresh every 30 seconds
        setInterval(() => this.loadData(true), 30000);
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.loadData();
        });

        // Search input
        document.getElementById('search-input').addEventListener('input', (e) => {
            this.searchTerm = e.target.value.toLowerCase();
            this.applyFilters();
        });

        // Status filter
        document.querySelectorAll('input[name="status-filter"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.currentFilter = e.target.value;
                this.applyFilters();
            });
        });

        // Table sorting
        document.querySelectorAll('.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const column = th.dataset.sort;
                this.sortBy(column);
            });
        });

        // Modal close
        document.querySelector('.modal-close').addEventListener('click', () => {
            this.closeModal();
        });

        // Modal background click
        document.getElementById('device-modal').addEventListener('click', (e) => {
            if (e.target.id === 'device-modal') {
                this.closeModal();
            }
        });

        // ESC key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });

        // Navigation tabs
        document.querySelectorAll('.nav-item').forEach(navItem => {
            navItem.addEventListener('click', (e) => {
                e.preventDefault();
                const view = navItem.dataset.view;
                this.switchView(view);
            });
        });

        // Timeline refresh button
        const timelineRefreshBtn = document.getElementById('refresh-timeline-btn');
        if (timelineRefreshBtn) {
            timelineRefreshBtn.addEventListener('click', () => {
                this.loadTimeline();
            });
        }

        // Timeline filter
        document.querySelectorAll('input[name="timeline-filter"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.timelineFilter = e.target.value;
                this.applyTimelineFilters();
            });
        });

        // Internet page - Run speed test button
        const runSpeedTestBtn = document.getElementById('run-speedtest-btn');
        if (runSpeedTestBtn) {
            runSpeedTestBtn.addEventListener('click', () => {
                this.runSpeedTest();
            });
        }

        // Internet page - Trend period selector
        document.querySelectorAll('input[name="trend-period"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                const days = parseInt(e.target.value);
                this.loadSpeedTestTrends(days);
            });
        });
    }

    /**
     * Load data from API
     */
    async loadData(silent = false) {
        try {
            if (!silent) {
                this.showLoading();
            }

            // Load devices
            const devicesResponse = await fetch(`${this.apiBase}/devices`);
            if (!devicesResponse.ok) {
                throw new Error('Failed to load devices');
            }
            this.devices = await devicesResponse.json();

            // Load statistics
            const statsResponse = await fetch(`${this.apiBase}/statistics`);
            if (statsResponse.ok) {
                const stats = await statsResponse.json();
                this.updateStatistics(stats);
            }

            this.applyFilters();

        } catch (error) {
            console.error('Error loading data:', error);
            this.showError('Failed to load data. Please check if Blacktip scanner is running.');
        }
    }

    /**
     * Apply filters and search
     */
    applyFilters() {
        this.filteredDevices = this.devices.filter(device => {
            // Status filter
            if (this.currentFilter === 'online' && !device.is_online) {
                return false;
            }
            if (this.currentFilter === 'offline' && device.is_online) {
                return false;
            }

            // Search filter
            if (this.searchTerm) {
                const searchableText = [
                    device.ip_address,
                    device.mac_address,
                    device.vendor || '',
                    device.ptr_hostname || '',
                    device.classified_type || '',
                    device.device_name || ''
                ].join(' ').toLowerCase();

                if (!searchableText.includes(this.searchTerm)) {
                    return false;
                }
            }

            return true;
        });

        this.sortDevices();
        this.renderDevices();
    }

    /**
     * Sort devices
     */
    sortDevices() {
        this.filteredDevices.sort((a, b) => {
            const column = this.currentSort.column;
            let aVal = a[column];
            let bVal = b[column];

            // Handle nulls
            if (aVal === null || aVal === undefined) aVal = '';
            if (bVal === null || bVal === undefined) bVal = '';

            // Special handling for booleans (status)
            if (column === 'is_online') {
                aVal = aVal ? 1 : 0;
                bVal = bVal ? 1 : 0;
            }

            // Special handling for numbers
            if (column === 'open_port_count') {
                aVal = parseInt(aVal) || 0;
                bVal = parseInt(bVal) || 0;
            }

            // String comparison
            if (typeof aVal === 'string') {
                aVal = aVal.toLowerCase();
                bVal = bVal.toLowerCase();
            }

            let result = 0;
            if (aVal < bVal) result = -1;
            if (aVal > bVal) result = 1;

            return this.currentSort.direction === 'asc' ? result : -result;
        });
    }

    /**
     * Sort by column
     */
    sortBy(column) {
        if (this.currentSort.column === column) {
            // Toggle direction
            this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
            // New column
            this.currentSort.column = column;
            this.currentSort.direction = 'desc';
        }

        // Update UI
        document.querySelectorAll('.sortable').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
        });

        const th = document.querySelector(`[data-sort="${column}"]`);
        th.classList.add(`sort-${this.currentSort.direction}`);

        this.sortDevices();
        this.renderDevices();
    }

    /**
     * Render devices table
     */
    renderDevices() {
        const tbody = document.getElementById('devices-tbody');

        if (this.filteredDevices.length === 0) {
            tbody.innerHTML = `
                <tr class="loading-row">
                    <td colspan="7">
                        <div class="empty-state">
                            <div class="empty-state-icon">🔍</div>
                            <div class="empty-state-text">No devices found</div>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.filteredDevices.map(device => `
            <tr data-ip="${this.escapeHtml(device.ip_address)}">
                <td>
                    <span class="status-badge ${device.is_online ? 'online' : 'offline'}">
                        <span class="status-dot"></span>
                        ${device.is_online ? 'Online' : 'Offline'}
                    </span>
                </td>
                <td>${this.escapeHtml(device.device_name || '-')}</td>
                <td class="mono">${this.escapeHtml(device.ip_address)}</td>
                <td class="mono">${this.escapeHtml(device.mac_address)}</td>
                <td>${this.escapeHtml(device.vendor || '-')}</td>
                <td>
                    ${device.open_port_count ?
                        `<span class="port-badge has-ports">${device.open_port_count}</span>` :
                        `<span class="port-badge">0</span>`
                    }
                </td>
                <td>${this.escapeHtml(device.time_ago)}</td>
            </tr>
        `).join('');

        // Add click handlers
        tbody.querySelectorAll('tr').forEach(tr => {
            tr.addEventListener('click', () => {
                const ip = tr.dataset.ip;
                this.showDeviceDetails(ip);
            });
        });
    }

    /**
     * Update statistics in sidebar
     */
    updateStatistics(stats) {
        document.getElementById('total-devices').textContent = stats.total_devices || 0;
        document.getElementById('online-devices').textContent = stats.online_devices || 0;
        document.getElementById('offline-devices').textContent =
            (stats.total_devices - stats.online_devices) || 0;
    }

    /**
     * Show device details in modal
     */
    async showDeviceDetails(ip) {
        const modal = document.getElementById('device-modal');
        const modalBody = document.getElementById('modal-body');
        const modalTitle = document.getElementById('modal-title');

        // Show modal with loading state
        modal.classList.add('active');
        modalTitle.textContent = `Device: ${ip}`;
        modalBody.innerHTML = '<p>Loading device details...</p>';

        try {
            const response = await fetch(`${this.apiBase}/devices/${encodeURIComponent(ip)}`);
            if (!response.ok) {
                throw new Error('Failed to load device details');
            }

            const device = await response.json();
            modalBody.innerHTML = this.renderDeviceDetails(device);

            // Attach event listener to save button
            const saveBtn = document.getElementById('save-device-name-btn');
            if (saveBtn) {
                saveBtn.addEventListener('click', () => this.saveDeviceName(device.ip_address, device.mac_address));
            }

        } catch (error) {
            console.error('Error loading device details:', error);
            modalBody.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-text">Failed to load device details</div>
                </div>
            `;
        }
    }

    /**
     * Save device name
     */
    async saveDeviceName(ip, mac) {
        const nameInput = document.getElementById('device-name-input');
        const saveBtn = document.getElementById('save-device-name-btn');

        if (!nameInput || !saveBtn) {
            return;
        }

        const deviceName = nameInput.value.trim();

        // Disable button and show loading state
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';

        try {
            const response = await fetch(`${this.apiBase}/devices/${encodeURIComponent(ip)}/name`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    mac_address: mac,
                    device_name: deviceName
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to save device name');
            }

            // Success! Update button state
            saveBtn.textContent = 'Saved!';
            saveBtn.style.background = 'var(--success-500, #28a745)';

            // Reload devices to show updated name
            setTimeout(() => {
                this.loadData(true);
                // Reset button after a short delay
                setTimeout(() => {
                    saveBtn.textContent = 'Save';
                    saveBtn.style.background = 'var(--primary-500, #007bff)';
                    saveBtn.disabled = false;
                }, 1000);
            }, 500);

        } catch (error) {
            console.error('Error saving device name:', error);
            saveBtn.textContent = 'Error!';
            saveBtn.style.background = 'var(--danger-500, #dc3545)';

            // Reset button after delay
            setTimeout(() => {
                saveBtn.textContent = 'Save';
                saveBtn.style.background = 'var(--primary-500, #007bff)';
                saveBtn.disabled = false;
            }, 2000);

            alert('Failed to save device name: ' + error.message);
        }
    }

    /**
     * Render device details HTML
     */
    renderDeviceDetails(device) {
        let html = `
            <div class="detail-section">
                <h3>Basic Information</h3>
                <div class="detail-grid">
                    <div class="detail-item" style="grid-column: 1 / -1;">
                        <div class="detail-label">Device Name</div>
                        <div class="detail-value" style="display: flex; gap: 0.5rem; align-items: center;">
                            <input
                                type="text"
                                id="device-name-input"
                                value="${this.escapeHtml(device.device_name || '')}"
                                placeholder="Enter a friendly name for this device"
                                style="flex: 1; padding: 0.5rem; border: 1px solid var(--gray-300, #ddd); border-radius: 4px; font-size: 0.9rem;"
                                data-ip="${this.escapeHtml(device.ip_address)}"
                                data-mac="${this.escapeHtml(device.mac_address)}"
                            />
                            <button
                                id="save-device-name-btn"
                                style="padding: 0.5rem 1rem; background: var(--primary-500, #007bff); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem;"
                            >
                                Save
                            </button>
                        </div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">IP Address</div>
                        <div class="detail-value">${this.escapeHtml(device.ip_address)}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">MAC Address</div>
                        <div class="detail-value">${this.escapeHtml(device.mac_address)}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Vendor</div>
                        <div class="detail-value">${this.escapeHtml(device.vendor || 'Unknown')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Status</div>
                        <div class="detail-value">
                            <span class="status-badge ${device.is_online ? 'online' : 'offline'}">
                                <span class="status-dot"></span>
                                ${device.is_online ? 'Online' : 'Offline'}
                            </span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Hostname</div>
                        <div class="detail-value ${!device.ptr_hostname ? 'empty' : ''}">${this.escapeHtml(device.ptr_hostname || 'None')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Device Type</div>
                        <div class="detail-value ${!device.classified_type ? 'empty' : ''}">${this.escapeHtml(device.classified_type || 'Unknown')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">First Seen</div>
                        <div class="detail-value">${this.formatTimestamp(device.first_seen)}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Last Seen</div>
                        <div class="detail-value">${this.formatTimestamp(device.last_seen)} (${device.time_ago})</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Packet Count</div>
                        <div class="detail-value">${device.packet_count || 0}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Requests</div>
                        <div class="detail-value">${device.request_count || 0}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Replies</div>
                        <div class="detail-value">${device.reply_count || 0}</div>
                    </div>
                </div>
            </div>
        `;

        // Nmap scan results
        if (device.nmap_scan) {
            const scan = device.nmap_scan;
            html += `
                <div class="detail-section">
                    <h3>Port Scan Results</h3>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <div class="detail-label">Scan Date</div>
                            <div class="detail-value">${this.formatTimestamp(scan.scan_start)}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Status</div>
                            <div class="detail-value">${this.escapeHtml(scan.status || 'unknown')}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">OS Detection</div>
                            <div class="detail-value ${!scan.os_name ? 'empty' : ''}">${this.escapeHtml(scan.os_name || 'None')}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">OS Accuracy</div>
                            <div class="detail-value">${scan.os_accuracy ? scan.os_accuracy + '%' : '-'}</div>
                        </div>
                    </div>

                    ${scan.ports && scan.ports.length > 0 ? `
                        <h4 style="margin-top: 1.5rem; margin-bottom: 0.75rem; font-size: 1rem;">Open Ports (${scan.ports.filter(p => p.state === 'open').length})</h4>
                        <table class="ports-table">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                    <th>State</th>
                                    <th>Service</th>
                                    <th>Version</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${scan.ports.filter(p => p.state === 'open').map(port => `
                                    <tr>
                                        <td class="mono">${port.port}</td>
                                        <td>${port.protocol}</td>
                                        <td>${port.state}</td>
                                        <td>${this.escapeHtml(port.service_name || '-')}</td>
                                        <td>${this.escapeHtml(port.service_version || '-')}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : '<p style="color: var(--gray-500); font-style: italic; margin-top: 1rem;">No open ports detected</p>'}
                </div>
            `;

            // NetBIOS/SMB information
            if (scan.netbios) {
                const nb = scan.netbios;
                html += `
                    <div class="detail-section">
                        <h3>NetBIOS / SMB Information</h3>
                        <div class="detail-grid">
                            ${nb.netbios_computer_name ? `
                                <div class="detail-item">
                                    <div class="detail-label">Computer Name</div>
                                    <div class="detail-value">${this.escapeHtml(nb.netbios_computer_name)}</div>
                                </div>
                            ` : ''}
                            ${nb.netbios_workgroup ? `
                                <div class="detail-item">
                                    <div class="detail-label">Workgroup</div>
                                    <div class="detail-value">${this.escapeHtml(nb.netbios_workgroup)}</div>
                                </div>
                            ` : ''}
                            ${nb.smb_os ? `
                                <div class="detail-item">
                                    <div class="detail-label">SMB OS</div>
                                    <div class="detail-value">${this.escapeHtml(nb.smb_os)}</div>
                                </div>
                            ` : ''}
                            ${nb.smb_signing_required !== null ? `
                                <div class="detail-item">
                                    <div class="detail-label">SMB Signing Required</div>
                                    <div class="detail-value">${nb.smb_signing_required ? 'Yes' : 'No'}</div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            }
        } else {
            html += `
                <div class="detail-section">
                    <h3>Port Scan Results</h3>
                    <p style="color: var(--gray-500); font-style: italic;">No nmap scan data available yet</p>
                </div>
            `;
        }

        // Anomalies
        if (device.anomalies && device.anomalies.length > 0) {
            html += `
                <div class="detail-section">
                    <h3>Anomalies (${device.anomalies.length})</h3>
                    <table class="ports-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Message</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${device.anomalies.map(anomaly => `
                                <tr>
                                    <td>${this.escapeHtml(anomaly.anomaly_type)}</td>
                                    <td>${this.escapeHtml(anomaly.message)}</td>
                                    <td>${this.formatTimestamp(anomaly.timestamp)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        return html;
    }

    /**
     * Close modal
     */
    closeModal() {
        document.getElementById('device-modal').classList.remove('active');
    }

    /**
     * Show loading state
     */
    showLoading() {
        const tbody = document.getElementById('devices-tbody');
        tbody.innerHTML = `
            <tr class="loading-row">
                <td colspan="7">Loading devices...</td>
            </tr>
        `;
    }

    /**
     * Show error message
     */
    showError(message) {
        const tbody = document.getElementById('devices-tbody');
        tbody.innerHTML = `
            <tr class="loading-row">
                <td colspan="7">
                    <div class="empty-state">
                        <div class="empty-state-icon">⚠️</div>
                        <div class="empty-state-text">${this.escapeHtml(message)}</div>
                    </div>
                </td>
            </tr>
        `;
    }

    /**
     * Format timestamp for display
     */
    formatTimestamp(timestamp) {
        if (!timestamp) return '-';

        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (e) {
            return timestamp;
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (text === null || text === undefined) return '';

        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Switch between views
     */
    switchView(viewName) {
        this.currentView = viewName;

        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.view === viewName) {
                item.classList.add('active');
            }
        });

        // Update content views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.remove('active');
        });

        const targetView = document.getElementById(`${viewName}-view`);
        if (targetView) {
            targetView.classList.add('active');
        }

        // Load data for the view
        if (viewName === 'timeline' && this.timelineEvents.length === 0) {
            this.loadTimeline();
        }
        
        if (viewName === 'internet') {
            this.loadInternetData();
        }
    }

    /**
     * Load timeline events
     */
    async loadTimeline(silent = false) {
        try {
            if (!silent) {
                this.showTimelineLoading();
            }

            const response = await fetch(`${this.apiBase}/timeline`);
            if (!response.ok) {
                throw new Error('Failed to load timeline');
            }

            this.timelineEvents = await response.json();
            this.applyTimelineFilters();

        } catch (error) {
            console.error('Error loading timeline:', error);
            this.showTimelineError('Failed to load timeline events.');
        }
    }

    /**
     * Apply timeline filters
     */
    applyTimelineFilters() {
        this.filteredTimelineEvents = this.timelineEvents.filter(event => {
            if (this.timelineFilter === 'all') {
                return true;
            }
            return event.event_type === this.timelineFilter;
        });

        this.renderTimeline();
    }

    /**
     * Render timeline events
     */
    renderTimeline() {
        const container = document.getElementById('timeline-container');

        if (this.filteredTimelineEvents.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">📅</div>
                    <div class="empty-state-text">No timeline events found</div>
                </div>
            `;
            return;
        }

        container.innerHTML = this.filteredTimelineEvents.map(event => {
            const iconMap = {
                'discovered': '🆕',
                'online': '🟢',
                'offline': '⚫',
                'anomaly': '⚠️',
                'speedtest': '🚀'
            };

            const icon = iconMap[event.event_type] || '•';

            // Build the description based on event type
            let description = event.description || '';
            let durationInfo = '';
            
            // Add duration information for online/offline events
            if ((event.event_type === 'online' || event.event_type === 'offline') && event.duration_str) {
                const eventState = event.event_type; // The state the device transitioned TO
                const previousState = event.previous_state || (eventState === 'online' ? 'offline' : 'online');
                const isCurrentState = event.is_current_state;
                
                if (isCurrentState) {
                    // Device is still in the state it transitioned to
                    const stateText = eventState === 'online' ? 'online' : 'offline';
                    durationInfo = `<div class="timeline-duration">
                        <strong>${this.escapeHtml(event.device_name)}</strong> has been ${stateText} for <strong>${this.escapeHtml(event.duration_str)}</strong>
                    </div>`;
                } else {
                    // Device has changed state since this event
                    // Show: "was [previous state] for [duration] (now [current state])"
                    const previousStateText = previousState === 'online' ? 'online' : 'offline';
                    const nowState = event.current_state === 'online' ? 'online' : 'offline';
                    durationInfo = `<div class="timeline-duration">
                        <strong>${this.escapeHtml(event.device_name)}</strong> was ${previousStateText} for <strong>${this.escapeHtml(event.duration_str)}</strong> (now ${nowState})
                    </div>`;
                }
            }

            // Special rendering for speed test events
            if (event.event_type === 'speedtest') {
                return `
                    <div class="timeline-event speedtest" data-ip="${this.escapeHtml(event.ip_address || '')}">
                        <div class="timeline-event-header">
                            <div class="timeline-event-title">
                                <span class="timeline-event-icon ${event.event_type}">${icon}</span>
                                <span>${this.escapeHtml(event.title)}</span>
                            </div>
                            <div class="timeline-event-time">
                                <span class="timeline-event-timestamp">${this.formatTimestamp(event.timestamp)}</span>
                                <span class="timeline-event-ago">${this.escapeHtml(event.time_ago)}</span>
                            </div>
                        </div>
                        <div class="timeline-event-body">
                            <div class="speedtest-metrics-inline">
                                <div class="metric-inline download">
                                    <span class="metric-label">Download:</span>
                                    <span class="metric-value">${event.download_mbps.toFixed(1)} Mbps</span>
                                </div>
                                <div class="metric-inline upload">
                                    <span class="metric-label">Upload:</span>
                                    <span class="metric-value">${event.upload_mbps.toFixed(1)} Mbps</span>
                                </div>
                                <div class="metric-inline ping">
                                    <span class="metric-label">Latency:</span>
                                    <span class="metric-value">${event.ping_ms.toFixed(0)} ms</span>
                                </div>
                                <div class="metric-inline server">
                                    <span class="metric-label">Server:</span>
                                    <span class="metric-value">${this.escapeHtml(event.server_location || 'Unknown')}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }

            return `
                <div class="timeline-event ${event.event_type}" data-ip="${this.escapeHtml(event.ip_address || '')}">
                    <div class="timeline-event-header">
                        <div class="timeline-event-title">
                            <span class="timeline-event-icon ${event.event_type}">${icon}</span>
                            <span>${this.escapeHtml(event.title)}</span>
                        </div>
                        <div class="timeline-event-time">
                            <span class="timeline-event-timestamp">${this.formatTimestamp(event.timestamp)}</span>
                            <span class="timeline-event-ago">${this.escapeHtml(event.time_ago)}</span>
                        </div>
                    </div>
                    <div class="timeline-event-body">
                        ${durationInfo}
                        ${event.ip_address || event.mac_address ? `
                            <div class="timeline-event-meta">
                                ${event.ip_address ? `
                                    <div class="timeline-event-meta-item">
                                        <span class="timeline-event-meta-label">IP:</span>
                                        <span class="timeline-event-meta-value">${this.escapeHtml(event.ip_address)}</span>
                                    </div>
                                ` : ''}
                                ${event.mac_address ? `
                                    <div class="timeline-event-meta-item">
                                        <span class="timeline-event-meta-label">MAC:</span>
                                        <span class="timeline-event-meta-value">${this.escapeHtml(event.mac_address)}</span>
                                    </div>
                                ` : ''}
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');

        // Add click handlers to timeline events (except speedtest)
        container.querySelectorAll('.timeline-event:not(.speedtest)').forEach(eventEl => {
            eventEl.addEventListener('click', () => {
                const ip = eventEl.dataset.ip;
                if (ip) {
                    this.showDeviceDetails(ip);
                }
            });
        });
    }

    /**
     * Show timeline loading state
     */
    showTimelineLoading() {
        const container = document.getElementById('timeline-container');
        container.innerHTML = '<div class="loading-state">Loading timeline events...</div>';
    }

    /**
     * Show timeline error
     */
    showTimelineError(message) {
        const container = document.getElementById('timeline-container');
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">⚠️</div>
                <div class="empty-state-text">${this.escapeHtml(message)}</div>
            </div>
        `;
    }

    /**
     * Load Internet page data
     */
    loadInternetData() {
        this.loadLatestSpeedTest();
        this.loadNetworkInfo();
        this.loadSpeedTestHistory();
        this.loadSpeedTestTrends(7); // Default to 7 days
    }

    /**
     * Load latest speed test
     */
    async loadLatestSpeedTest() {
        const container = document.getElementById('latest-speedtest-card');
        container.innerHTML = '<div class="loading-state">Loading latest speed test...</div>';

        try {
            const response = await fetch(`${this.apiBase}/speed-tests?limit=1`);
            if (!response.ok) throw new Error('Failed to load speed test');

            const tests = await response.json();
            
            if (tests.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">🚀</div>
                        <div class="empty-state-text">No speed tests yet</div>
                        <button onclick="blacktipApp.runSpeedTest()" class="btn-primary" style="margin-top: 1rem;">
                            Run First Speed Test
                        </button>
                    </div>
                `;
                return;
            }

            const test = tests[0];
            this.renderSpeedTestCard(test, container);

        } catch (error) {
            console.error('Error loading speed test:', error);
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-text">Failed to load speed test</div>
                </div>
            `;
        }
    }

    /**
     * Render speed test card
     */
    renderSpeedTestCard(test, container) {
        const status = test.test_status;
        const isRunning = status === 'running';
        const isFailed = status === 'failed';
        const isCompleted = status === 'completed';

        let html = `
            <div class="speedtest-results">
                <div class="speedtest-header">
                    <div class="speedtest-date">${this.formatTimestamp(test.test_start)}</div>
                    <span class="status-badge ${status}">${status}</span>
                </div>
        `;

        if (isCompleted) {
            html += `
                <div class="speedtest-metrics">
                    <div class="metric download">
                        <div class="metric-label">Download</div>
                        <div class="metric-value">${test.download_mbps.toFixed(1)}</div>
                        <div class="metric-unit">Mbps</div>
                    </div>
                    <div class="metric upload">
                        <div class="metric-label">Upload</div>
                        <div class="metric-value">${test.upload_mbps.toFixed(1)}</div>
                        <div class="metric-unit">Mbps</div>
                    </div>
                    <div class="metric ping">
                        <div class="metric-label">Latency</div>
                        <div class="metric-value">${test.ping_ms.toFixed(0)}</div>
                        <div class="metric-unit">ms</div>
                    </div>
                </div>
            `;

            if (test.server_name) {
                html += `
                    <div class="speedtest-server">
                        <span class="server-label">Server:</span>
                        <span class="server-value">${this.escapeHtml(test.server_name)}, ${this.escapeHtml(test.server_location || '')}</span>
                    </div>
                `;
            }
        } else if (isRunning) {
            html += `
                <div class="speedtest-running">
                    <div class="spinner"></div>
                    <p>Running speed test... This may take 20-30 seconds.</p>
                </div>
            `;
        } else if (isFailed) {
            html += `
                <div class="speedtest-error">
                    <p>❌ Test failed: ${this.escapeHtml(test.error_message || 'Unknown error')}</p>
                </div>
            `;
        }

        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * Run a new speed test
     */
    async runSpeedTest() {
        const btn = document.getElementById('run-speedtest-btn');
        if (!btn) return;

        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = '⏳ Running...';

        try {
            const response = await fetch(`${this.apiBase}/speed-tests/run`, {
                method: 'POST'
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to start speed test');
            }

            // Show running state
            const container = document.getElementById('latest-speedtest-card');
            container.innerHTML = `
                <div class="speedtest-results">
                    <div class="speedtest-running">
                        <div class="spinner"></div>
                        <p>Running speed test... This may take 20-30 seconds.</p>
                        <p class="hint">The page will auto-refresh when complete.</p>
                    </div>
                </div>
            `;

            // Poll for results every 3 seconds
            const pollInterval = setInterval(async () => {
                try {
                    const response = await fetch(`${this.apiBase}/speed-tests?limit=1`);
                    const tests = await response.json();
                    
                    if (tests.length > 0 && tests[0].test_status !== 'running') {
                        clearInterval(pollInterval);
                        this.loadInternetData();
                        btn.disabled = false;
                        btn.textContent = originalText;
                    }
                } catch (e) {
                    console.error('Poll error:', e);
                }
            }, 3000);

            // Stop polling after 60 seconds
            setTimeout(() => {
                clearInterval(pollInterval);
                btn.disabled = false;
                btn.textContent = originalText;
            }, 60000);

        } catch (error) {
            console.error('Error running speed test:', error);
            alert('Failed to start speed test: ' + error.message);
            btn.disabled = false;
            btn.textContent = originalText;
        }
    }

    /**
     * Load network information
     */
    async loadNetworkInfo() {
        const container = document.getElementById('network-info-card');
        container.innerHTML = '<div class="loading-state">Loading network information...</div>';

        try {
            const response = await fetch(`${this.apiBase}/network-info`);
            if (!response.ok) throw new Error('Failed to load network info');

            const info = await response.json();
            
            if (!info || info.message) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">🌐</div>
                        <div class="empty-state-text">No network information available</div>
                        <p class="hint">Run a speed test to collect network information</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="network-info-grid">
                    <div class="info-item">
                        <div class="info-label">Service Provider</div>
                        <div class="info-value">${this.escapeHtml(info.isp_name || '-')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Public IP Address</div>
                        <div class="info-value mono">${this.escapeHtml(info.public_ip || '-')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Public Hostname</div>
                        <div class="info-value mono">${this.escapeHtml(info.hostname || '-')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Location</div>
                        <div class="info-value">${this.formatLocation(info)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Timezone</div>
                        <div class="info-value">${this.escapeHtml(info.timezone || '-')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Last Updated</div>
                        <div class="info-value">${this.formatTimestamp(info.last_seen)}</div>
                    </div>
                </div>
            `;

        } catch (error) {
            console.error('Error loading network info:', error);
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-text">Failed to load network information</div>
                </div>
            `;
        }
    }

    /**
     * Format location string
     */
    formatLocation(info) {
        const parts = [];
        if (info.city) parts.push(info.city);
        if (info.region) parts.push(info.region);
        if (info.country) parts.push(info.country);
        return parts.length > 0 ? parts.join(', ') : '-';
    }

    /**
     * Load speed test trends
     */
    async loadSpeedTestTrends(days) {
        const container = document.getElementById('trend-stats-container');
        container.innerHTML = '<div class="loading-state">Loading trends...</div>';

        try {
            const response = await fetch(`${this.apiBase}/speed-tests/statistics?days=${days}`);
            if (!response.ok) throw new Error('Failed to load statistics');

            const stats = await response.json();
            
            if (!stats.total_tests || stats.total_tests === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">📊</div>
                        <div class="empty-state-text">No data for selected period</div>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="trend-stats">
                    <div class="trend-stat">
                        <div class="trend-label">Average Download</div>
                        <div class="trend-value">${(stats.avg_download || 0).toFixed(1)} <span class="trend-unit">Mbps</span></div>
                    </div>
                    <div class="trend-stat">
                        <div class="trend-label">Average Upload</div>
                        <div class="trend-value">${(stats.avg_upload || 0).toFixed(1)} <span class="trend-unit">Mbps</span></div>
                    </div>
                    <div class="trend-stat">
                        <div class="trend-label">Average Latency</div>
                        <div class="trend-value">${(stats.avg_ping || 0).toFixed(0)} <span class="trend-unit">ms</span></div>
                    </div>
                    <div class="trend-stat">
                        <div class="trend-label">Tests Run</div>
                        <div class="trend-value">${stats.total_tests}</div>
                    </div>
                </div>
            `;

        } catch (error) {
            console.error('Error loading trends:', error);
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-text">Failed to load trends</div>
                </div>
            `;
        }
    }

    /**
     * Load speed test history
     */
    async loadSpeedTestHistory() {
        const container = document.getElementById('speedtest-history-container');
        container.innerHTML = '<div class="loading-state">Loading test history...</div>';

        try {
            const response = await fetch(`${this.apiBase}/speed-tests?limit=20`);
            if (!response.ok) throw new Error('Failed to load history');

            const tests = await response.json();
            
            if (tests.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">📝</div>
                        <div class="empty-state-text">No test history</div>
                    </div>
                `;
                return;
            }

            const completedTests = tests.filter(t => t.test_status === 'completed');

            if (completedTests.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">📝</div>
                        <div class="empty-state-text">No completed tests yet</div>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <table class="speedtest-history-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Download</th>
                            <th>Upload</th>
                            <th>Ping</th>
                            <th>Server</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${completedTests.map(test => `
                            <tr>
                                <td>${this.formatTimestamp(test.test_start)}</td>
                                <td class="metric-cell">${test.download_mbps.toFixed(1)} Mbps</td>
                                <td class="metric-cell">${test.upload_mbps.toFixed(1)} Mbps</td>
                                <td class="metric-cell">${test.ping_ms.toFixed(0)} ms</td>
                                <td>${this.escapeHtml(test.server_location || '-')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;

        } catch (error) {
            console.error('Error loading history:', error);
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-text">Failed to load history</div>
                </div>
            `;
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.blacktipApp = new BlacktipApp();
});
