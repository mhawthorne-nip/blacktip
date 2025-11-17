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
                    <td colspan="9">
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
                <td>${this.escapeHtml(device.ptr_hostname || '-')}</td>
                <td>${this.escapeHtml(device.classified_type || '-')}</td>
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
                <td colspan="9">Loading devices...</td>
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
                <td colspan="9">
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
                'anomaly': '⚠️'
            };

            const icon = iconMap[event.event_type] || '•';

            return `
                <div class="timeline-event" data-ip="${this.escapeHtml(event.ip_address || '')}">
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
                    </div>
                </div>
            `;
        }).join('');

        // Add click handlers to timeline events
        container.querySelectorAll('.timeline-event').forEach(eventEl => {
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
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.blacktipApp = new BlacktipApp();
});
