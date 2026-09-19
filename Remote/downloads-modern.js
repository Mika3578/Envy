// Enhanced downloads functionality
(function() {
    let selectedDownloads = new Set();
    let downloadsData = [];

    // Initialize
    loadDownloads();

    // Event listeners
    document.getElementById('select-all').addEventListener('change', toggleSelectAll);
    document.addEventListener('change', handleCheckboxChange);
    document.addEventListener('change', function(e) {
        if (e.target.classList.contains('priority-select')) {
            const id = e.target.getAttribute('data-download-id');
            if (id) {
                changePriority(id, e.target.value);
            }
        }
    });
    document.addEventListener('click', function(e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) {
            return;
        }
        const action = btn.getAttribute('data-action');
        const id = btn.getAttribute('data-id');
        switch (action) {
            case 'refresh-page':
                refreshPage();
                break;
            case 'select-all':
                selectAll();
                break;
            case 'clear-selected':
                clearSelected();
                break;
            case 'start-selected':
                startSelected();
                break;
            case 'pause-selected':
                pauseSelected();
                break;
            case 'cancel-selected':
                cancelSelected();
                break;
            case 'move-selected':
                moveSelected();
                break;
            case 'start-download':
                if (id) startDownload(id);
                break;
            case 'pause-download':
                if (id) pauseDownload(id);
                break;
            case 'cancel-download':
                if (id) cancelDownload(id);
                break;
            default:
                break;
        }
    });

    // Functions
    function loadDownloads() {
        showLoadingState();

        EnvyRemote.ajaxRequest('/api/downloads')
            .then(data => {
                downloadsData = data.downloads || [];
                renderDownloadsTable(downloadsData);
                updateStatistics(data.stats);
                hideLoadingState();
            })
            .catch(error => {
                console.error('Failed to load downloads:', error);
                showErrorState('Failed to load downloads. Please refresh the page.');
            });
    }

    function renderDownloadsTable(downloads) {
        const tbody = document.querySelector('#downloads-table tbody');
        tbody.innerHTML = '';

        if (downloads.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center">
                        No downloads found. <a href="/remote/home">Start a new download</a>.
                    </td>
                </tr>
            `;
            return;
        }

        downloads.forEach(download => {
            const row = createDownloadRow(download);
            tbody.appendChild(row);
        });

        updateBulkActionsState();
    }

    function createDownloadRow(download) {
        const row = document.createElement('tr');
        row.setAttribute('data-download-id', download.id);

        const statusClass = getStatusClass(download.status);
        const progressPercent = download.progress || 0;

        row.innerHTML = `
            <td><input type="checkbox" class="download-checkbox" value="${download.id}"></td>
            <td class="filename" title="${download.filename}">${download.filename}</td>
            <td data-sort-value="${download.size}">${formatBytes(download.size)}</td>
            <td class="progress-cell">
                <div class="progress-container">
                    <div class="progress">
                        <div class="progress-bar" style="width: ${progressPercent}%"
                             data-progress-id="${download.id}"></div>
                    </div>
                    <span class="progress-text">${progressPercent}%</span>
                </div>
            </td>
            <td class="speed-cell">${formatSpeed(download.speed)}</td>
            <td class="sources-cell">${download.sources || 0}/${download.totalSources || 0}</td>
            <td><span class="status-badge status-${statusClass}">${download.status}</span></td>
            <td>
                <select class="priority-select" data-download-id="${download.id}">
                    <option value="low" ${download.priority === 'low' ? 'selected' : ''}>Low</option>
                    <option value="normal" ${download.priority === 'normal' ? 'selected' : ''}>Normal</option>
                    <option value="high" ${download.priority === 'high' ? 'selected' : ''}>High</option>
                </select>
            </td>
            <td class="action-buttons">
                <button type="button" class="action-btn btn-success" data-action="start-download" data-id="${download.id}" title="Start">
                    ▶️
                </button>
                <button type="button" class="action-btn btn-warning" data-action="pause-download" data-id="${download.id}" title="Pause">
                    ⏸️
                </button>
                <button type="button" class="action-btn btn-danger" data-action="cancel-download" data-id="${download.id}" title="Cancel">
                    🗑️
                </button>
            </td>
        `;

        return row;
    }

    function getStatusClass(status) {
        const statusMap = {
            'active': 'active',
            'paused': 'paused',
            'completed': 'completed',
            'error': 'error',
            'queued': 'paused'
        };
        return statusMap[status] || 'error';
    }

    function formatBytes(bytes) {
        if (!bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatSpeed(bytesPerSecond) {
        if (!bytesPerSecond) return '0 B/s';
        return formatBytes(bytesPerSecond) + '/s';
    }

    function toggleSelectAll() {
        const selectAllCheckbox = document.getElementById('select-all');
        const checkboxes = document.querySelectorAll('.download-checkbox');

        checkboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
        });

        updateSelectedDownloads();
    }

    function handleCheckboxChange(e) {
        if (e.target.classList.contains('download-checkbox')) {
            updateSelectedDownloads();
        }
    }

    function updateSelectedDownloads() {
        selectedDownloads.clear();
        document.querySelectorAll('.download-checkbox:checked').forEach(checkbox => {
            selectedDownloads.add(checkbox.value);
            checkbox.closest('tr').classList.add('selected');
        });

        document.querySelectorAll('.download-checkbox:not(:checked)').forEach(checkbox => {
            checkbox.closest('tr').classList.remove('selected');
        });

        updateBulkActionsState();
    }

    function updateBulkActionsState() {
        const bulkButtons = document.querySelectorAll('.bulk-actions .btn');
        const hasSelection = selectedDownloads.size > 0;

        bulkButtons.forEach(btn => {
            btn.disabled = !hasSelection;
        });
    }

    function updateStatistics(stats) {
        if (!stats) return;

        Object.keys(stats).forEach(key => {
            const element = document.querySelector(`[data-stat="${key}"]`);
            if (element) {
                element.textContent = stats[key];
            }
        });
    }

    function showLoadingState() {
        const tbody = document.querySelector('#downloads-table tbody');
        tbody.innerHTML = `
            <tr class="loading-row">
                <td colspan="9" class="text-center">
                    <div class="loading"></div>
                    Loading downloads...
                </td>
            </tr>
        `;
    }

    function hideLoadingState() {
        // Table content is replaced by renderDownloadsTable
    }

    function showErrorState(message) {
        const tbody = document.querySelector('#downloads-table tbody');
        tbody.innerHTML = `
            <tr class="loading-row">
                <td colspan="9" class="text-center">
                    <div class="alert alert-error" style="margin: 0;">${message}</div>
                </td>
            </tr>
        `;
    }

    // Global functions for button actions
    window.selectAll = function() {
        document.getElementById('select-all').checked = true;
        toggleSelectAll();
    };

    window.clearSelected = function() {
        if (confirm('Are you sure you want to clear the selected downloads?')) {
            selectedDownloads.forEach(id => {
                cancelDownload(id);
            });
            selectedDownloads.clear();
            updateBulkActionsState();
        }
    };

    window.startSelected = function() {
        selectedDownloads.forEach(id => startDownload(id));
    };

    window.pauseSelected = function() {
        selectedDownloads.forEach(id => pauseDownload(id));
    };

    window.cancelSelected = function() {
        if (confirm('Are you sure you want to cancel the selected downloads?')) {
            selectedDownloads.forEach(id => cancelDownload(id));
        }
    };

    window.moveSelected = function() {
        // Priority change dialog would go here
        alert('Priority change feature coming soon!');
    };

    window.startDownload = function(id) {
        EnvyRemote.ajaxRequest(`/api/downloads/${id}/start`, { method: 'POST' })
            .then(() => {
                EnvyRemote.showNotification('Download started', 'success');
                loadDownloads();
            })
            .catch(error => {
                EnvyRemote.showNotification('Failed to start download', 'error');
            });
    };

    window.pauseDownload = function(id) {
        EnvyRemote.ajaxRequest(`/api/downloads/${id}/pause`, { method: 'POST' })
            .then(() => {
                EnvyRemote.showNotification('Download paused', 'success');
                loadDownloads();
            })
            .catch(error => {
                EnvyRemote.showNotification('Failed to pause download', 'error');
            });
    };

    window.cancelDownload = function(id) {
        if (confirm('Are you sure you want to cancel this download?')) {
            EnvyRemote.ajaxRequest(`/api/downloads/${id}/cancel`, { method: 'DELETE' })
                .then(() => {
                    EnvyRemote.showNotification('Download cancelled', 'success');
                    loadDownloads();
                })
                .catch(error => {
                    EnvyRemote.showNotification('Failed to cancel download', 'error');
                });
        }
    };

    window.changePriority = function(id, priority) {
        EnvyRemote.ajaxRequest(`/api/downloads/${id}/priority`, {
            method: 'PUT',
            body: { priority }
        })
        .then(() => {
            EnvyRemote.showNotification('Priority updated', 'success');
        })
        .catch(error => {
            EnvyRemote.showNotification('Failed to update priority', 'error');
        });
    };

    window.refreshPage = function() {
        loadDownloads();
    };

    // Auto-refresh every 30 seconds
    setInterval(loadDownloads, 30000);
})();
