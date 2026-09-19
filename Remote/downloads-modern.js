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
        const id = String(download.id ?? '');
        const filename = String(download.filename ?? '');
        const statusClass = getStatusClass(download.status);
        const progressPercent = Number(download.progress) || 0;

        row.setAttribute('data-download-id', id);

        const checkTd = document.createElement('td');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'download-checkbox';
        checkbox.value = id;
        checkTd.appendChild(checkbox);

        const nameTd = document.createElement('td');
        nameTd.className = 'filename';
        nameTd.title = filename;
        nameTd.textContent = filename;

        const sizeTd = document.createElement('td');
        sizeTd.setAttribute('data-sort-value', String(download.size ?? 0));
        sizeTd.textContent = formatBytes(download.size);

        const progressTd = document.createElement('td');
        progressTd.className = 'progress-cell';
        const progressContainer = document.createElement('div');
        progressContainer.className = 'progress-container';
        const progress = document.createElement('div');
        progress.className = 'progress';
        const progressBar = document.createElement('div');
        progressBar.className = 'progress-bar';
        progressBar.style.width = `${Math.max(0, Math.min(100, progressPercent))}%`;
        progressBar.setAttribute('data-progress-id', id);
        progress.appendChild(progressBar);
        const progressText = document.createElement('span');
        progressText.className = 'progress-text';
        progressText.textContent = `${Math.max(0, Math.min(100, progressPercent))}%`;
        progressContainer.appendChild(progress);
        progressContainer.appendChild(progressText);
        progressTd.appendChild(progressContainer);

        const speedTd = document.createElement('td');
        speedTd.className = 'speed-cell';
        speedTd.textContent = formatSpeed(download.speed);

        const sourcesTd = document.createElement('td');
        sourcesTd.className = 'sources-cell';
        sourcesTd.textContent = `${download.sources || 0}/${download.totalSources || 0}`;

        const statusTd = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge status-${statusClass}`;
        statusBadge.textContent = String(download.status ?? '');
        statusTd.appendChild(statusBadge);

        const priorityTd = document.createElement('td');
        const select = document.createElement('select');
        select.className = 'priority-select';
        select.setAttribute('data-download-id', id);
        ['low', 'normal', 'high'].forEach((value) => {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = value.charAt(0).toUpperCase() + value.slice(1);
            if (download.priority === value) {
                option.selected = true;
            }
            select.appendChild(option);
        });
        priorityTd.appendChild(select);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'action-buttons';
        [
            ['start-download', 'btn-success', 'Start', '▶️'],
            ['pause-download', 'btn-warning', 'Pause', '⏸️'],
            ['cancel-download', 'btn-danger', 'Cancel', '🗑️']
        ].forEach(([action, cls, title, label]) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = `action-btn ${cls}`;
            button.setAttribute('data-action', action);
            button.setAttribute('data-id', id);
            button.title = title;
            button.textContent = label;
            actionsTd.appendChild(button);
        });

        [
            checkTd, nameTd, sizeTd, progressTd, speedTd,
            sourcesTd, statusTd, priorityTd, actionsTd
        ].forEach((td) => row.appendChild(td));

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
        if (!bytes || bytes <= 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.max(0, Math.min(
            sizes.length - 1,
            Math.floor(Math.log(bytes) / Math.log(k))
        ));
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
        tbody.textContent = '';
        const tr = document.createElement('tr');
        tr.className = 'loading-row';
        const td = document.createElement('td');
        td.colSpan = 9;
        td.className = 'text-center';
        const alert = document.createElement('div');
        alert.className = 'alert alert-error';
        alert.style.margin = '0';
        alert.textContent = String(message || '');
        td.appendChild(alert);
        tr.appendChild(td);
        tbody.appendChild(tr);
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
