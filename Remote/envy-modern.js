/**
 * Envy Remote Control Interface - Modern JavaScript
 * Version 2026 - Enhanced UX with AJAX and Real-time Updates
 */

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        refreshInterval: 30000, // 30 seconds
        ajaxTimeout: 10000,    // 10 seconds
        retryAttempts: 3,
        enableNotifications: true
    };

    // Application State
    const state = {
        currentPage: null,
        isLoggedIn: false,
        refreshTimer: null,
        csrfToken: null,
        lastUpdate: null
    };

    // DOM Cache
    const cache = {};

    /**
     * Initialize the application
     */
    function init() {
        cacheElements();
        setupEventListeners();
        initializeFeatures();
        hideLoadingScreen();
        startPeriodicRefresh();
    }

    /**
     * Cache frequently used DOM elements
     */
    function cacheElements() {
        cache.loadingScreen = document.getElementById('loading-screen');
        cache.mainContent = document.getElementById('main-content');
        cache.navTabs = document.querySelector('.nav-tabs');
    }

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        // Navigation
        if (cache.navTabs) {
            cache.navTabs.addEventListener('click', handleNavigation);
        }

        // Form submissions
        document.addEventListener('submit', handleFormSubmit);

        // Keyboard shortcuts
        document.addEventListener('keydown', handleKeyboardShortcuts);

        // Online/Offline detection
        window.addEventListener('online', handleOnlineStatus);
        window.addEventListener('offline', handleOfflineStatus);

        // Page visibility
        document.addEventListener('visibilitychange', handleVisibilityChange);
    }

    /**
     * Initialize additional features
     */
    function initializeFeatures() {
        setupCSRFProtection();
        initializeNotifications();
        setupResponsiveFeatures();
        initializeTooltips();
    }

    /**
     * Setup CSRF protection
     */
    function setupCSRFProtection() {
        // Generate CSRF token
        state.csrfToken = generateCSRFToken();

        // Add to all forms
        document.querySelectorAll('form').forEach(form => {
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = state.csrfToken;
            form.appendChild(csrfInput);
        });
    }

    /**
     * Handle navigation clicks
     */
    function handleNavigation(e) {
        if (e.target.tagName === 'A') {
            e.preventDefault();
            const url = e.target.getAttribute('href');
            navigateTo(url);
        }
    }

    /**
     * Navigate to a new page with AJAX
     */
    function navigateTo(url, pushState = true) {
        showLoadingIndicator();

        ajaxRequest(url, {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': state.csrfToken
            }
        })
        .then(response => {
            updateContent(response.html);
            if (pushState) {
                history.pushState({url: url}, '', url);
            }
            updateNavigationState(url);
            hideLoadingIndicator();
        })
        .catch(error => {
            console.error('Navigation failed:', error);
            // Fallback to regular navigation
            window.location.href = url;
        });
    }

    /**
     * Handle form submissions
     */
    function handleFormSubmit(e) {
        const form = e.target;

        // Check if form should use AJAX
        if (form.hasAttribute('data-ajax')) {
            e.preventDefault();
            submitFormAjax(form);
        }
    }

    /**
     * Submit form via AJAX
     */
    function submitFormAjax(form) {
        const formData = new FormData(form);
        const url = form.getAttribute('action') || window.location.href;

        showLoadingIndicator();

        ajaxRequest(url, {
            method: form.method || 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': state.csrfToken
            }
        })
        .then(response => {
            if (response.success) {
                showNotification(response.message || 'Operation completed successfully', 'success');
                if (response.redirect) {
                    setTimeout(() => navigateTo(response.redirect), 1000);
                } else if (response.refresh) {
                    refreshCurrentPage();
                }
            } else {
                showNotification(response.message || 'Operation failed', 'error');
            }
            hideLoadingIndicator();
        })
        .catch(error => {
            console.error('Form submission failed:', error);
            showNotification('Request failed. Please try again.', 'error');
            hideLoadingIndicator();
        });
    }

    /**
     * AJAX request utility
     */
    function ajaxRequest(url, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            timeout: CONFIG.ajaxTimeout
        };

        const finalOptions = { ...defaultOptions, ...options };

        // Handle FormData
        if (finalOptions.body instanceof FormData) {
            delete finalOptions.headers['Content-Type'];
        } else if (typeof finalOptions.body === 'object') {
            finalOptions.body = JSON.stringify(finalOptions.body);
        }

        return new Promise((resolve, reject) => {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), finalOptions.timeout);

            fetch(url, {
                ...finalOptions,
                signal: controller.signal
            })
            .then(response => {
                clearTimeout(timeoutId);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(resolve)
            .catch(error => {
                clearTimeout(timeoutId);
                reject(error);
            });
        });
    }

    /**
     * Update main content area
     */
    function updateContent(html) {
        if (cache.mainContent) {
            cache.mainContent.innerHTML = html;
            initializeDynamicContent();
        }
    }

    /**
     * Initialize dynamic content after AJAX updates
     */
    function initializeDynamicContent() {
        // Re-initialize tooltips
        initializeTooltips();

        // Setup progress bars
        initializeProgressBars();

        // Setup sortable tables
        initializeSortableTables();
    }

    /**
     * Show loading indicator
     */
    function showLoadingIndicator() {
        const indicator = document.querySelector('.loading-indicator') ||
                         createLoadingIndicator();
        indicator.style.display = 'block';
    }

    /**
     * Hide loading indicator
     */
    function hideLoadingIndicator() {
        const indicator = document.querySelector('.loading-indicator');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    /**
     * Create loading indicator
     */
    function createLoadingIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'loading-indicator';
        indicator.innerHTML = `
            <div class="loading-content">
                <div class="loading-spinner"></div>
                <span>Loading...</span>
            </div>
        `;
        indicator.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            z-index: 10000;
            display: none;
        `;
        document.body.appendChild(indicator);
        return indicator;
    }

    /**
     * Show notification
     */
    function showNotification(message, type = 'info') {
        const notification = createNotification(message, type);
        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }

    /**
     * Create notification element
     */
    function createNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type}`;
        notification.innerHTML = `
            <span>${message}</span>
            <button type="button" onclick="this.parentElement.remove()" aria-label="Close notification">×</button>
        `;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            max-width: 400px;
            z-index: 10001;
            animation: slideIn 0.3s ease;
        `;
        return notification;
    }

    /**
     * Initialize notifications system
     */
    function initializeNotifications() {
        if ('Notification' in window && CONFIG.enableNotifications) {
            if (Notification.permission === 'default') {
                Notification.requestPermission();
            }
        }
    }

    /**
     * Handle keyboard shortcuts
     */
    function handleKeyboardShortcuts(e) {
        // Ctrl/Cmd + R for refresh
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            refreshCurrentPage();
        }

        // Escape to close modals
        if (e.key === 'Escape') {
            closeModals();
        }
    }

    /**
     * Refresh current page
     */
    function refreshCurrentPage() {
        navigateTo(window.location.href, false);
    }

    /**
     * Start periodic refresh
     */
    function startPeriodicRefresh() {
        state.refreshTimer = setInterval(() => {
            if (!document.hidden) {
                performSilentRefresh();
            }
        }, CONFIG.refreshInterval);
    }

    /**
     * Perform silent refresh (update data without full page reload)
     */
    function performSilentRefresh() {
        // This would update specific elements like download progress
        // without full page refresh
        updateDynamicContent();
    }

    /**
     * Update dynamic content
     */
    function updateDynamicContent() {
        // Update progress bars
        updateProgressBars();

        // Update statistics
        updateStatistics();

        // Update timestamps
        updateTimestamps();
    }

    /**
     * Initialize progress bars
     */
    function initializeProgressBars() {
        document.querySelectorAll('.progress-bar').forEach(bar => {
            const percentage = bar.getAttribute('data-percentage') || 0;
            bar.style.width = percentage + '%';
        });
    }

    /**
     * Update progress bars
     */
    function updateProgressBars() {
        document.querySelectorAll('[data-progress-id]').forEach(element => {
            const id = element.getAttribute('data-progress-id');
            // Fetch updated progress from server
            fetchProgressUpdate(id);
        });
    }

    /**
     * Fetch progress update
     */
    function fetchProgressUpdate(id) {
        ajaxRequest(`/api/progress/${id}`)
            .then(data => {
                updateProgressElement(id, data);
            })
            .catch(error => {
                console.warn('Failed to update progress:', error);
            });
    }

    /**
     * Update progress element
     */
    function updateProgressElement(id, data) {
        const element = document.querySelector(`[data-progress-id="${id}"]`);
        if (element) {
            element.style.width = data.percentage + '%';
            element.setAttribute('aria-valuenow', data.percentage);

            // Update status text
            const statusElement = element.closest('.progress-container')
                                   .querySelector('.progress-text');
            if (statusElement) {
                statusElement.textContent = `${data.percentage}% - ${data.status}`;
            }
        }
    }

    /**
     * Initialize sortable tables
     */
    function initializeSortableTables() {
        document.querySelectorAll('.table-sortable').forEach(table => {
            const headers = table.querySelectorAll('th[data-sort]');
            headers.forEach(header => {
                header.style.cursor = 'pointer';
                header.addEventListener('click', () => sortTable(table, header));
            });
        });
    }

    /**
     * Sort table
     */
    function sortTable(table, header) {
        const column = header.getAttribute('data-sort');
        const direction = header.getAttribute('data-direction') || 'asc';

        // Update direction
        header.setAttribute('data-direction', direction === 'asc' ? 'desc' : 'asc');

        // Sort rows
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));

        rows.sort((a, b) => {
            const aVal = a.querySelector(`[data-sort-value="${column}"]`)?.textContent || '';
            const bVal = b.querySelector(`[data-sort-value="${column}"]`)?.textContent || '';

            if (direction === 'asc') {
                return aVal.localeCompare(bVal);
            } else {
                return bVal.localeCompare(aVal);
            }
        });

        // Re-append sorted rows
        rows.forEach(row => tbody.appendChild(row));
    }

    /**
     * Initialize tooltips
     */
    function initializeTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.addEventListener('mouseenter', showTooltip);
            element.addEventListener('mouseleave', hideTooltip);
        });
    }

    /**
     * Show tooltip
     */
    function showTooltip(e) {
        const tooltip = createTooltip(e.target.getAttribute('data-tooltip'));
        document.body.appendChild(tooltip);

        const rect = e.target.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) + 'px';
        tooltip.style.top = rect.top - 30 + 'px';
    }

    /**
     * Hide tooltip
     */
    function hideTooltip() {
        const tooltip = document.querySelector('.tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    /**
     * Create tooltip element
     */
    function createTooltip(text) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = text;
        tooltip.style.cssText = `
            position: absolute;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            pointer-events: none;
            z-index: 10000;
            transform: translateX(-50%);
        `;
        return tooltip;
    }

    /**
     * Setup responsive features
     */
    function setupResponsiveFeatures() {
        // Mobile menu toggle
        const navToggle = document.createElement('button');
        navToggle.className = 'nav-toggle';
        navToggle.innerHTML = '☰';
        navToggle.style.cssText = `
            display: none;
            background: none;
            border: none;
            font-size: 1.5rem;
            color: #007bff;
            cursor: pointer;
        `;

        const header = document.querySelector('.header');
        if (header) {
            header.appendChild(navToggle);
            navToggle.addEventListener('click', toggleMobileMenu);
        }

        // Show/hide toggle based on screen size
        function checkScreenSize() {
            if (window.innerWidth <= 768) {
                navToggle.style.display = 'block';
                cache.navTabs.style.display = 'none';
            } else {
                navToggle.style.display = 'none';
                cache.navTabs.style.display = 'flex';
            }
        }

        window.addEventListener('resize', checkScreenSize);
        checkScreenSize();
    }

    /**
     * Toggle mobile menu
     */
    function toggleMobileMenu() {
        const nav = cache.navTabs;
        if (nav) {
            nav.style.display = nav.style.display === 'flex' ? 'none' : 'flex';
            if (nav.style.display === 'flex') {
                nav.style.flexDirection = 'column';
                nav.style.position = 'absolute';
                nav.style.top = '100%';
                nav.style.left = '0';
                nav.style.right = '0';
                nav.style.background = 'white';
                nav.style.boxShadow = '0 2px 10px rgba(0,0,0,0.1)';
            }
        }
    }

    /**
     * Handle online status
     */
    function handleOnlineStatus() {
        showNotification('Connection restored', 'success');
        refreshCurrentPage();
    }

    /**
     * Handle offline status
     */
    function handleOfflineStatus() {
        showNotification('Connection lost. Working offline.', 'error');
    }

    /**
     * Handle page visibility change
     */
    function handleVisibilityChange() {
        if (document.hidden) {
            // Pause updates when page is not visible
            clearInterval(state.refreshTimer);
        } else {
            // Resume updates
            startPeriodicRefresh();
            refreshCurrentPage();
        }
    }

    /**
     * Close modals
     */
    function closeModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }

    /**
     * Generate CSRF token
     */
    function generateCSRFToken() {
        return Math.random().toString(36).substring(2) + Date.now().toString(36);
    }

    /**
     * Update navigation state
     */
    function updateNavigationState(url) {
        // Update active tab based on URL
        document.querySelectorAll('.nav-tabs a').forEach(link => {
            link.removeAttribute('aria-current');
            if (link.getAttribute('href') === url) {
                link.setAttribute('aria-current', 'page');
                link.parentElement.classList.add('active');
            } else {
                link.parentElement.classList.remove('active');
            }
        });
    }

    /**
     * Update statistics
     */
    function updateStatistics() {
        // Update download/upload speeds, peer counts, etc.
        document.querySelectorAll('[data-stat]').forEach(element => {
            const stat = element.getAttribute('data-stat');
            fetchStatUpdate(stat);
        });
    }

    /**
     * Fetch stat update
     */
    function fetchStatUpdate(stat) {
        ajaxRequest(`/api/stats/${stat}`)
            .then(data => {
                const element = document.querySelector(`[data-stat="${stat}"]`);
                if (element) {
                    element.textContent = data.value;
                }
            })
            .catch(error => {
                console.warn('Failed to update stat:', error);
            });
    }

    /**
     * Update timestamps
     */
    function updateTimestamps() {
        document.querySelectorAll('[data-timestamp]').forEach(element => {
            const timestamp = parseInt(element.getAttribute('data-timestamp'));
            const now = Date.now();
            const diff = now - timestamp;

            element.textContent = formatTimeAgo(diff);
        });
    }

    /**
     * Format time ago
     */
    function formatTimeAgo(diff) {
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return `${seconds}s ago`;
    }

    /**
     * Hide loading screen
     */
    function hideLoadingScreen() {
        setTimeout(() => {
            if (cache.loadingScreen) {
                cache.loadingScreen.classList.add('hidden');
                setTimeout(() => {
                    cache.loadingScreen.style.display = 'none';
                }, 300);
            }
        }, 1000);
    }

    // Browser history support
    window.addEventListener('popstate', (e) => {
        if (e.state && e.state.url) {
            navigateTo(e.state.url, false);
        }
    });

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose public API
    window.EnvyRemote = {
        navigateTo,
        refreshCurrentPage,
        showNotification,
        ajaxRequest
    };

})();