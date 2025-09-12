/**
 * Web Network Scanner - Main JavaScript
 * Common functions and utilities for the web interface
 */

$(document).ready(function() {
    // Initialize tooltips
    initializeTooltips();
    
    // Set active navigation item
    setActiveNavigation();
    
    // Initialize global error handler
    setupGlobalErrorHandler();
});

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Set active navigation item based on current page
 */
function setActiveNavigation() {
    const currentPath = window.location.pathname;
    $('.navbar-nav .nav-link').removeClass('active');
    
    if (currentPath === '/') {
        $('.navbar-nav .nav-link[href="/"]').addClass('active');
    } else if (currentPath.includes('/port-scanner')) {
        $('.navbar-nav .nav-link[href="/port-scanner"]').addClass('active');
    } else if (currentPath.includes('/packet-sniffer')) {
        $('.navbar-nav .nav-link[href="/packet-sniffer"]').addClass('active');
    }
}

/**
 * Setup global AJAX error handler
 */
function setupGlobalErrorHandler() {
    $(document).ajaxError(function(event, xhr, settings, error) {
        console.error('AJAX Error:', {
            url: settings.url,
            status: xhr.status,
            error: error,
            response: xhr.responseText
        });
        
        // Show user-friendly error message for network errors
        if (xhr.status === 0) {
            showNotification('Connection Error', 'Unable to connect to the server. Please check your connection.', 'error');
        }
    });
}

/**
 * Show notification toast
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, warning, info)
 */
function showNotification(title, message, type = 'info') {
    const toastId = 'toast-' + Date.now();
    const iconClass = {
        'success': 'fas fa-check-circle text-success',
        'error': 'fas fa-exclamation-circle text-danger',
        'warning': 'fas fa-exclamation-triangle text-warning',
        'info': 'fas fa-info-circle text-info'
    };
    
    const toastHtml = `
        <div class="toast" id="${toastId}" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <i class="${iconClass[type] || iconClass.info} me-2"></i>
                <strong class="me-auto">${title}</strong>
                <small class="text-muted">now</small>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    // Create toast container if it doesn't exist
    if (!$('#toast-container').length) {
        $('body').append(`
            <div id="toast-container" class="position-fixed top-0 end-0 p-3" style="z-index: 9999;">
            </div>
        `);
    }
    
    $('#toast-container').append(toastHtml);
    
    const toast = new bootstrap.Toast(document.getElementById(toastId), {
        delay: 5000
    });
    toast.show();
    
    // Remove toast element after it's hidden
    $(`#${toastId}`).on('hidden.bs.toast', function() {
        $(this).remove();
    });
}

/**
 * Validate IP address
 * @param {string} ip - IP address to validate
 * @returns {boolean} - True if valid IP
 */
function isValidIP(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Validate CIDR notation
 * @param {string} cidr - CIDR notation to validate
 * @returns {boolean} - True if valid CIDR
 */
function isValidCIDR(cidr) {
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
    return cidrRegex.test(cidr);
}

/**
 * Validate port number
 * @param {number} port - Port number to validate
 * @returns {boolean} - True if valid port
 */
function isValidPort(port) {
    return port >= 1 && port <= 65535;
}

/**
 * Validate port range
 * @param {string} range - Port range to validate (e.g., "1-1000")
 * @returns {boolean} - True if valid range
 */
function isValidPortRange(range) {
    const rangeRegex = /^(\d+)-(\d+)$/;
    const match = range.match(rangeRegex);
    
    if (!match) return false;
    
    const start = parseInt(match[1]);
    const end = parseInt(match[2]);
    
    return isValidPort(start) && isValidPort(end) && start <= end;
}

/**
 * Format bytes to human readable format
 * @param {number} bytes - Number of bytes
 * @returns {string} - Formatted string
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format timestamp to relative time
 * @param {string} timestamp - ISO timestamp
 * @returns {string} - Relative time string
 */
function formatRelativeTime(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diffMs = now - time;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffSecs < 60) {
        return diffSecs === 1 ? '1 second ago' : `${diffSecs} seconds ago`;
    } else if (diffMins < 60) {
        return diffMins === 1 ? '1 minute ago' : `${diffMins} minutes ago`;
    } else if (diffHours < 24) {
        return diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
    } else {
        return diffDays === 1 ? '1 day ago' : `${diffDays} days ago`;
    }
}

/**
 * Debounce function to limit function calls
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @param {Function} callback - Optional callback function
 */
function copyToClipboard(text, callback) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            if (callback) callback(true);
            showNotification('Copied', 'Text copied to clipboard', 'success');
        }).catch(() => {
            if (callback) callback(false);
            showNotification('Error', 'Failed to copy text', 'error');
        });
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            textArea.remove();
            if (callback) callback(true);
            showNotification('Copied', 'Text copied to clipboard', 'success');
        } catch (err) {
            textArea.remove();
            if (callback) callback(false);
            showNotification('Error', 'Failed to copy text', 'error');
        }
    }
}

/**
 * Download data as file
 * @param {string} data - Data to download
 * @param {string} filename - Filename for download
 * @param {string} type - MIME type
 */
function downloadAsFile(data, filename, type = 'text/plain') {
    const blob = new Blob([data], { type: type });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Parse CSV data
 * @param {string} csv - CSV data
 * @returns {Array} - Array of objects
 */
function parseCSV(csv) {
    const lines = csv.split('\n');
    const headers = lines[0].split(',');
    const result = [];
    
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') continue;
        
        const values = line.split(',');
        const obj = {};
        
        headers.forEach((header, index) => {
            obj[header.trim()] = values[index] ? values[index].trim() : '';
        });
        
        result.push(obj);
    }
    
    return result;
}

/**
 * Get current theme preference
 * @returns {string} - 'light' or 'dark'
 */
function getTheme() {
    return localStorage.getItem('theme') || 
           (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}

/**
 * Set theme preference
 * @param {string} theme - 'light' or 'dark'
 */
function setTheme(theme) {
    localStorage.setItem('theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
}

// Global keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+/ or Cmd+/ to show help
    if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        showKeyboardShortcuts();
    }
    
    // Escape to close modals
    if (e.key === 'Escape') {
        $('.modal.show').modal('hide');
    }
});

/**
 * Show keyboard shortcuts modal
 */
function showKeyboardShortcuts() {
    const shortcuts = [
        { keys: 'Ctrl + /', description: 'Show keyboard shortcuts' },
        { keys: 'Escape', description: 'Close modals' },
        { keys: 'Ctrl + R', description: 'Refresh page' },
    ];
    
    let shortcutsList = shortcuts.map(s => 
        `<tr><td><kbd>${s.keys}</kbd></td><td>${s.description}</td></tr>`
    ).join('');
    
    const modalHtml = `
        <div class="modal fade" id="shortcutsModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Keyboard Shortcuts</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <table class="table table-sm">
                            <thead>
                                <tr><th>Shortcut</th><th>Description</th></tr>
                            </thead>
                            <tbody>
                                ${shortcutsList}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal if present
    $('#shortcutsModal').remove();
    $('body').append(modalHtml);
    $('#shortcutsModal').modal('show');
    
    // Clean up when modal is hidden
    $('#shortcutsModal').on('hidden.bs.modal', function() {
        $(this).remove();
    });
}