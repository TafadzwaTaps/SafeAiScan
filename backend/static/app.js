// SafeScan AI - Vanilla JavaScript Application
(function() {
    'use strict';

    // API Configuration
    const API_BASE = window.location.origin + '/api';

    // DOM Elements
    const elements = {
        inputText: document.getElementById('input-text'),
        charCount: document.getElementById('char-count'),
        analyzeBtn: document.getElementById('analyze-btn'),
        clearInputBtn: document.getElementById('clear-input-btn'),
        loadingSection: document.getElementById('loading-section'),
        loadingProgress: document.getElementById('loading-progress'),
        loadingMessage: document.getElementById('loading-message'),
        resultsSection: document.getElementById('results-section'),
        riskBadge: document.getElementById('risk-badge'),
        explanationText: document.getElementById('explanation-text'),
        fixesList: document.getElementById('fixes-list'),
        resultTimestamp: document.getElementById('result-timestamp'),
        copyResultsBtn: document.getElementById('copy-results-btn'),
        errorSection: document.getElementById('error-section'),
        errorMessage: document.getElementById('error-message'),
        historyList: document.getElementById('history-list'),
        clearHistoryBtn: document.getElementById('clear-history-btn'),
        sidebar: document.getElementById('sidebar'),
        sidebarToggle: document.getElementById('sidebar-toggle'),
        toast: document.getElementById('toast'),
        toastMessage: document.getElementById('toast-message')
    };

    // Example data cache
    let examplesCache = null;

    // Current analysis result
    let currentResult = null;

    // Initialize application
    function init() {
        setupEventListeners();
        loadHistory();
        loadExamples();
        updateCharCount();
    }

    // Setup event listeners
    function setupEventListeners() {
        // Input events
        elements.inputText.addEventListener('input', updateCharCount);
        elements.clearInputBtn.addEventListener('click', clearInput);
        
        // Analyze button
        elements.analyzeBtn.addEventListener('click', analyzeInput);
        
        // Copy results
        elements.copyResultsBtn.addEventListener('click', copyResults);
        
        // History
        elements.clearHistoryBtn.addEventListener('click', clearHistory);
        
        // Sidebar toggle (mobile)
        elements.sidebarToggle.addEventListener('click', toggleSidebar);
        
        // Example buttons
        document.querySelectorAll('[data-example]').forEach(btn => {
            btn.addEventListener('click', () => loadExample(btn.dataset.example));
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', handleKeyboard);
        
        // Close sidebar on outside click (mobile)
        document.addEventListener('click', (e) => {
            if (window.innerWidth < 992 && 
                elements.sidebar.classList.contains('open') &&
                !elements.sidebar.contains(e.target) &&
                !elements.sidebarToggle.contains(e.target)) {
                elements.sidebar.classList.remove('open');
            }
        });
    }

    // Update character count
    function updateCharCount() {
        const count = elements.inputText.value.length;
        elements.charCount.textContent = `${count.toLocaleString()} / 50,000`;
        
        if (count > 50000) {
            elements.charCount.style.color = 'var(--risk-high)';
        } else if (count > 40000) {
            elements.charCount.style.color = 'var(--risk-medium)';
        } else {
            elements.charCount.style.color = 'var(--text-muted)';
        }
    }

    // Clear input
    function clearInput() {
        elements.inputText.value = '';
        updateCharCount();
        hideError();
        hideResults();
        elements.inputText.focus();
    }

    // Toggle sidebar (mobile)
    function toggleSidebar() {
        elements.sidebar.classList.toggle('open');
    }

    // Keyboard shortcuts
    function handleKeyboard(e) {
        // Ctrl/Cmd + Enter to analyze
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            analyzeInput();
        }
    }

    // Load examples from API
    async function loadExamples() {
        try {
            const response = await fetch(`${API_BASE}/examples`);
            if (response.ok) {
                const data = await response.json();
                examplesCache = data.examples;
            }
        } catch (error) {
            console.error('Failed to load examples:', error);
        }
    }

    // Load example into textarea
    function loadExample(type) {
        if (!examplesCache) return;
        
        const example = examplesCache.find(ex => ex.type === type);
        if (example) {
            elements.inputText.value = example.content;
            updateCharCount();
            hideError();
            hideResults();
            showToast(`Loaded ${example.name} example`);
        }
    }

    // Analyze input
    async function analyzeInput() {
        const text = elements.inputText.value.trim();
        
        // Validation
        if (text.length < 10) {
            showError('Input too short. Please provide at least 10 characters.');
            return;
        }
        
        if (text.length > 50000) {
            showError('Input too long. Maximum 50,000 characters allowed.');
            return;
        }
        
        // Show loading
        hideError();
        hideResults();
        showLoading();
        
        try {
            const response = await fetch(`${API_BASE}/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ text })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `Analysis failed (${response.status})`);
            }
            
            const result = await response.json();
            currentResult = result;
            
            hideLoading();
            displayResults(result);
            loadHistory(); // Refresh history
            
        } catch (error) {
            hideLoading();
            showError(error.message || 'Analysis failed. Please try again.');
        }
    }

    // Show loading state
    function showLoading() {
        elements.analyzeBtn.disabled = true;
        elements.loadingSection.style.display = 'block';
        
        // Animate loading messages
        const messages = [
            'SCANNING PAYLOAD...',
            'ANALYZING PATTERNS...',
            'DETECTING THREATS...',
            'EVALUATING RISK LEVEL...',
            'GENERATING REPORT...'
        ];
        
        let msgIndex = 0;
        const messageInterval = setInterval(() => {
            msgIndex = (msgIndex + 1) % messages.length;
            elements.loadingMessage.textContent = messages[msgIndex];
        }, 1500);
        
        // Store interval ID for cleanup
        elements.loadingSection.dataset.interval = messageInterval;
    }

    // Hide loading state
    function hideLoading() {
        elements.analyzeBtn.disabled = false;
        elements.loadingSection.style.display = 'none';
        
        // Clear message interval
        const intervalId = elements.loadingSection.dataset.interval;
        if (intervalId) {
            clearInterval(parseInt(intervalId));
        }
    }

    // Display results
    function displayResults(result) {
        // Risk badge
        const riskLower = result.risk.toLowerCase();
        elements.riskBadge.textContent = result.risk.toUpperCase();
        elements.riskBadge.className = `risk-badge ${riskLower}`;
        
        // Explanation
        elements.explanationText.textContent = result.explanation;
        
        // Fixes
        elements.fixesList.innerHTML = '';
        result.fixes.forEach(fix => {
            const li = document.createElement('li');
            li.textContent = fix;
            elements.fixesList.appendChild(li);
        });
        
        // Timestamp
        const timestamp = new Date(result.timestamp);
        elements.resultTimestamp.textContent = timestamp.toLocaleString();
        
        // Show section
        elements.resultsSection.style.display = 'block';
        
        // Scroll to results
        elements.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Hide results
    function hideResults() {
        elements.resultsSection.style.display = 'none';
        currentResult = null;
    }

    // Show error
    function showError(message) {
        elements.errorMessage.textContent = message;
        elements.errorSection.style.display = 'block';
    }

    // Hide error
    function hideError() {
        elements.errorSection.style.display = 'none';
    }

    // Copy results to clipboard
    async function copyResults() {
        if (!currentResult) return;
        
        const text = `Security Analysis Report
========================
Risk Level: ${currentResult.risk.toUpperCase()}

Analysis:
${currentResult.explanation}

Recommended Actions:
${currentResult.fixes.map((fix, i) => `${i + 1}. ${fix}`).join('\n')}

Analyzed at: ${new Date(currentResult.timestamp).toLocaleString()}
Generated by SafeScan AI`;

        try {
            await navigator.clipboard.writeText(text);
            showToast('Results copied to clipboard');
        } catch (error) {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            showToast('Results copied to clipboard');
        }
    }

    // Load history from API
    async function loadHistory() {
        try {
            const response = await fetch(`${API_BASE}/history`);
            if (response.ok) {
                const history = await response.json();
                displayHistory(history);
            }
        } catch (error) {
            console.error('Failed to load history:', error);
        }
    }

    // Display history items
    function displayHistory(history) {
        if (history.length === 0) {
            elements.historyList.innerHTML = `
                <div class="history-empty">
                    <i class="ph ph-folder-open" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                    <p>No analysis history yet</p>
                </div>
            `;
            return;
        }
        
        elements.historyList.innerHTML = history.map(item => `
            <div class="history-item" data-testid="history-item-${item.id}" data-id="${item.id}">
                <div class="history-item-header">
                    <span class="history-risk ${item.risk_level.toLowerCase()}">${item.risk_level}</span>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="history-time">${formatTime(item.timestamp)}</span>
                        <button class="history-delete" data-testid="delete-history-${item.id}" aria-label="Delete this analysis">
                            <i class="ph ph-x"></i>
                        </button>
                    </div>
                </div>
                <p class="history-preview">${escapeHtml(item.input_preview)}</p>
            </div>
        `).join('');
        
        // Add click handlers
        elements.historyList.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (!e.target.closest('.history-delete')) {
                    showHistoryItem(item.dataset.id, history);
                }
            });
        });
        
        elements.historyList.querySelectorAll('.history-delete').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const item = btn.closest('.history-item');
                deleteHistoryItem(item.dataset.id);
            });
        });
    }

    // Show history item details
    function showHistoryItem(id, history) {
        const item = history.find(h => h.id === id);
        if (item) {
            currentResult = {
                id: item.id,
                risk: item.risk_level,
                explanation: item.explanation,
                fixes: item.fixes,
                timestamp: item.timestamp
            };
            displayResults(currentResult);
            
            // Close sidebar on mobile
            if (window.innerWidth < 992) {
                elements.sidebar.classList.remove('open');
            }
        }
    }

    // Delete history item
    async function deleteHistoryItem(id) {
        try {
            const response = await fetch(`${API_BASE}/history/${id}`, {
                method: 'DELETE'
            });
            
            if (response.ok) {
                loadHistory();
                showToast('Analysis deleted');
                
                // Hide results if viewing deleted item
                if (currentResult && currentResult.id === id) {
                    hideResults();
                }
            }
        } catch (error) {
            showError('Failed to delete item');
        }
    }

    // Clear all history
    async function clearHistory() {
        if (!confirm('Clear all analysis history?')) return;
        
        try {
            const response = await fetch(`${API_BASE}/history`, {
                method: 'DELETE'
            });
            
            if (response.ok) {
                loadHistory();
                hideResults();
                showToast('History cleared');
            }
        } catch (error) {
            showError('Failed to clear history');
        }
    }

    // Show toast notification
    function showToast(message) {
        elements.toastMessage.textContent = message;
        elements.toast.classList.add('show');
        
        setTimeout(() => {
            elements.toast.classList.remove('show');
        }, 3000);
    }

    // Format timestamp
    function formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
        
        return date.toLocaleDateString();
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
