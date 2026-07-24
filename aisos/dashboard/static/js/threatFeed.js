/**
 * ThreatFeed - Live scrolling threat event feed
 * FILE 8 of AI-SOS Premium Security Dashboard
 */

const SEVERITY_CONFIG = {
    CRITICAL: { color: '#FF3366', bg: 'rgba(255,51,102,0.15)',   icon: '🔴', pulse: true  },
    HIGH:     { color: '#FF6B35', bg: 'rgba(255,107,53,0.12)',   icon: '🟠', pulse: false },
    MEDIUM:   { color: '#FFB800', bg: 'rgba(255,184,0,0.12)',    icon: '🟡', pulse: false },
    LOW:      { color: '#00D4FF', bg: 'rgba(0,212,255,0.10)',    icon: '🔵', pulse: false },
    INFO:     { color: '#6B8CAE', bg: 'rgba(107,140,174,0.08)', icon: '⚪', pulse: false },
};

const DECISION_CONFIG = {
    BLOCK:      { color: '#FF3366', label: 'BLOCK'      },
    MONITOR:    { color: '#00D4FF', label: 'MONITOR'    },
    ALLOW:      { color: '#00FF9F', label: 'ALLOW'      },
    RATE_LIMIT: { color: '#FFB800', label: 'RATE LIMIT' },
    CHALLENGE:  { color: '#B44FFF', label: 'CHALLENGE'  },
};

const ATTACK_ICONS = {
    'sql_injection':      '💉',
    'xss':                '📜',
    'prompt_injection':   '🤖',
    'path_traversal':     '📁',
    'brute_force':        '🔨',
    'bot':                '🤖',
    'ddos':               '⚡',
    'command_injection':  '💻',
    'data_exfiltration':  '📤',
    'default':            '⚠️',
};

/**
 * Returns a human-readable "time ago" string for a Unix timestamp (seconds).
 * @param {number} ts - Unix timestamp in seconds
 * @returns {string}
 */
function timeAgo(ts) {
    const diff = (Date.now() / 1000) - ts;
    if (diff < 60)   return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
}

/**
 * Escapes a string for safe insertion into HTML attribute values or text.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

class ThreatFeed {
    /**
     * @param {string} containerId - ID of the DOM element acting as the scrollable feed container.
     */
    constructor(containerId) {
        this.container     = document.getElementById(containerId);
        this.events        = [];          // In-memory ring buffer
        this.maxEvents     = 200;         // Maximum events kept in memory
        this.paused        = false;       // Whether new events are rendered
        this.autoScroll    = true;        // Scroll to newest item
        this.filterSeverity = '';         // Active severity filter
        this.filterDecision = '';         // Active decision filter
        this.searchQuery   = '';          // Active search string (lowercased)
        this._eventCount   = 0;           // Used to deduplicate IDs
        this._setupControls();
    }

    // ─────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────

    /** Wires up all toolbar control elements if present in the DOM. */
    _setupControls() {
        // Pause / Resume
        const pauseBtn = document.getElementById('pause-feed');
        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => {
                this.paused = !this.paused;
                pauseBtn.textContent = this.paused ? '▶ Resume' : '⏸ Pause';
                pauseBtn.classList.toggle('btn-active', this.paused);
            });
        }

        // Clear
        const clearBtn = document.getElementById('clear-feed');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clear());
        }

        // Export
        const exportBtn = document.getElementById('export-events');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportJSON());
        }

        // Severity filter
        const sevFilter = document.getElementById('filter-severity');
        if (sevFilter) {
            sevFilter.addEventListener('change', (e) => {
                this.filterSeverity = e.target.value;
                this._rerender();
            });
        }

        // Decision filter
        const decFilter = document.getElementById('filter-decision');
        if (decFilter) {
            decFilter.addEventListener('change', (e) => {
                this.filterDecision = e.target.value;
                this._rerender();
            });
        }

        // Search
        const searchInput = document.getElementById('search-feed');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.toLowerCase().trim();
                this._rerender();
            });
        }

        // Auto-scroll detection on manual scroll
        if (this.container) {
            this.container.addEventListener('scroll', () => {
                const atTop = this.container.scrollTop <= 50;
                this.autoScroll = atTop;
            }, { passive: true });
        }
    }

    // ─────────────────────────────────────────────
    // Filtering
    // ─────────────────────────────────────────────

    /**
     * Returns true if the given event passes all active filters.
     * @param {object} event
     * @returns {boolean}
     */
    _matches(event) {
        if (this.filterSeverity && event.severity !== this.filterSeverity) return false;
        if (this.filterDecision && event.decision !== this.filterDecision) return false;
        if (this.searchQuery) {
            const q   = this.searchQuery;
            const ip  = (event.source_ip || '').toLowerCase();
            const path = (event.path || '').toLowerCase();
            const cat  = (event.attack_category || '').toLowerCase();
            if (!ip.includes(q) && !path.includes(q) && !cat.includes(q)) return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────

    /**
     * Ingests a new threat event object and, if not paused and passing filters,
     * prepends a row to the feed container.
     *
     * @param {object} eventData - Threat event. Expected fields:
     *   event_id, timestamp, severity, decision, attack_category,
     *   source_ip, path, method, risk_score, user_agent, reasoning, indicators[]
     */
    addEvent(eventData) {
        // Assign a local ID if missing
        if (!eventData.event_id) {
            eventData.event_id = `local-${++this._eventCount}`;
        }

        // Push into ring buffer
        this.events.push(eventData);
        if (this.events.length > this.maxEvents) {
            this.events.shift();
        }

        // Update live badge counter (if present)
        this._updateBadge();

        if (this.paused) return;

        if (this._matches(eventData)) {
            this._renderItem(eventData, true);

            // Trim excess DOM nodes
            if (this.container) {
                const items = this.container.querySelectorAll('.threat-item');
                if (items.length > this.maxEvents) {
                    items[items.length - 1].remove();
                }
            }

            // Auto-scroll to top (newest)
            if (this.autoScroll && this.container) {
                this.container.scrollTop = 0;
            }
        }
    }

    /**
     * Removes all events from memory and clears the DOM feed.
     */
    clear() {
        this.events = [];
        if (this.container) this.container.innerHTML = '';
        this._updateBadge();
    }

    /**
     * Downloads all stored events as a JSON file.
     */
    exportJSON() {
        const blob = new Blob(
            [JSON.stringify(this.events, null, 2)],
            { type: 'application/json' }
        );
        const url = URL.createObjectURL(blob);
        const a   = document.createElement('a');
        a.href     = url;
        a.download = `aisos-events-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ─────────────────────────────────────────────
    // Rendering
    // ─────────────────────────────────────────────

    /**
     * Re-renders the entire feed container from the in-memory event buffer
     * applying active filters. Used when a filter changes.
     */
    _rerender() {
        if (!this.container) return;
        this.container.innerHTML = '';
        const filtered = this.events.filter(e => this._matches(e));
        // Show last 100 matching in reverse-chronological order
        filtered.slice(-100).reverse().forEach(e => this._renderItem(e, false));
    }

    /**
     * Creates and inserts a single threat row element.
     * @param {object} event
     * @param {boolean} prepend - If true, inserts at top; else appends.
     */
    _renderItem(event, prepend = false) {
        if (!this.container) return;

        const sev     = event.severity || 'INFO';
        const dec     = event.decision || 'ALLOW';
        const sevConf = SEVERITY_CONFIG[sev]  || SEVERITY_CONFIG.INFO;
        const decConf = DECISION_CONFIG[dec]  || DECISION_CONFIG.ALLOW;
        const atkIcon = ATTACK_ICONS[event.attack_category] || ATTACK_ICONS.default;
        const ts      = event.timestamp ? timeAgo(event.timestamp) : 'now';

        const safePath = escapeHtml((event.path || '/').substring(0, 40));
        const safeIp   = escapeHtml(event.source_ip || 'N/A');
        const safeCat  = escapeHtml((event.attack_category || 'unknown').replace(/_/g, ' '));
        const safeAtk  = escapeHtml(event.attack_category || 'unknown');

        const el = document.createElement('div');
        el.className  = `threat-item${sevConf.pulse ? ' pulse-item' : ''}`;
        el.style.cssText = `
            border-left: 3px solid ${sevConf.color};
            background: ${sevConf.bg};
        `;
        el.dataset.eventId = event.event_id;

        el.innerHTML = `
            <div class="threat-item-main">
                <span class="threat-sev-badge"
                      style="color:${sevConf.color};border-color:${sevConf.color};"
                      title="Severity: ${sev}">${escapeHtml(sev)}</span>
                <span class="attack-icon" title="${safeAtk}">${atkIcon}</span>
                <span class="threat-category">${safeCat}</span>
                <span class="threat-ip"
                      title="Source IP">${safeIp}</span>
                <span class="threat-path"
                      title="${escapeHtml(event.path || '')}">${safePath}</span>
                <span class="threat-dec-badge"
                      style="color:${decConf.color};border-color:${decConf.color};"
                      title="Decision: ${dec}">${escapeHtml(decConf.label)}</span>
                <span class="threat-time"
                      title="${event.timestamp ? new Date(event.timestamp * 1000).toISOString() : ''}">${ts}</span>
                <span class="threat-expand-arrow">▶</span>
            </div>
        `;

        // Toggle expand on click
        el.addEventListener('click', () => this._expandEvent(el, event));

        if (prepend) {
            el.classList.add('slide-in');
            this.container.prepend(el);
        } else {
            this.container.appendChild(el);
        }
    }

    /**
     * Toggles the expanded detail panel beneath a threat item row.
     * @param {HTMLElement} el
     * @param {object} event
     */
    _expandEvent(el, event) {
        const existing = el.querySelector('.threat-detail');
        if (existing) {
            existing.remove();
            const arrow = el.querySelector('.threat-expand-arrow');
            if (arrow) arrow.textContent = '▶';
            return;
        }

        const arrow = el.querySelector('.threat-expand-arrow');
        if (arrow) arrow.textContent = '▼';

        const indicators = Array.isArray(event.indicators) ? event.indicators : [];
        const agentContribs = event.agent_contributions
            ? Object.entries(event.agent_contributions)
                  .map(([k, v]) => `<span class="contrib-item"><strong>${escapeHtml(k)}:</strong> ${(+v).toFixed(3)}</span>`)
                  .join('')
            : '—';

        const detail = document.createElement('div');
        detail.className = 'threat-detail';
        detail.innerHTML = `
            <div class="detail-grid">
                <div class="detail-row">
                    <strong>Event ID:</strong>
                    <code>${escapeHtml(event.event_id || 'N/A')}</code>
                </div>
                <div class="detail-row">
                    <strong>Method:</strong>
                    <span>${escapeHtml(event.method || 'N/A')}</span>
                </div>
                <div class="detail-row">
                    <strong>Risk Score:</strong>
                    <span class="risk-score-value" style="color:${this._riskColor(event.risk_score)};">
                        ${(+(event.risk_score || 0)).toFixed(4)}
                    </span>
                </div>
                <div class="detail-row">
                    <strong>Confidence:</strong>
                    <span>${event.confidence !== undefined ? (+(event.confidence)).toFixed(2) : 'N/A'}</span>
                </div>
                <div class="detail-row detail-row--full">
                    <strong>User Agent:</strong>
                    <span class="ua-text">${escapeHtml((event.user_agent || 'N/A').substring(0, 120))}</span>
                </div>
                <div class="detail-row detail-row--full">
                    <strong>Reasoning:</strong>
                    <span class="reasoning-text">${escapeHtml(event.reasoning || 'N/A')}</span>
                </div>
                <div class="detail-row detail-row--full">
                    <strong>Indicators:</strong>
                    <span>${indicators.length ? indicators.map(i => `<span class="indicator-tag">${escapeHtml(i)}</span>`).join('') : 'None'}</span>
                </div>
                <div class="detail-row detail-row--full">
                    <strong>Agent Contributions:</strong>
                    <div class="contrib-row">${agentContribs}</div>
                </div>
            </div>
        `;

        el.appendChild(detail);
    }

    // ─────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────

    /**
     * Returns an appropriate colour hex for a 0-1 risk score.
     * @param {number} score
     * @returns {string}
     */
    _riskColor(score) {
        const v = +(score || 0);
        if (v >= 0.7) return '#FF3366';
        if (v >= 0.4) return '#FFB800';
        return '#00FF9F';
    }

    /**
     * Refreshes the feed badge counter element (#feed-badge) if it exists.
     */
    _updateBadge() {
        const badge = document.getElementById('feed-badge');
        if (badge) {
            badge.textContent = this.events.length.toLocaleString();
            badge.style.display = this.events.length > 0 ? 'inline-flex' : 'none';
        }
    }
}

export default ThreatFeed;
