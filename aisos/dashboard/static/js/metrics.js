/**
 * MetricsPanel - Live metrics charts using the Canvas 2D API
 * FILE 10 of AI-SOS Premium Security Dashboard
 */

const HISTORY_LENGTH = 60;   // Data points kept per time-series

class MetricsPanel {
    /**
     * @param {string} containerId - Container element ID (unused directly but
     *   kept for API consistency; chart canvases are fetched by fixed IDs).
     */
    constructor(containerId) {
        this.containerId = containerId;

        // Time-series ring buffers
        this.rpsData  = new Array(HISTORY_LENGTH).fill(0);
        this.riskData = new Array(HISTORY_LENGTH).fill(0);

        // Decision distribution counters
        this.decisions = {
            ALLOW:      0,
            BLOCK:      0,
            MONITOR:    0,
            RATE_LIMIT: 0,
            CHALLENGE:  0,
        };

        // Summary stats
        this.stats = {
            total:   0,
            threats: 0,
            blocks:  0,
            fp:      0,
        };

        // Previous snapshot for trend calculation
        this._prevStats = { total: 0, threats: 0, blocks: 0, fp: 0 };

        // Canvas element references (populated in initCharts)
        this.canvases = {};

        // Resize handler ref (for cleanup)
        this._resizeHandler = () => this._renderAll();
    }

    // ─────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────

    /**
     * Fetches canvas elements and performs initial render. Call once after
     * the DOM is ready.
     */
    initCharts() {
        this.canvases.rps       = document.getElementById('chart-rps');
        this.canvases.risk      = document.getElementById('chart-risk');
        this.canvases.decisions = document.getElementById('chart-decisions');

        this._renderStatsRow();
        this._renderAll();

        window.addEventListener('resize', this._resizeHandler);
    }

    /**
     * Ingests a metrics payload from the backend WebSocket feed and
     * re-renders all charts.
     *
     * @param {object} data - Expected fields (all optional):
     *   requests_per_sec, avg_risk_score, decision_counts{},
     *   total_events, total_threats, total_blocks, false_positives
     */
    updateMetrics(data) {
        // ── Time-series ───────────────────────────────────────────
        if (data.requests_per_sec !== undefined) {
            this.rpsData.shift();
            this.rpsData.push(Math.max(0, +data.requests_per_sec || 0));
        }
        if (data.avg_risk_score !== undefined) {
            this.riskData.shift();
            this.riskData.push(Math.min(1, Math.max(0, +data.avg_risk_score || 0)));
        }

        // ── Decisions ─────────────────────────────────────────────
        if (data.decision_counts && typeof data.decision_counts === 'object') {
            Object.entries(data.decision_counts).forEach(([k, v]) => {
                if (k in this.decisions) this.decisions[k] = +v || 0;
            });
        }

        // ── Summary stats ─────────────────────────────────────────
        this._prevStats = { ...this.stats };
        if (data.total_events   !== undefined) this.stats.total   = +data.total_events   || 0;
        if (data.total_threats  !== undefined) this.stats.threats = +data.total_threats  || 0;
        if (data.total_blocks   !== undefined) this.stats.blocks  = +data.total_blocks   || 0;
        if (data.false_positives !== undefined) this.stats.fp     = +data.false_positives || 0;

        this._renderAll();
        this._updateStatsRow();
    }

    /** Removes event listeners (call when tearing down). */
    destroy() {
        window.removeEventListener('resize', this._resizeHandler);
    }

    // ─────────────────────────────────────────────
    // Rendering orchestration
    // ─────────────────────────────────────────────

    _renderAll() {
        this._drawLineChart('rps',   this.rpsData,  '#00D4FF', 'Req/s');
        this._drawRiskChart('risk',  this.riskData);
        this._drawDecisionChart('decisions', this.decisions);
    }

    // ─────────────────────────────────────────────
    // Chart: RPS line chart
    // ─────────────────────────────────────────────

    /**
     * Draws a filled line chart (area chart) for any 1-D data series.
     * @param {string}   key       - Key in this.canvases
     * @param {number[]} data      - Data points
     * @param {string}   lineColor - CSS hex colour
     * @param {string}   label     - Chart label (unused visually; kept for aria)
     */
    _drawLineChart(key, data, lineColor, label) {
        const canvas = this.canvases[key];
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        const w = canvas.offsetWidth  || canvas.clientWidth  || 300;
        const h = canvas.offsetHeight || canvas.clientHeight || 80;
        canvas.width  = w;
        canvas.height = h;

        const max    = Math.max(...data, 1);
        const xStep  = data.length > 1 ? w / (data.length - 1) : w;
        const pad    = 8;

        ctx.clearRect(0, 0, w, h);

        // ── Grid ──────────────────────────────────────────────────
        ctx.save();
        ctx.strokeStyle = 'rgba(107,140,174,0.15)';
        ctx.lineWidth   = 1;
        for (let i = 0; i <= 3; i++) {
            const y = (i / 3) * h;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
        ctx.restore();

        // ── Gradient fill ─────────────────────────────────────────
        const rgb      = this._hexToRgb(lineColor);
        const fillGrad = ctx.createLinearGradient(0, 0, 0, h);
        fillGrad.addColorStop(0,   `rgba(${rgb},0.30)`);
        fillGrad.addColorStop(0.7, `rgba(${rgb},0.06)`);
        fillGrad.addColorStop(1,   `rgba(${rgb},0.00)`);

        ctx.beginPath();
        ctx.moveTo(0, h);
        data.forEach((val, i) => {
            const x = i * xStep;
            const y = h - (val / max) * (h - pad);
            ctx.lineTo(x, y);
        });
        ctx.lineTo((data.length - 1) * xStep, h);
        ctx.closePath();
        ctx.fillStyle = fillGrad;
        ctx.fill();

        // ── Line ──────────────────────────────────────────────────
        ctx.beginPath();
        data.forEach((val, i) => {
            const x = i * xStep;
            const y = h - (val / max) * (h - pad);
            if (i === 0) ctx.moveTo(x, y);
            else         ctx.lineTo(x, y);
        });
        ctx.strokeStyle = lineColor;
        ctx.lineWidth   = 2;
        ctx.lineJoin    = 'round';
        ctx.stroke();

        // ── Current value label ───────────────────────────────────
        const current = data[data.length - 1];
        ctx.fillStyle  = lineColor;
        ctx.font       = 'bold 11px Inter, sans-serif';
        ctx.textAlign  = 'right';
        ctx.fillText(current.toFixed(1), w - 4, 14);
    }

    // ─────────────────────────────────────────────
    // Chart: Risk score (colour-coded)
    // ─────────────────────────────────────────────

    /**
     * Draws a segmented risk-score line chart where colour shifts from
     * green (low) → amber (medium) → red (high) based on the value.
     * @param {string}   key
     * @param {number[]} data - Values in range 0–1
     */
    _drawRiskChart(key, data) {
        const canvas = this.canvases[key];
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        const w = canvas.offsetWidth  || canvas.clientWidth  || 300;
        const h = canvas.offsetHeight || canvas.clientHeight || 80;
        canvas.width  = w;
        canvas.height = h;

        const xStep = data.length > 1 ? w / (data.length - 1) : w;
        const pad   = 8;

        ctx.clearRect(0, 0, w, h);

        // ── Grid lines ────────────────────────────────────────────
        ctx.save();
        ctx.strokeStyle = 'rgba(107,140,174,0.15)';
        ctx.lineWidth   = 1;
        [0.25, 0.5, 0.75].forEach(pct => {
            ctx.beginPath();
            ctx.moveTo(0, h * pct);
            ctx.lineTo(w, h * pct);
            ctx.stroke();
        });
        ctx.restore();

        // ── Threshold labels ──────────────────────────────────────
        ctx.fillStyle = 'rgba(107,140,174,0.5)';
        ctx.font      = '8px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText('HIGH 0.7',   2, h * 0.30 - 1);
        ctx.fillText('MED  0.4',   2, h * 0.60 - 1);

        // ── Gradient fill under curve ─────────────────────────────
        const fillGrad = ctx.createLinearGradient(0, 0, 0, h);
        fillGrad.addColorStop(0,   'rgba(255,51,102,0.20)');
        fillGrad.addColorStop(0.5, 'rgba(255,184,0,0.10)');
        fillGrad.addColorStop(1,   'rgba(0,255,159,0.05)');

        ctx.beginPath();
        ctx.moveTo(0, h);
        data.forEach((val, i) => {
            const x = i * xStep;
            const y = h - val * (h - pad);
            ctx.lineTo(x, y);
        });
        ctx.lineTo((data.length - 1) * xStep, h);
        ctx.closePath();
        ctx.fillStyle = fillGrad;
        ctx.fill();

        // ── Segmented line ────────────────────────────────────────
        for (let i = 1; i < data.length; i++) {
            const x1 = (i - 1) * xStep;
            const y1 = h - data[i - 1] * (h - pad);
            const x2 = i * xStep;
            const y2 = h - data[i]     * (h - pad);
            ctx.beginPath();
            ctx.moveTo(x1, y1);
            ctx.lineTo(x2, y2);
            ctx.strokeStyle = this._riskColor(data[i]);
            ctx.lineWidth   = 2;
            ctx.lineJoin    = 'round';
            ctx.stroke();
        }

        // ── Current value ─────────────────────────────────────────
        const current = data[data.length - 1];
        ctx.fillStyle = this._riskColor(current);
        ctx.font      = 'bold 11px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(current.toFixed(3), w - 4, 14);
    }

    // ─────────────────────────────────────────────
    // Chart: Decision distribution (horizontal bars)
    // ─────────────────────────────────────────────

    /**
     * Draws a horizontal bar chart for security decision distribution.
     * @param {string} key
     * @param {object} decisions - { ALLOW, BLOCK, MONITOR, RATE_LIMIT, CHALLENGE }
     */
    _drawDecisionChart(key, decisions) {
        const canvas = this.canvases[key];
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        const w = canvas.offsetWidth  || canvas.clientWidth  || 300;
        const h = canvas.offsetHeight || canvas.clientHeight || 120;
        canvas.width  = w;
        canvas.height = h;

        ctx.clearRect(0, 0, w, h);

        const bars = [
            { label: 'ALLOW',      value: decisions.ALLOW      || 0, color: '#00FF9F' },
            { label: 'MONITOR',    value: decisions.MONITOR     || 0, color: '#00D4FF' },
            { label: 'BLOCK',      value: decisions.BLOCK       || 0, color: '#FF3366' },
            { label: 'RATE LIMIT', value: decisions.RATE_LIMIT  || 0, color: '#FFB800' },
            { label: 'CHALLENGE',  value: decisions.CHALLENGE   || 0, color: '#B44FFF' },
        ];

        const total   = bars.reduce((s, b) => s + b.value, 0) || 1;
        const gap     = 4;
        const labelW  = 62;
        const barH    = (h - (bars.length - 1) * gap) / bars.length;
        const trackW  = w - labelW - 36;   // 36px for value text

        bars.forEach((bar, i) => {
            const y    = i * (barH + gap);
            const barW = (bar.value / total) * trackW;

            // Track background
            ctx.fillStyle = 'rgba(255,255,255,0.05)';
            this._roundRect(ctx, labelW, y, trackW, barH, 2);
            ctx.fill();

            // Filled bar
            if (barW > 0) {
                ctx.fillStyle = bar.color;
                this._roundRect(ctx, labelW, y, barW, barH, 2);
                ctx.fill();
            }

            // Label (right-aligned into the label column)
            ctx.fillStyle  = '#6B8CAE';
            ctx.font       = '9px Inter, sans-serif';
            ctx.textAlign  = 'right';
            ctx.textBaseline = 'middle';
            ctx.fillText(bar.label, labelW - 4, y + barH / 2);

            // Value count (to the right of the bar)
            ctx.fillStyle  = bar.color;
            ctx.textAlign  = 'left';
            const pct = ((bar.value / total) * 100).toFixed(0);
            ctx.fillText(`${bar.value.toLocaleString()} (${pct}%)`, labelW + barW + 4, y + barH / 2);
        });
    }

    // ─────────────────────────────────────────────
    // Stats row
    // ─────────────────────────────────────────────

    /** Creates the four KPI stat cards inside #stats-row. */
    _renderStatsRow() {
        const container = document.getElementById('stats-row');
        if (!container) return;
        container.innerHTML = `
            <div class="stat-card" id="sc-card-total">
                <div class="stat-card-value" id="sc-total">0</div>
                <div class="stat-card-label">Total Events</div>
                <div class="stat-trend neutral" id="sc-total-trend">—</div>
            </div>
            <div class="stat-card" id="sc-card-threats">
                <div class="stat-card-value accent-red" id="sc-threats">0</div>
                <div class="stat-card-label">Threats Detected</div>
                <div class="stat-trend neutral" id="sc-threats-trend">—</div>
            </div>
            <div class="stat-card" id="sc-card-blocks">
                <div class="stat-card-value accent-amber" id="sc-blocks">0</div>
                <div class="stat-card-label">Requests Blocked</div>
                <div class="stat-trend neutral" id="sc-blocks-trend">—</div>
            </div>
            <div class="stat-card" id="sc-card-fp">
                <div class="stat-card-value accent-blue" id="sc-fp">0</div>
                <div class="stat-card-label">False Positives</div>
                <div class="stat-trend neutral" id="sc-fp-trend">—</div>
            </div>
        `;
    }

    /** Updates stat card values and trend indicators. */
    _updateStatsRow() {
        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
        };
        const setTrend = (id, curr, prev) => {
            const el = document.getElementById(id);
            if (!el) return;
            const delta = curr - prev;
            if (delta > 0) {
                el.textContent   = `▲ +${delta.toLocaleString()}`;
                el.className     = 'stat-trend up';
            } else if (delta < 0) {
                el.textContent   = `▼ ${delta.toLocaleString()}`;
                el.className     = 'stat-trend down';
            } else {
                el.textContent   = '—';
                el.className     = 'stat-trend neutral';
            }
        };

        setVal('sc-total',   this.stats.total);
        setVal('sc-threats', this.stats.threats);
        setVal('sc-blocks',  this.stats.blocks);
        setVal('sc-fp',      this.stats.fp);

        setTrend('sc-total-trend',   this.stats.total,   this._prevStats.total);
        setTrend('sc-threats-trend', this.stats.threats, this._prevStats.threats);
        setTrend('sc-blocks-trend',  this.stats.blocks,  this._prevStats.blocks);
        setTrend('sc-fp-trend',      this.stats.fp,      this._prevStats.fp);
    }

    // ─────────────────────────────────────────────
    // Utilities
    // ─────────────────────────────────────────────

    /**
     * Returns a CSS colour string based on a 0-1 risk value.
     * @param {number} v
     * @returns {string}
     */
    _riskColor(v) {
        if (v >= 0.7) return '#FF3366';
        if (v >= 0.4) return '#FFB800';
        return '#00FF9F';
    }

    /**
     * Converts a CSS hex colour (#RRGGBB) to an "R,G,B" string.
     * @param {string} hex
     * @returns {string}
     */
    _hexToRgb(hex) {
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return `${r},${g},${b}`;
    }

    /**
     * Draws a rounded rectangle path. Falls back to fillRect when
     * CanvasRenderingContext2D.roundRect is unsupported.
     * @param {CanvasRenderingContext2D} ctx
     * @param {number} x
     * @param {number} y
     * @param {number} w
     * @param {number} h
     * @param {number} r - Border radius
     */
    _roundRect(ctx, x, y, w, h, r) {
        if (typeof ctx.roundRect === 'function') {
            ctx.beginPath();
            ctx.roundRect(x, y, w, h, r);
        } else {
            ctx.beginPath();
            ctx.moveTo(x + r, y);
            ctx.lineTo(x + w - r, y);
            ctx.quadraticCurveTo(x + w, y,     x + w, y + r);
            ctx.lineTo(x + w, y + h - r);
            ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
            ctx.lineTo(x + r, y + h);
            ctx.quadraticCurveTo(x, y + h,     x, y + h - r);
            ctx.lineTo(x, y + r);
            ctx.quadraticCurveTo(x, y,          x + r, y);
            ctx.closePath();
        }
    }
}

export default MetricsPanel;
