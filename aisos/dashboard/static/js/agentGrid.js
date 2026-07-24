/**
 * AgentGrid - Renders and updates 5 security agent status cards
 * FILE 9 of AI-SOS Premium Security Dashboard
 */

const AGENT_DEFS = [
    { id: 'traffic',  name: 'Traffic Agent',       icon: '🚦', description: 'Monitors request patterns & bot detection'   },
    { id: 'threat',   name: 'Threat Agent',        icon: '🔍', description: 'Detects injection & attack signatures'        },
    { id: 'risk',     name: 'Risk Agent',          icon: '⚖️', description: 'Computes composite risk scores'              },
    { id: 'decision', name: 'Decision Agent',      icon: '🧠', description: 'Determines security action'                  },
    { id: 'notif',    name: 'Notification Agent',  icon: '🔔', description: 'Sends alerts & notifications'                },
];

const STATUS_CONFIG = {
    IDLE:       { color: '#6B8CAE', label: 'IDLE',       glowColor: 'rgba(107,140,174,0.3)'   },
    ACTIVE:     { color: '#00FF9F', label: 'ACTIVE',     glowColor: 'rgba(0,255,159,0.3)'     },
    PROCESSING: { color: '#00D4FF', label: 'PROCESSING', glowColor: 'rgba(0,212,255,0.3)'     },
    ERROR:      { color: '#FF3366', label: 'ERROR',      glowColor: 'rgba(255,51,102,0.35)'   },
    STARTING:   { color: '#FFB800', label: 'STARTING',   glowColor: 'rgba(255,184,0,0.3)'     },
};

const SPARKLINE_LENGTH = 20;

class AgentGrid {
    /**
     * @param {string} containerId - ID of the grid container element.
     */
    constructor(containerId) {
        this.containerId = containerId;
        this.container   = document.getElementById(containerId);
        this.agentData   = {};
        this.sparklines  = {};     // canvas element refs
        this._animFrames = {};     // rAF handles per agent

        AGENT_DEFS.forEach(a => {
            this.agentData[a.id] = {
                status:           'IDLE',
                events_processed: 0,
                threats_found:    0,
                uptime_sec:       0,
                avg_latency_ms:   0,
                activity:         new Array(SPARKLINE_LENGTH).fill(0),
            };
        });
    }

    // ─────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────

    /** Builds the initial card grid in the container. */
    render() {
        if (!this.container) return;
        this.container.innerHTML = '';
        AGENT_DEFS.forEach(agent => {
            const card = this._createCard(agent);
            this.container.appendChild(card);
        });
        this._initSparklines();
    }

    /**
     * Accepts an array of agent status objects from the backend and
     * updates the relevant cards without a full re-render.
     *
     * @param {Array<object>} agentStatuses - Each element should contain at
     *   minimum: agent_id (or id), status, events_processed, threats_found,
     *   uptime_sec, avg_latency_ms.
     */
    updateAgents(agentStatuses) {
        if (!Array.isArray(agentStatuses)) return;
        agentStatuses.forEach(status => {
            const id = status.agent_id || status.id;
            if (!id || !this.agentData[id]) return;

            const prev   = this.agentData[id];
            const delta  = Math.max(0, (status.events_processed || 0) - (prev.events_processed || 0));

            // Merge incoming fields
            this.agentData[id] = { ...prev, ...status };

            // Push activity delta into sparkline ring buffer
            const activity = this.agentData[id].activity;
            activity.shift();
            activity.push(delta);

            this._updateCard(id);
        });
    }

    // ─────────────────────────────────────────────
    // Card creation
    // ─────────────────────────────────────────────

    /**
     * Creates the full card DOM element for a single agent.
     * @param {object} agent - Entry from AGENT_DEFS
     * @returns {HTMLElement}
     */
    _createCard(agent) {
        const data       = this.agentData[agent.id];
        const statusConf = STATUS_CONFIG[data.status] || STATUS_CONFIG.IDLE;

        const el = document.createElement('div');
        el.className   = 'agent-card';
        el.id          = `agent-card-${agent.id}`;
        el.dataset.agentId = agent.id;
        el.setAttribute('role', 'button');
        el.setAttribute('tabindex', '0');
        el.setAttribute('aria-label', `${agent.name} status card`);

        el.innerHTML = `
            <div class="agent-header">
                <span class="agent-icon" aria-hidden="true">${agent.icon}</span>
                <div class="agent-info">
                    <div class="agent-name">${agent.name}</div>
                    <div class="agent-desc">${agent.description}</div>
                </div>
                <div class="agent-status-badge"
                     id="status-${agent.id}"
                     style="color:${statusConf.color};border-color:${statusConf.color};box-shadow:0 0 8px ${statusConf.glowColor};">
                    ${statusConf.label}
                </div>
            </div>

            <div class="agent-stats">
                <div class="agent-stat">
                    <span class="astat-label">Events</span>
                    <span class="astat-value" id="ev-${agent.id}">
                        ${data.events_processed.toLocaleString()}
                    </span>
                </div>
                <div class="agent-stat">
                    <span class="astat-label">Threats</span>
                    <span class="astat-value accent-red" id="th-${agent.id}">
                        ${data.threats_found}
                    </span>
                </div>
                <div class="agent-stat">
                    <span class="astat-label">Uptime</span>
                    <span class="astat-value" id="ut-${agent.id}">
                        ${this._fmtUptime(data.uptime_sec)}
                    </span>
                </div>
                <div class="agent-stat">
                    <span class="astat-label">Latency</span>
                    <span class="astat-value accent-blue" id="lat-${agent.id}">
                        ${(data.avg_latency_ms || 0).toFixed(0)}ms
                    </span>
                </div>
            </div>

            <div class="agent-heartbeat">
                <canvas id="spark-${agent.id}"
                        class="sparkline"
                        width="200"
                        height="40"
                        aria-label="${agent.name} activity sparkline"
                        role="img"></canvas>
            </div>

            <div class="agent-log-preview" id="log-${agent.id}"></div>
        `;

        // Click / keyboard handlers
        el.addEventListener('click',   () => this._showAgentLog(agent));
        el.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') this._showAgentLog(agent);
        });

        return el;
    }

    // ─────────────────────────────────────────────
    // Sparklines
    // ─────────────────────────────────────────────

    /** Stores canvas refs for all agents after render(). */
    _initSparklines() {
        AGENT_DEFS.forEach(agent => {
            const canvas = document.getElementById(`spark-${agent.id}`);
            if (canvas) {
                this.sparklines[agent.id] = canvas;
                this._drawSparkline(agent.id);
            }
        });
    }

    /**
     * Draws a mini area+line sparkline on the agent's canvas.
     * @param {string} agentId
     */
    _drawSparkline(agentId) {
        const canvas = this.sparklines[agentId];
        if (!canvas) return;

        const ctx  = canvas.getContext('2d');
        const data = this.agentData[agentId].activity;
        const w    = canvas.offsetWidth  || canvas.width  || 200;
        const h    = canvas.offsetHeight || canvas.height || 40;

        // Keep canvas pixels in sync with CSS layout size
        if (canvas.width !== w)  canvas.width  = w;
        if (canvas.height !== h) canvas.height = h;

        const max = Math.max(...data, 1);
        ctx.clearRect(0, 0, w, h);

        const xStep = data.length > 1 ? w / (data.length - 1) : w;

        // ── Gradient fill ──────────────────────────────────────
        const fillGrad = ctx.createLinearGradient(0, 0, 0, h);
        fillGrad.addColorStop(0,   'rgba(0,212,255,0.40)');
        fillGrad.addColorStop(0.7, 'rgba(0,212,255,0.10)');
        fillGrad.addColorStop(1,   'rgba(0,212,255,0.00)');

        ctx.beginPath();
        ctx.moveTo(0, h);
        data.forEach((val, i) => {
            const x = i * xStep;
            const y = h - (val / max) * (h - 6);
            ctx.lineTo(x, y);
        });
        ctx.lineTo((data.length - 1) * xStep, h);
        ctx.closePath();
        ctx.fillStyle = fillGrad;
        ctx.fill();

        // ── Line ──────────────────────────────────────────────
        ctx.beginPath();
        data.forEach((val, i) => {
            const x = i * xStep;
            const y = h - (val / max) * (h - 6);
            if (i === 0) ctx.moveTo(x, y);
            else         ctx.lineTo(x, y);
        });
        ctx.strokeStyle = '#00D4FF';
        ctx.lineWidth   = 1.5;
        ctx.lineJoin    = 'round';
        ctx.stroke();

        // ── Latest dot ─────────────────────────────────────────
        const last  = data[data.length - 1];
        const dotX  = (data.length - 1) * xStep;
        const dotY  = h - (last / max) * (h - 6);
        ctx.beginPath();
        ctx.arc(dotX, dotY, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = '#00D4FF';
        ctx.fill();
    }

    // ─────────────────────────────────────────────
    // Card updates (no full re-render)
    // ─────────────────────────────────────────────

    /**
     * Performs targeted DOM updates on an agent card after new data arrives.
     * @param {string} agentId
     */
    _updateCard(agentId) {
        const data       = this.agentData[agentId];
        const statusConf = STATUS_CONFIG[data.status] || STATUS_CONFIG.IDLE;

        // Status badge
        const statusEl = document.getElementById(`status-${agentId}`);
        if (statusEl) {
            statusEl.textContent       = statusConf.label;
            statusEl.style.color       = statusConf.color;
            statusEl.style.borderColor = statusConf.color;
            statusEl.style.boxShadow   = `0 0 8px ${statusConf.glowColor}`;
        }

        // Animate card border while PROCESSING
        const card = document.getElementById(`agent-card-${agentId}`);
        if (card) {
            card.classList.toggle('agent-processing', data.status === 'PROCESSING');
            card.classList.toggle('agent-error',      data.status === 'ERROR');
        }

        // Stats
        const evEl  = document.getElementById(`ev-${agentId}`);
        const thEl  = document.getElementById(`th-${agentId}`);
        const utEl  = document.getElementById(`ut-${agentId}`);
        const latEl = document.getElementById(`lat-${agentId}`);

        if (evEl)  evEl.textContent  = (data.events_processed || 0).toLocaleString();
        if (thEl)  thEl.textContent  = (data.threats_found    || 0).toLocaleString();
        if (utEl)  utEl.textContent  = this._fmtUptime(data.uptime_sec || 0);
        if (latEl) latEl.textContent = `${(data.avg_latency_ms || 0).toFixed(0)}ms`;

        // Sparkline
        this._drawSparkline(agentId);
    }

    // ─────────────────────────────────────────────
    // Interaction
    // ─────────────────────────────────────────────

    /**
     * Called when a card is clicked; briefly highlights it and optionally
     * emits a custom event so the parent dashboard can react.
     * @param {object} agent
     */
    _showAgentLog(agent) {
        const card = document.getElementById(`agent-card-${agent.id}`);
        if (card) {
            card.classList.add('agent-selected');
            setTimeout(() => card.classList.remove('agent-selected'), 900);
        }

        // Emit custom event for the dashboard shell to listen for
        document.dispatchEvent(new CustomEvent('aisos:agent-selected', {
            bubbles: true,
            detail: {
                agentId:   agent.id,
                agentName: agent.name,
                data:      this.agentData[agent.id],
            },
        }));
    }

    // ─────────────────────────────────────────────
    // Utilities
    // ─────────────────────────────────────────────

    /**
     * Formats an uptime in seconds into a human-readable string.
     * @param {number} sec
     * @returns {string}
     */
    _fmtUptime(sec) {
        sec = Math.floor(sec || 0);
        const h = Math.floor(sec / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const s = sec % 60;
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    }
}

export default AgentGrid;
