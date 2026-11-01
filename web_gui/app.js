/**
 * AI Cyber Forensics & Incident Response Platform
 * Full-featured Frontend Client Logic
 */

document.addEventListener("DOMContentLoaded", () => {
    // State Store
    let allProcesses = [];
    let allTimelineEvents = [];
    let evidenceFiles = [];

    // Initialize UI
    initNavigation();
    initSystemMetrics();
    initOllamaStatus();
    initLiveForensics();
    initTimeline();
    initEvidenceAndCustody();
    initThreatIntel();
    initInspector();
    initAICopilot();
    initChatbot();

    // -----------------------------------------------------------------------
    // Navigation & Sub-Tabs
    // -----------------------------------------------------------------------
    function initNavigation() {
        const navItems = document.querySelectorAll(".nav-item");
        const tabPanes = document.querySelectorAll(".tab-pane");

        navItems.forEach(item => {
            item.addEventListener("click", (e) => {
                e.preventDefault();
                const targetTab = item.getAttribute("data-tab");

                navItems.forEach(n => n.classList.remove("active"));
                tabPanes.forEach(p => p.classList.remove("active"));

                item.classList.add("active");
                const targetPane = document.getElementById(`tab-${targetTab}`);
                if (targetPane) {
                    targetPane.classList.add("active");
                }

                // Update page titles
                const titles = {
                    "dashboard": ["Forensic Operations Dashboard", "Real-time host metrics, evidence integrity & AI incident response"],
                    "live-forensics": ["Live Host Forensics", "Process anomalies, active sockets, persistence hooks & user accounts"],
                    "timeline": ["Chronological Super-Timeline", "Multi-source forensic event correlation & attack kill chain reconstruction"],
                    "evidence": ["Evidence & Chain of Custody", "Cryptographic hashes, Shannon entropy & tamper-evident legal records"],
                    "threat-intel": ["IOCs & Threat Intelligence", "High-fidelity threat indicators & MITRE ATT&CK matrix alignment"],
                    "inspector": ["Hex & Strings Inspector", "Deep binary inspection, offset dump & printable string extraction"],
                    "ai-copilot": ["AI Incident Copilot", "Automated executive DFIR report generation & actionable response plan"],
                    "rag-chatbot": ["AI Forensic Assistant", "Natural language Q&A backed by forensic evidence context"]
                };
                if (titles[targetTab]) {
                    document.getElementById("page-title").textContent = titles[targetTab][0];
                    document.getElementById("page-subtitle").textContent = titles[targetTab][1];
                }
            });
        });

        // Sub-tabs in Live Forensics
        const subTabBtns = document.querySelectorAll(".sub-tab-btn");
        subTabBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                const targetSub = btn.getAttribute("data-sub");
                subTabBtns.forEach(b => b.classList.remove("active"));
                document.querySelectorAll(".sub-tab-content").forEach(c => c.classList.remove("active"));

                btn.classList.add("active");
                const targetContent = document.getElementById(targetSub);
                if (targetContent) targetContent.classList.add("active");
            });
        });
    }

    // -----------------------------------------------------------------------
    // 1. System Metrics & Telemetry
    // -----------------------------------------------------------------------
    function initSystemMetrics() {
        async function fetchSystemMetrics() {
            try {
                const res = await fetch("/api/system_info");
                if (!res.ok) return;
                const data = await res.json();

                // Quick stats header
                document.getElementById("quick-os").textContent = `${data.os} ${data.machine}`;
                document.getElementById("quick-cpu").textContent = `${data.cpu_usage_percent}%`;
                document.getElementById("quick-ram").textContent = `${data.memory.percentage}%`;

                // Detailed profiling card
                document.getElementById("sys-hostname").textContent = data.hostname || "-";
                document.getElementById("sys-os").textContent = `${data.os} (${data.release || ""})`;
                document.getElementById("sys-version").textContent = data.version || "-";
                document.getElementById("sys-arch").textContent = data.machine || "-";
                document.getElementById("sys-uptime").textContent = data.uptime || "-";
                document.getElementById("sys-boot-time").textContent = data.boot_time || "-";
                document.getElementById("sys-processor").textContent = data.processor || "-";

                // Progress Bars
                document.getElementById("cpu-cores").textContent = data.cpu_count_logical || 0;
                document.getElementById("cpu-percent-lbl").textContent = `${data.cpu_usage_percent}%`;
                document.getElementById("cpu-progress-bar").style.width = `${data.cpu_usage_percent}%`;

                document.getElementById("ram-used").textContent = data.memory.used_gb;
                document.getElementById("ram-total").textContent = data.memory.total_gb;
                document.getElementById("ram-percent-lbl").textContent = `${data.memory.percentage}%`;
                document.getElementById("ram-progress-bar").style.width = `${data.memory.percentage}%`;

                document.getElementById("disk-free").textContent = data.disk.free_gb;
                document.getElementById("disk-percent-lbl").textContent = `${data.disk.percentage}%`;
                document.getElementById("disk-progress-bar").style.width = `${data.disk.percentage}%`;
            } catch (err) {
                console.error("System info error:", err);
            }
        }

        fetchSystemMetrics();
        setInterval(fetchSystemMetrics, 10000);
    }

    // -----------------------------------------------------------------------
    // 2. Ollama Status Check
    // -----------------------------------------------------------------------
    function initOllamaStatus() {
        async function checkOllama() {
            const indicator = document.getElementById("ollama-status-indicator");
            const statusText = document.getElementById("ollama-status-text");
            const daemonStatus = document.getElementById("ollama-daemon-status");
            const versionVal = document.getElementById("ollama-version-val");
            const pathVal = document.getElementById("ollama-path-val");
            const badgesContainer = document.getElementById("installed-models-badges");

            try {
                const res = await fetch("/api/ollama_info");
                const data = await res.json();

                if (data.service_running || (data.installed_models && data.installed_models.length > 0)) {
                    indicator.className = "status-indicator online";
                    statusText.textContent = "Service Active";
                    if (daemonStatus) daemonStatus.innerHTML = '<span class="badge-verified">Running (Online)</span>';
                } else {
                    indicator.className = "status-indicator";
                    statusText.textContent = "Offline (Using Heuristic Engine)";
                    if (daemonStatus) daemonStatus.innerHTML = '<span class="badge-info">Offline - Heuristic Fallback Active</span>';
                }

                if (versionVal) versionVal.textContent = data.version || "Not detected";
                if (pathVal) pathVal.textContent = data.installed_path || "N/A";

                if (badgesContainer) {
                    if (data.installed_models && data.installed_models.length > 0) {
                        badgesContainer.innerHTML = data.installed_models
                            .map(m => `<span class="badge-low font-mono" style="margin-right: 6px;">${m}</span>`)
                            .join("");
                    } else {
                        badgesContainer.innerHTML = '<span class="badge-info">Deterministic DFIR Expert Engine Active (No models required)</span>';
                    }
                }
            } catch (err) {
                indicator.className = "status-indicator";
                statusText.textContent = "Offline (Heuristic Mode)";
            }
        }

        checkOllama();
        setInterval(checkOllama, 15000);
    }

    // -----------------------------------------------------------------------
    // 3. Live Host Forensics (Processes, Sockets, Persistence, Users)
    // -----------------------------------------------------------------------
    function initLiveForensics() {
        const btnRefreshProcs = document.getElementById("btn-refresh-procs");
        const btnRefreshSockets = document.getElementById("btn-refresh-sockets");
        const procSearch = document.getElementById("proc-search-input");
        const procFilter = document.getElementById("proc-filter-select");

        async function loadProcesses() {
            const tbody = document.getElementById("procs-table-body");
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">Scanning live processes...</td></tr>';

            try {
                const res = await fetch("/api/forensics/processes");
                const data = await res.json();
                allProcesses = data.processes || [];

                document.getElementById("count-procs").textContent = data.total_processes;
                renderProcesses();
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="8" style="color: var(--danger);">Failed to load processes: ${err.message}</td></tr>`;
            }
        }

        function renderProcesses() {
            const tbody = document.getElementById("procs-table-body");
            const q = (procSearch.value || "").toLowerCase();
            const filterType = procFilter.value;

            let filtered = allProcesses.filter(p => {
                if (filterType === "suspicious" && !p.is_suspicious) return false;
                if (!q) return true;
                return (
                    p.name.toLowerCase().includes(q) ||
                    String(p.pid).includes(q) ||
                    p.user.toLowerCase().includes(q) ||
                    (p.anomalies && p.anomalies.some(a => a.toLowerCase().includes(q)))
                );
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No matching processes found.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.slice(0, 100).map(p => {
                let badge = '<span class="badge-info">Normal</span>';
                if (p.is_suspicious) {
                    badge = `<span class="badge-tampered">${p.anomalies.join(", ")}</span>`;
                }

                return `
                    <tr style="${p.is_suspicious ? 'background: rgba(220, 38, 38, 0.05);' : ''}">
                        <td class="font-mono"><strong>${p.pid}</strong></td>
                        <td class="font-mono text-muted">${p.ppid}</td>
                        <td><strong>${escapeHtml(p.name)}</strong></td>
                        <td>${escapeHtml(p.user)}</td>
                        <td>${p.cpu_percent}%</td>
                        <td>${p.memory_mb} MB</td>
                        <td><span class="badge-low">${p.status}</span></td>
                        <td>${badge}</td>
                    </tr>
                `;
            }).join("");
        }

        async function loadSockets() {
            const tbody = document.getElementById("sockets-table-body");
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">Scanning network sockets...</td></tr>';

            try {
                const res = await fetch("/api/forensics/sockets");
                const data = await res.json();
                const conns = data.connections || [];
                document.getElementById("count-sockets").textContent = data.total_connections;

                if (conns.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No active internet connections or socket access restricted.</td></tr>';
                    return;
                }

                tbody.innerHTML = conns.map(c => {
                    let threatBadge = '—';
                    if (c.threat_tag) {
                        if (c.threat_tag.includes("CRITICAL")) {
                            threatBadge = `<span class="badge-critical">${escapeHtml(c.threat_tag)}</span>`;
                        } else if (c.threat_tag.includes("HIGH") || c.threat_tag.includes("Outbound")) {
                            threatBadge = `<span class="badge-high">${escapeHtml(c.threat_tag)}</span>`;
                        } else {
                            threatBadge = `<span class="badge-medium">${escapeHtml(c.threat_tag)}</span>`;
                        }
                    }

                    return `
                        <tr>
                            <td><span class="badge-low">${c.protocol}</span></td>
                            <td class="font-mono">${escapeHtml(c.local_address)}</td>
                            <td class="font-mono">${escapeHtml(c.remote_address)}</td>
                            <td><span class="badge-info">${c.status}</span></td>
                            <td><strong>${escapeHtml(c.process_name)}</strong></td>
                            <td class="font-mono">${c.pid || "—"}</td>
                            <td>${threatBadge}</td>
                        </tr>
                    `;
                }).join("");
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="7" style="color: var(--danger);">Failed to scan sockets: ${err.message}</td></tr>`;
            }
        }

        async function loadPersistence() {
            const tbody = document.getElementById("persistence-table-body");
            try {
                const res = await fetch("/api/forensics/persistence");
                const data = await res.json();
                const autoruns = data.autoruns || [];
                document.getElementById("count-autoruns").textContent = data.total_autoruns;

                if (autoruns.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No persistent autoruns identified.</td></tr>';
                    return;
                }

                tbody.innerHTML = autoruns.map(a => `
                    <tr>
                        <td><span class="badge-high">${escapeHtml(a.type)}</span></td>
                        <td><strong>${escapeHtml(a.name)}</strong></td>
                        <td class="font-mono" style="font-size: 11px;">${escapeHtml(a.location)}</td>
                        <td>${a.modified || "—"}</td>
                    </tr>
                `).join("");
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="4">Error loading persistence: ${err.message}</td></tr>`;
            }
        }

        async function loadUsers() {
            const container = document.getElementById("users-info-container");
            try {
                const res = await fetch("/api/forensics/users");
                const data = await res.json();

                let html = '<div style="margin-bottom: 16px;"><strong>Active Logged-In Sessions:</strong></div>';
                if (data.active_sessions && data.active_sessions.length > 0) {
                    html += '<ul>' + data.active_sessions.map(s => `
                        <li style="margin-bottom: 6px;">
                            User <strong>${escapeHtml(s.username)}</strong> on terminal <code>${escapeHtml(s.terminal)}</code> from host <code>${escapeHtml(s.host)}</code> (Session started: ${s.started})
                        </li>
                    `).join("") + '</ul>';
                } else {
                    html += '<p style="color: var(--color-text-muted);">No interactive active remote sessions detected.</p>';
                }

                html += '<div style="margin-top: 20px; margin-bottom: 12px;"><strong>Interactive System Accounts:</strong></div>';
                if (data.interactive_accounts && data.interactive_accounts.length > 0) {
                    html += '<div class="table-container"><table><thead><tr><th>Username</th><th>UID</th><th>Home Directory</th><th>Default Shell</th></tr></thead><tbody>';
                    html += data.interactive_accounts.map(u => `
                        <tr>
                            <td><strong>${escapeHtml(u.username)}</strong></td>
                            <td class="font-mono">${u.uid}</td>
                            <td class="font-mono">${escapeHtml(u.home)}</td>
                            <td><code>${escapeHtml(u.shell)}</code></td>
                        </tr>
                    `).join("");
                    html += '</tbody></table></div>';
                }
                container.innerHTML = html;
            } catch (err) {
                container.innerHTML = `<p style="color: var(--danger);">Failed to load user accounts: ${err.message}</p>`;
            }
        }

        if (btnRefreshProcs) btnRefreshProcs.addEventListener("click", loadProcesses);
        if (btnRefreshSockets) btnRefreshSockets.addEventListener("click", loadSockets);
        if (procSearch) procSearch.addEventListener("input", renderProcesses);
        if (procFilter) procFilter.addEventListener("change", renderProcesses);

        // Initial loads
        loadProcesses();
        loadSockets();
        loadPersistence();
        loadUsers();
    }

    // -----------------------------------------------------------------------
    // 4. Super-Timeline
    // -----------------------------------------------------------------------
    function initTimeline() {
        const btnRebuild = document.getElementById("btn-rebuild-timeline");
        const timelineSearch = document.getElementById("timeline-search-input");
        const sevFilter = document.getElementById("timeline-severity-filter");
        const srcFilter = document.getElementById("timeline-source-filter");

        async function fetchTimeline() {
            const tbody = document.getElementById("timeline-table-body");
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">Correlating multi-source forensic logs...</td></tr>';

            try {
                const res = await fetch("/api/timeline");
                const data = await res.json();
                allTimelineEvents = data.timeline || [];

                // Update KPI counters
                if (data.summary) {
                    document.getElementById("kpi-events-count").textContent = data.summary.total_events || allTimelineEvents.length;
                    document.getElementById("kpi-critical-count").textContent = data.summary.severity_summary?.CRITICAL || 0;
                }

                renderTimeline();
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="8" style="color: var(--danger);">Failed to build timeline: ${err.message}</td></tr>`;
            }
        }

        function renderTimeline() {
            const tbody = document.getElementById("timeline-table-body");
            const q = (timelineSearch.value || "").toLowerCase();
            const sev = sevFilter.value;
            const src = srcFilter.value;

            let filtered = allTimelineEvents.filter(ev => {
                if (sev !== "ALL" && ev.severity !== sev) return false;
                if (src !== "ALL" && ev.log_type !== src) return false;
                if (!q) return true;

                return (
                    ev.description.toLowerCase().includes(q) ||
                    ev.timestamp.toLowerCase().includes(q) ||
                    (ev.user && ev.user.toLowerCase().includes(q)) ||
                    (ev.src_ip && ev.src_ip.includes(q)) ||
                    (ev.dst_ip && ev.dst_ip.includes(q)) ||
                    (ev.kill_chain_stage && ev.kill_chain_stage.toLowerCase().includes(q))
                );
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No timeline events match the filter criteria.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.map(ev => {
                let sevBadge = `<span class="badge-info">${ev.severity}</span>`;
                if (ev.severity === "CRITICAL") sevBadge = `<span class="badge-critical">CRITICAL</span>`;
                else if (ev.severity === "HIGH") sevBadge = `<span class="badge-high">HIGH</span>`;
                else if (ev.severity === "MEDIUM") sevBadge = `<span class="badge-medium">MEDIUM</span>`;
                else if (ev.severity === "LOW") sevBadge = `<span class="badge-low">LOW</span>`;

                return `
                    <tr style="${ev.severity === 'CRITICAL' ? 'background: rgba(220, 38, 38, 0.05);' : ''}">
                        <td class="font-mono" style="white-space: nowrap;"><strong>${ev.timestamp}</strong></td>
                        <td>${sevBadge}</td>
                        <td><span class="badge-medium">${escapeHtml(ev.kill_chain_stage)}</span></td>
                        <td><strong>${escapeHtml(ev.log_type)}</strong></td>
                        <td>${ev.user !== 'N/A' ? `<code>${escapeHtml(ev.user)}</code>` : '—'}</td>
                        <td class="font-mono">${ev.src_ip !== 'N/A' ? escapeHtml(ev.src_ip) : '—'}</td>
                        <td class="font-mono">${ev.dst_ip !== 'N/A' ? escapeHtml(ev.dst_ip) : '—'}</td>
                        <td style="font-size: 12px;">${escapeHtml(ev.description)}</td>
                    </tr>
                `;
            }).join("");
        }

        if (btnRebuild) btnRebuild.addEventListener("click", fetchTimeline);
        if (timelineSearch) timelineSearch.addEventListener("input", renderTimeline);
        if (sevFilter) sevFilter.addEventListener("change", renderTimeline);
        if (srcFilter) srcFilter.addEventListener("change", renderTimeline);

        fetchTimeline();
    }

    // -----------------------------------------------------------------------
    // 5. Evidence & Chain of Custody
    // -----------------------------------------------------------------------
    function initEvidenceAndCustody() {
        const btnVerifyHashes = document.getElementById("btn-run-hashing");
        const btnIntegrityReport = document.getElementById("btn-gen-integrity-report");
        const btnUpload = document.getElementById("btn-upload-evidence");
        const fileInput = document.getElementById("evidence-file-input");

        async function loadEvidence() {
            const tbody = document.getElementById("evidence-table-body");
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Calculating evidence hashes & entropy...</td></tr>';

            try {
                const res = await fetch("/api/evidence/list");
                evidenceFiles = await res.json();
                document.getElementById("kpi-evidence-count").textContent = evidenceFiles.length;

                // Populate inspector dropdown too
                const inspectorSelect = document.getElementById("inspector-file-select");
                if (inspectorSelect) {
                    inspectorSelect.innerHTML = '<option value="">Select Evidence File...</option>' +
                        evidenceFiles.map(f => `<option value="${f.filename}">${f.filename} (${f.size_bytes} B)</option>`).join("");
                }

                tbody.innerHTML = evidenceFiles.map(f => {
                    let entropyBadge = `<span class="badge-low">${f.entropy}</span>`;
                    if (f.entropy >= 7.2) entropyBadge = `<span class="badge-critical">${f.entropy} (High)</span>`;
                    else if (f.entropy >= 5.0) entropyBadge = `<span class="badge-medium">${f.entropy}</span>`;

                    return `
                        <tr>
                            <td><strong>${escapeHtml(f.filename)}</strong></td>
                            <td class="font-mono">${f.size_bytes} B</td>
                            <td class="font-mono" style="font-size: 11px;">${f.sha256}</td>
                            <td class="font-mono" style="font-size: 11px;">${f.md5}</td>
                            <td>${entropyBadge}</td>
                            <td><span class="badge-verified">Verified</span></td>
                        </tr>
                    `;
                }).join("");
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="6" style="color: var(--danger);">Failed to load evidence: ${err.message}</td></tr>`;
            }
        }

        async function loadCustodyLedger() {
            const transfersBody = document.getElementById("coc-transfers-body");
            try {
                const res = await fetch("/api/custody/ledger");
                const ledger = await res.json();

                const transfers = ledger.custody_transfers || [];
                if (transfers.length === 0) {
                    transfersBody.innerHTML = '<tr><td colspan="4">No custody transfers recorded.</td></tr>';
                    return;
                }

                transfersBody.innerHTML = transfers.map(t => `
                    <tr>
                        <td class="font-mono" style="font-size: 11px;">${t.timestamp}</td>
                        <td>${escapeHtml(t.released_by)}</td>
                        <td>${escapeHtml(t.received_by)}</td>
                        <td><strong>${escapeHtml(t.purpose)}</strong></td>
                    </tr>
                `).join("");
            } catch (err) {
                transfersBody.innerHTML = `<tr><td colspan="4">Error loading custody: ${err.message}</td></tr>`;
            }
        }

        async function verifyHashes() {
            try {
                const res = await fetch("/api/hashing", { method: "POST" });
                const data = await res.json();
                if (data.has_tampered) {
                    document.getElementById("kpi-integrity-status").innerHTML = '<span style="color: #ef4444;">Tampered!</span>';
                    alert("WARNING: Checksum mismatch detected! One or more evidence files have been altered.");
                } else {
                    document.getElementById("kpi-integrity-status").textContent = "Intact";
                    alert("SUCCESS: All digital evidence files match baseline SHA-256 hashes.");
                }
                loadEvidence();
                loadCustodyLedger();
            } catch (err) {
                alert(`Error during hash verification: ${err.message}`);
            }
        }

        async function generateIntegrityReport() {
            try {
                const res = await fetch("/api/report/integrity", { method: "POST" });
                const data = await res.json();
                alert(`Integrity Report generated at:\n${data.report_path}`);
            } catch (err) {
                alert(`Error generating integrity report: ${err.message}`);
            }
        }

        async function uploadEvidenceFile() {
            if (!fileInput.files || fileInput.files.length === 0) {
                alert("Please select a file to upload.");
                return;
            }

            const file = fileInput.files[0];
            const formData = new FormData();
            formData.append("file", file);

            const msgDiv = document.getElementById("upload-status-msg");
            msgDiv.textContent = `Uploading and hashing ${file.name}...`;

            try {
                const res = await fetch("/api/evidence/upload", {
                    method: "POST",
                    body: formData
                });
                const data = await res.json();
                msgDiv.innerHTML = `<span style="color: var(--green);">✓ Uploaded: ${file.name} (SHA-256: ${data.metadata?.sha256?.substring(0, 16)}...)</span>`;
                loadEvidence();
                loadCustodyLedger();
                fileInput.value = "";
            } catch (err) {
                msgDiv.innerHTML = `<span style="color: var(--danger);">Upload failed: ${err.message}</span>`;
            }
        }

        if (btnVerifyHashes) btnVerifyHashes.addEventListener("click", verifyHashes);
        if (btnIntegrityReport) btnIntegrityReport.addEventListener("click", generateIntegrityReport);
        if (btnUpload) btnUpload.addEventListener("click", uploadEvidenceFile);

        loadEvidence();
        loadCustodyLedger();
    }

    // -----------------------------------------------------------------------
    // 6. IOCs & Threat Intelligence
    // -----------------------------------------------------------------------
    function initThreatIntel() {
        async function loadIOCs() {
            const tbody = document.getElementById("ioc-table-body");
            const mitreContainer = document.getElementById("mitre-cards-container");

            try {
                const res = await fetch("/api/iocs");
                const data = await res.json();
                const ips = data.iocs?.ip_addresses || [];

                tbody.innerHTML = ips.map(ip => {
                    let badge = '<span class="badge-info">Internal</span>';
                    if (ip.threat_level === "MALICIOUS") badge = '<span class="badge-critical">MALICIOUS</span>';
                    else if (ip.threat_level === "SUSPICIOUS") badge = '<span class="badge-high">SUSPICIOUS</span>';
                    else if (ip.threat_level.includes("COMPROMISED")) badge = '<span class="badge-medium">COMPROMISED</span>';

                    return `
                        <tr>
                            <td class="font-mono"><strong>${ip.ip}</strong></td>
                            <td>${badge}</td>
                            <td><strong>${escapeHtml(ip.role)}</strong></td>
                            <td>${escapeHtml(ip.description)}</td>
                        </tr>
                    `;
                }).join("");

                // Render MITRE Cards
                const mitre = data.mitre_attack || [];
                mitreContainer.innerHTML = mitre.map(m => `
                    <div class="mitre-card">
                        <div class="mitre-tactic">${escapeHtml(m.tactic)}</div>
                        <div class="mitre-id">${m.technique_id} : ${escapeHtml(m.technique_name)}</div>
                        <div class="mitre-desc">${escapeHtml(m.description)}</div>
                        <div style="font-size: 11px; color: var(--color-text-muted); margin-top: 6px;">
                            <strong>Source:</strong> ${escapeHtml(m.evidence_source)}
                        </div>
                    </div>
                `).join("");
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="4">Error loading IOCs: ${err.message}</td></tr>`;
            }
        }

        loadIOCs();
    }

    // -----------------------------------------------------------------------
    // 7. Hex & Strings Inspector
    // -----------------------------------------------------------------------
    function initInspector() {
        const fileSelect = document.getElementById("inspector-file-select");
        const btnHex = document.getElementById("btn-load-hex");
        const btnStrings = document.getElementById("btn-load-strings");
        const container = document.getElementById("inspector-viewer-container");

        async function loadHex() {
            const filename = fileSelect.value;
            if (!filename) {
                alert("Please select an evidence file.");
                return;
            }

            container.innerHTML = '<p style="text-align: center; padding: 20px;">Generating hex dump...</p>';
            try {
                const res = await fetch(`/api/evidence/hex?filename=${encodeURIComponent(filename)}&offset=0&length=2048`);
                const data = await res.json();
                if (data.error) {
                    container.innerHTML = `<p style="color: var(--danger);">${data.error}</p>`;
                    return;
                }

                container.innerHTML = `
                    <div style="margin-bottom: 8px; font-size: 12px;">
                        <strong>Viewing:</strong> ${escapeHtml(data.filename)} | Size: ${data.total_size} bytes (Offset: 0 - ${data.bytes_returned})
                    </div>
                    <pre class="hex-viewer">${escapeHtml(data.hex_dump)}</pre>
                `;
            } catch (err) {
                container.innerHTML = `<p style="color: var(--danger);">Hex dump error: ${err.message}</p>`;
            }
        }

        async function loadStrings() {
            const filename = fileSelect.value;
            if (!filename) {
                alert("Please select an evidence file.");
                return;
            }

            container.innerHTML = '<p style="text-align: center; padding: 20px;">Extracting printable strings...</p>';
            try {
                const res = await fetch(`/api/evidence/strings?filename=${encodeURIComponent(filename)}&min_length=4`);
                const data = await res.json();
                if (data.error) {
                    container.innerHTML = `<p style="color: var(--danger);">${data.error}</p>`;
                    return;
                }

                const strList = data.strings || [];
                container.innerHTML = `
                    <div style="margin-bottom: 8px; font-size: 12px;">
                        <strong>Artifact:</strong> ${escapeHtml(data.filename)} | Found <strong>${data.total_found}</strong> printable strings (Min length: 4)
                    </div>
                    <div class="strings-viewer">
                        ${strList.map(s => `<div class="string-item">${escapeHtml(s)}</div>`).join("")}
                    </div>
                `;
            } catch (err) {
                container.innerHTML = `<p style="color: var(--danger);">Strings error: ${err.message}</p>`;
            }
        }

        if (btnHex) btnHex.addEventListener("click", loadHex);
        if (btnStrings) btnStrings.addEventListener("click", loadStrings);
    }

    // -----------------------------------------------------------------------
    // 8. AI Incident Copilot
    // -----------------------------------------------------------------------
    function initAICopilot() {
        const btnGen = document.getElementById("btn-generate-ai-report");
        const preview = document.getElementById("ai-report-preview-container");

        async function generateReport() {
            preview.innerHTML = '<p style="text-align: center; padding: 40px;"><span class="material-icons-round" style="font-size: 32px; animation: spin 1s infinite linear;">sync</span><br>Synthesizing evidence with AI Incident Copilot...</p>';

            try {
                const res = await fetch("/api/report/generate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ model: "llama3.2:1b" })
                });
                const data = await res.json();
                displayReport(data.report_markdown || data.report);
            } catch (err) {
                preview.innerHTML = `<p style="color: var(--danger);">Report generation failed: ${err.message}</p>`;
            }
        }

        async function loadExistingReport() {
            try {
                const res = await fetch("/api/report/get");
                const data = await res.json();
                if (data.exists && data.report) {
                    displayReport(data.report);
                }
            } catch (err) {
                console.error("Report check error:", err);
            }
        }

        function displayReport(markdownText) {
            // Render basic markdown into HTML
            let html = markdownText
                .replace(/^# (.*$)/gim, '<h2 style="color: var(--cyan); margin-top: 18px; margin-bottom: 10px;">$1</h2>')
                .replace(/^## (.*$)/gim, '<h3 style="color: var(--color-text-heading); margin-top: 16px; margin-bottom: 8px;">$1</h3>')
                .replace(/^### (.*$)/gim, '<h4 style="color: var(--purple); margin-top: 14px; margin-bottom: 6px;">$1</h4>')
                .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
                .replace(/`(.*?)`/gim, '<code style="background: rgba(0,0,0,0.06); padding: 2px 4px; border-radius: 4px; font-family: monospace;">$1</code>')
                .replace(/\n\n/gim, '<br><br>');

            preview.innerHTML = html;
        }

        // Action chips
        document.querySelectorAll("[data-preset]").forEach(btn => {
            btn.addEventListener("click", () => {
                generateReport();
            });
        });

        if (btnGen) btnGen.addEventListener("click", generateReport);
        loadExistingReport();
    }

    // -----------------------------------------------------------------------
    // 9. AI Forensic Chatbot
    // -----------------------------------------------------------------------
    function initChatbot() {
        const input = document.getElementById("chat-query-input");
        const btnSend = document.getElementById("btn-send-chat");
        const messagesContainer = document.getElementById("chat-messages-container");
        const modelSelect = document.getElementById("chat-model-select");

        async function sendQuery(queryText) {
            const text = (queryText || input.value || "").trim();
            if (!text) return;

            // Append User Message
            appendMessage("user", text);
            input.value = "";

            // Show Typing Indicator
            const typingId = "typing-" + Date.now();
            appendMessage("bot", '<span style="color: var(--color-text-muted); font-style: italic;">Consulting evidence repository...</span>', typingId);

            try {
                const res = await fetch("/api/chat/query", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        question: text,
                        model: modelSelect ? modelSelect.value : "llama3.2:1b"
                    })
                });

                const data = await res.json();
                const typingEl = document.getElementById(typingId);
                if (typingEl) typingEl.remove();

                if (!res.ok) {
                    appendMessage("bot", `<span style="color: var(--danger);">Error: ${data.detail || "Unknown error"}</span>`);
                    return;
                }

                // Format response
                let botHtml = data.answer.replace(/\n/g, "<br>").replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>").replace(/`(.*?)`/g, "<code>$1</code>");
                let metaHtml = '<div style="margin-top: 8px; font-size: 11px; color: var(--color-text-muted); display: flex; gap: 8px; flex-wrap: wrap;">';

                if (data.sources && data.sources.length > 0) {
                    metaHtml += `<span><strong>Sources:</strong> ${data.sources.map(s => `<code style="background: rgba(0,0,0,0.06); padding: 1px 4px; border-radius: 3px;">${escapeHtml(s)}</code>`).join(" ")}</span>`;
                }
                if (data.confidence) {
                    metaHtml += `<span><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(0)}%</span>`;
                }
                if (data.elapsed_seconds) {
                    metaHtml += `<span><strong>Latency:</strong> ${data.elapsed_seconds}s</span>`;
                }
                metaHtml += '</div>';

                appendMessage("bot", botHtml + metaHtml);
            } catch (err) {
                const typingEl = document.getElementById(typingId);
                if (typingEl) typingEl.remove();
                appendMessage("bot", `<span style="color: var(--danger);">Query failed: ${err.message}</span>`);
            }
        }

        function appendMessage(sender, htmlContent, customId) {
            const div = document.createElement("div");
            div.className = `chat-message ${sender}`;
            if (customId) div.id = customId;

            if (sender === "user") {
                div.style.cssText = "align-self: flex-end; background: rgba(8, 145, 178, 0.1); border: 1px solid rgba(8, 145, 178, 0.2); padding: 12px 16px; border-radius: 12px 12px 2px 12px; max-width: 80%; font-size: 13px;";
                div.innerHTML = `<div>${escapeHtml(htmlContent)}</div>`;
            } else {
                div.style.cssText = "align-self: flex-start; background: var(--bg-card); border: 1px solid var(--border-glass); padding: 14px 18px; border-radius: 12px 12px 12px 2px; max-width: 85%; font-size: 13px; line-height: 1.5;";
                div.innerHTML = `<div style="font-weight: 600; color: var(--cyan); margin-bottom: 6px; font-size: 12px;">AI Forensic Copilot</div><div>${htmlContent}</div>`;
            }

            messagesContainer.appendChild(div);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }

        if (btnSend) btnSend.addEventListener("click", () => sendQuery());
        if (input) {
            input.addEventListener("keydown", (e) => {
                if (e.key === "Enter") sendQuery();
            });
        }

        // Preset Question Chips
        document.querySelectorAll(".chat-preset-chip").forEach(chip => {
            chip.addEventListener("click", () => {
                const q = chip.getAttribute("data-q");
                if (q) sendQuery(q);
            });
        });
    }

    // Helper: Escape HTML
    function escapeHtml(text) {
        if (!text) return "";
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
