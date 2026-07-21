document.addEventListener("DOMContentLoaded", () => {
    // 1. Tab Switching Functionality
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanes = document.querySelectorAll(".tab-pane");
    const pageTitle = document.getElementById("page-title");
    const pageSubtitle = document.getElementById("page-subtitle");

    const tabMeta = {
        "dashboard": { title: "Security Dashboard", subtitle: "Real-time Windows system metrics & services status" },
        "artifacts": { title: "Artifact Discovery", subtitle: "Identify local LLM installations, caching paths, and model files" },
        "operations": { title: "Hashes & Timeline", subtitle: "Verify integrity of acquired evidence and build chronological timeline" },
        "ai-copilot": { title: "AI Incident Copilot", subtitle: "Synthesize gathered evidence and generate Incident Reports using local LLMs" },
        "rag-chatbot": { title: "AI Forensic Chatbot", subtitle: "Interact with local AI agent using RAG context from evidence logs" }
    };

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const tabId = item.getAttribute("data-tab");
            
            // Toggle sidebar active item
            navItems.forEach(nav => nav.classList.remove("active"));
            item.classList.add("active");

            // Toggle active pane
            tabPanes.forEach(pane => pane.classList.remove("active"));
            document.getElementById(`tab-${tabId}`).classList.add("active");

            // Update Titles
            if (tabMeta[tabId]) {
                pageTitle.textContent = tabMeta[tabId].title;
                pageSubtitle.textContent = tabMeta[tabId].subtitle;
            }

            // Trigger loading when RAG Chatbot is clicked
            if (tabId === "rag-chatbot") {
                loadRagEvidence();
                const modelSelect = document.getElementById("model-select");
                const currentModel = (modelSelect && modelSelect.value) || "llama3.2:1b";
                const ragModelSelect = document.getElementById("rag-model-select");
                if (ragModelSelect && currentModel) {
                    ragModelSelect.value = currentModel;
                }
            }
        });
    });

    // 2. Fetch System & Ollama Information
    async function loadSystemStats() {
        try {
            const res = await fetch("/api/system_info");
            if (!res.ok) throw new Error("Failed to fetch system info");
            const data = await res.json();

            // Quick stats in Header
            document.getElementById("quick-os").textContent = data.os;
            document.getElementById("quick-cpu").textContent = `${data.cpu_usage_percent}%`;
            document.getElementById("quick-ram").textContent = `${data.memory.percentage}%`;

            // Dashboard Grid System Info
            document.getElementById("sys-hostname").textContent = data.hostname;
            document.getElementById("sys-os").textContent = `${data.os} (${data.release})`;
            document.getElementById("sys-version").textContent = data.version;
            document.getElementById("sys-arch").textContent = data.machine;
            document.getElementById("sys-processor").textContent = data.processor || "Generic CPU";

            // Hardware Utilization Cards
            document.getElementById("cpu-cores").textContent = data.cpu_count;
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
            console.error(err);
        }
    }

    async function loadOllamaStats() {
        try {
            const res = await fetch("/api/ollama_info");
            if (!res.ok) throw new Error("Failed to fetch Ollama info");
            const data = await res.json();

            // Update Indicator
            const indicator = document.getElementById("ollama-status-indicator");
            const indicatorText = document.getElementById("ollama-status-text");
            const portDot = document.getElementById("port-status-dot");
            const portText = document.getElementById("port-status-text");

            if (data.service_running || data.port_listening) {
                indicator.classList.add("online");
                indicatorText.textContent = `Online (${data.version})`;
                
                portDot.className = "status-dot green";
                portText.textContent = "Listening on port 11434 (Active)";
            } else {
                indicator.classList.remove("online");
                indicatorText.textContent = "Offline / Inactive";

                portDot.className = "status-dot red";
                portText.textContent = "Port 11434 not listening";
            }

            // Populate Artifacts tab installation paths
            document.getElementById("art-exe").textContent = data.installed_path;
            
            // Populate models select dropdowns
            const select = document.getElementById("model-select");
            const ragSelect = document.getElementById("rag-model-select");
            
            if (select) select.innerHTML = "";
            if (ragSelect) ragSelect.innerHTML = "";
            
            if (data.installed_models && data.installed_models.length > 0) {
                data.installed_models.forEach(model => {
                    if (select) {
                        const opt = document.createElement("option");
                        opt.value = model;
                        opt.textContent = model;
                        select.appendChild(opt);
                    }
                    if (ragSelect) {
                        const opt = document.createElement("option");
                        opt.value = model;
                        opt.textContent = model;
                        if (model.includes("llama3.2:1b") || model.includes("llama3.2")) {
                            opt.selected = true;
                        }
                        ragSelect.appendChild(opt);
                    }
                });
            } else {
                if (select) {
                    const opt = document.createElement("option");
                    opt.value = "";
                    opt.textContent = "No models installed (Run 'ollama pull llama3.2:1b')";
                    select.appendChild(opt);
                }
                if (ragSelect) {
                    const opt = document.createElement("option");
                    opt.value = "";
                    opt.textContent = "No models installed";
                    ragSelect.appendChild(opt);
                }
            }

        } catch (err) {
            console.error(err);
        }
    }

    async function loadProcesses() {
        try {
            const res = await fetch("/api/processes");
            if (!res.ok) throw new Error("Failed to fetch processes");
            const data = await res.json();

            const tbody = document.getElementById("processes-tbody");
            tbody.innerHTML = "";

            if (data.ollama_processes && data.ollama_processes.length > 0) {
                data.ollama_processes.forEach(proc => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="font-mono">${proc.pid}</td>
                        <td>${proc.name}</td>
                        <td>${proc.cpu_percent}%</td>
                        <td class="font-mono">${proc.memory_mb} MB</td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No active Ollama service processes detected</td></tr>`;
            }

        } catch (err) {
            console.error(err);
        }
    }

    async function loadArtifactsFiles() {
        try {
            const res = await fetch("/api/artifacts");
            if (!res.ok) throw new Error("Failed to load artifacts");
            const data = await res.json();

            document.getElementById("art-dir").textContent = data.model_directory;
            document.getElementById("art-total-files").textContent = data.total_files;

            const tbody = document.getElementById("files-tbody");
            tbody.innerHTML = "";

            if (data.files && data.files.length > 0) {
                data.files.forEach(file => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="font-mono">${file.name}</td>
                        <td class="font-mono text-muted">${file.path}</td>
                        <td class="font-mono">${file.size_mb} MB</td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No cache files found in directory</td></tr>`;
            }

        } catch (err) {
            console.error(err);
        }
    }

    // 3. Hashing Operation Trigger
    const btnHashes = document.getElementById("btn-run-hashes");
    btnHashes.addEventListener("click", async () => {
        btnHashes.disabled = true;
        btnHashes.innerHTML = `<span class="material-icons-round spinner-btn">autorenew</span> Computing...`;
        
        try {
            const res = await fetch("/api/hashing", { method: "POST" });
            if (!res.ok) throw new Error("Failed to run hashes");
            const data = await res.json();
            
            // Populate Hashes table
            const tbody = document.getElementById("hashes-tbody");
            tbody.innerHTML = "";

            // Show run-type banner as first row
            const bannerRow = document.createElement("tr");
            if (data.is_first_run) {
                bannerRow.innerHTML = `<td colspan="3" style="background: rgba(16,185,129,0.1); border-left: 3px solid #10b981; color: #10b981; font-weight: 600; font-size: 12px; padding: 10px 16px;">
                    ✅ BASELINE RECORDED — Hashes saved. Now edit any file inside the <code style="background:rgba(255,255,255,0.07); padding:1px 5px; border-radius:4px;">Evidence/</code> folder, then click Compute SHA256 Hashes again to detect tampering.
                </td>`;
            } else if (data.has_tampered) {
                bannerRow.innerHTML = `<td colspan="3" style="background: rgba(239,68,68,0.12); border-left: 3px solid #ef4444; color: #ef4444; font-weight: 600; font-size: 12px; padding: 10px 16px;">
                    🚨 VERIFICATION RUN — Tampering detected in one or more evidence files! See highlighted rows below.
                </td>`;
            } else {
                bannerRow.innerHTML = `<td colspan="3" style="background: rgba(6,182,212,0.08); border-left: 3px solid #06b6d4; color: #06b6d4; font-weight: 600; font-size: 12px; padding: 10px 16px;">
                    🔍 VERIFICATION RUN — All files verified against baseline. No tampering detected.
                </td>`;
            }
            tbody.appendChild(bannerRow);
            
            data.hashes.forEach(file => {
                const tr = document.createElement("tr");
                if (file.status === "tampered") {
                    tr.className = "row-tampered";
                }
                
                const statusBadge = (() => {
                    if (file.status === "verified") {
                        return `<span class="status-badge-inline verified">✅ Verified</span>`;
                    } else if (file.status === "tampered") {
                        return `<span class="status-badge-inline tampered">⚠️ TAMPERED</span>`;
                    } else {
                        return `<span class="status-badge-inline new">🆕 New File</span>`;
                    }
                })();

                tr.innerHTML = `
                    <td><strong>${file.filename}</strong></td>
                    <td>
                        <div class="font-mono text-cyan" style="word-break: break-all;">${file.hash}</div>
                        ${file.status === 'tampered' ? `<div class="font-mono" style="color:#ef4444; font-size: 11px; margin-top: 6px;">⚠ Baseline was: ${file.baseline_hash}</div>` : ''}
                    </td>
                    <td>${statusBadge}</td>
                `;
                tbody.appendChild(tr);
            });

            if (data.is_first_run) {
                showToast("✅ Baseline hashes recorded successfully!");
            } else if (data.has_tampered) {
                showToast("🚨 Tampering detected in evidence files!");
            } else {
                showToast("✅ All evidence files verified — integrity confirmed.");
            }

        } catch (err) {
            showToast("Error computing hashes: " + err.message);
        } finally {
            btnHashes.disabled = false;
            btnHashes.innerHTML = `<span class="material-icons-round">fingerprint</span> Compute SHA256 Hashes`;
        }
    });

    // 4. Timeline Operation Trigger
    const btnTimeline = document.getElementById("btn-run-timeline");
    btnTimeline.addEventListener("click", async () => {
        btnTimeline.disabled = true;
        btnTimeline.innerHTML = `<span class="material-icons-round spinner-btn">autorenew</span> Building...`;

        try {
            const res = await fetch("/api/timeline", { method: "POST" });
            if (!res.ok) throw new Error("Failed to build timeline");
            const data = await res.json();

            // Populate Stepper Timeline
            const stepper = document.getElementById("timeline-stepper");
            stepper.innerHTML = "";

            data.timeline.forEach(event => {
                const node = document.createElement("div");
                node.className = "timeline-node";
                node.innerHTML = `
                    <div class="timeline-icon"></div>
                    <div class="timeline-content">
                        <span class="timeline-time">${event.modified_time}</span>
                        <span class="timeline-title">${event.filename} (Modified)</span>
                    </div>
                `;
                stepper.appendChild(node);
            });

            showToast("Forensic timeline built successfully!");

        } catch (err) {
            showToast("Error compiling timeline: " + err.message);
        } finally {
            btnTimeline.disabled = false;
            btnTimeline.innerHTML = `<span class="material-icons-round">schedule</span> Build Forensic Timeline`;
        }
    });

    // 5. AI Copilot Report Generation
    const btnReport = document.getElementById("btn-generate-report");
    const preloader = document.getElementById("report-preloader");
    const reportContent = document.getElementById("report-content");
    const reportBadge = document.getElementById("report-status-badge");

    btnReport.addEventListener("click", async () => {
        const model = document.getElementById("model-select").value;
        if (!model) {
            showToast("Please choose a valid local LLM model");
            return;
        }

        btnReport.disabled = true;
        preloader.classList.remove("hidden");
        reportContent.classList.add("hidden");
        reportBadge.className = "status-badge";
        reportBadge.textContent = "SYNTHESIZING...";

        try {
            const res = await fetch("/api/report/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ model })
            });
            if (!res.ok) throw new Error("Failed to generate report");
            const data = await res.json();

            // Simple markdown-to-html conversion for display formatting
            renderMarkdown(data.report);

            reportBadge.className = "status-badge success";
            reportBadge.textContent = "COMPLETED";
            showToast("AI Incident Report generated successfully!");

        } catch (err) {
            reportContent.textContent = "Error running analysis: " + err.message;
            reportBadge.className = "status-badge";
            reportBadge.textContent = "FAILED";
            showToast("Error generating report");
        } finally {
            btnReport.disabled = false;
            preloader.classList.add("hidden");
            reportContent.classList.remove("hidden");
        }
    });

    // Read existing report on init
    async function loadExistingReport() {
        try {
            const res = await fetch("/api/report/get");
            if (!res.ok) throw new Error("Failed to load report");
            const data = await res.json();
            if (data.exists) {
                renderMarkdown(data.report);
                reportBadge.className = "status-badge success";
                reportBadge.textContent = "COMPLETED";
            }
        } catch (err) {
            console.error(err);
        }
    }

    // Markdown Parser Helper
    function renderMarkdown(mdText) {
        let html = mdText
            // Escape HTML tags to prevent injections
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            // Headers
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            // Bold
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            // Code blocks
            .replace(/```text([\s\S]*?)```/g, '<pre class="font-mono" style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 6px; margin: 10px 0;">$1</pre>')
            .replace(/```([\s\S]*?)```/g, '<pre class="font-mono" style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 6px; margin: 10px 0;">$1</pre>')
            .replace(/`(.*?)`/g, '<code class="font-mono" style="background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px;">$1</code>')
            // Tables (Simple conversion)
            .replace(/\| (.*) \|/g, (match) => {
                let cells = match.split('|').map(c => c.trim()).filter(c => c !== '');
                if (cells[0].includes('---')) return ''; // Skip separator lines
                let isHeader = match.includes('File Name') || match.includes('SHA-256') || match.includes('Description');
                let tag = isHeader ? 'th' : 'td';
                let tr = '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
                return isHeader ? `<table><thead>${tr}</thead><tbody>` : tr;
            });
        
        // Close table tags
        if (html.includes('<table>')) {
            html = html.replace(/<\/tr>(?!\s*<tr>)/g, '</tr></tbody></table>');
        }

        reportContent.innerHTML = html;
    }

    // Toast Popup Helper
    function showToast(text) {
        const toast = document.getElementById("toast");
        const toastText = document.getElementById("toast-text");
        toastText.textContent = text;
        toast.classList.remove("hidden");
        
        setTimeout(() => {
            toast.classList.add("hidden");
        }, 4000);
    }

    // 5.5 RAG Chatbot Logic
    const ragChatInput = document.getElementById("rag-chat-input");
    const ragBtnSend = document.getElementById("rag-btn-send");
    const ragMessagesArea = document.getElementById("rag-messages-area");
    const ragFileList = document.getElementById("rag-file-list");
    const ragFileInput = document.getElementById("rag-file-input");
    const ragUploadStatus = document.getElementById("rag-upload-status");
    const ragUploadStatusText = document.getElementById("rag-upload-status-text");
    const chatTypingIndicator = document.getElementById("chat-typing-indicator");

    async function loadRagEvidence() {
        try {
            const res = await fetch("/api/chat/evidence");
            if (!res.ok) throw new Error("Failed to load evidence files");
            const files = await res.json();

            ragFileList.innerHTML = "";
            if (files.length === 0) {
                ragFileList.innerHTML = `<div class="text-muted text-center py-4">No evidence files found.</div>`;
                return;
            }

            files.forEach(file => {
                const item = document.createElement("div");
                item.className = "rag-file-item";
                
                const sizeKb = (file.size / 1024).toFixed(2);
                item.innerHTML = `
                    <div class="rag-file-details">
                        <span class="material-icons-round rag-file-icon">description</span>
                        <div class="rag-file-info">
                            <span class="rag-file-name" title="${file.name}">${file.name}</span>
                            <span class="rag-file-size">${sizeKb} KB</span>
                        </div>
                    </div>
                `;
                ragFileList.appendChild(item);
            });
        } catch (err) {
            console.error("Error loading RAG evidence:", err);
            ragFileList.innerHTML = `<div class="text-danger text-center py-4">Error loading evidence.</div>`;
        }
    }

    // Expose loadRagEvidence globally so it can be called from tab click
    window.loadRagEvidence = loadRagEvidence;

    async function sendChatMessage() {
        const question = ragChatInput.value.trim();
        if (!question) return;

        // Append user message
        appendChatMessage("user", question);
        ragChatInput.value = "";

        // Show typing indicator
        chatTypingIndicator.classList.remove("hidden");
        ragMessagesArea.scrollTop = ragMessagesArea.scrollHeight;

        const modelSelect = document.getElementById("rag-model-select");
        const model = (modelSelect && modelSelect.value) || "llama3.2:1b";

        try {
            const res = await fetch("/api/chat/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ question, model })
            });

            if (!res.ok) {
                const errorData = await res.json();
                throw new Error(errorData.detail || "Server error");
            }

            const data = await res.json();
            
            // Hide typing indicator
            chatTypingIndicator.classList.add("hidden");

            // Append AI response
            appendChatMessage("ai", data.answer, data.sources, data.confidence, data.time);

        } catch (err) {
            console.error("Chat error:", err);
            chatTypingIndicator.classList.add("hidden");
            appendChatMessage("ai", `⚠️ Error: ${err.message}. Please check if Ollama is running and has the selected model pulled.`);
        }
        
        ragMessagesArea.scrollTop = ragMessagesArea.scrollHeight;
    }

    function appendChatMessage(sender, text, sources = [], confidence = "", timeStr = "") {
        const msgDiv = document.createElement("div");
        msgDiv.className = `chat-message ${sender}`;

        // Simple markdown formatter for bubble text
        let formattedText = text
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            // Headers
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            // Bold
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            // Bullet points
            .replace(/^\s*-\s+(.*$)/gim, '<li>$1</li>')
            // Code blocks/inline
            .replace(/`(.*?)`/g, '<code class="font-mono" style="background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px;">$1</code>');

        // Wrap consecutive <li> tags in <ul>
        if (formattedText.includes('<li>')) {
            formattedText = formattedText.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
        }

        const time = timeStr || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const senderName = sender === "user" ? "Investigator" : "RAG Assistant";

        let sourcesHtml = "";
        if (sources && sources.length > 0) {
            sourcesHtml = `
                <div class="sources-used">
                    <span class="sources-title">Sources used:</span>
                    ${sources.map(src => `<span class="source-pill">${src}</span>`).join('')}
                </div>
            `;
        }

        let confidenceHtml = "";
        if (confidence) {
            const confClass = confidence.toLowerCase();
            confidenceHtml = `<span class="confidence-badge-inline ${confClass}">${confidence} Confidence</span>`;
        }

        msgDiv.innerHTML = `
            <div class="message-bubble">
                ${formattedText}
                ${sourcesHtml}
            </div>
            <div class="message-meta">
                <span>${senderName}</span>
                <span>•</span>
                <span>${time}</span>
                ${confidenceHtml ? `<span>•</span>${confidenceHtml}` : ""}
            </div>
        `;

        ragMessagesArea.appendChild(msgDiv);
        ragMessagesArea.scrollTop = ragMessagesArea.scrollHeight;
    }

    // Input elements event listeners
    ragBtnSend.addEventListener("click", sendChatMessage);
    ragChatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            sendChatMessage();
        }
    });

    // Quick start suggestions
    const suggestionPills = document.querySelectorAll(".suggestion-pill");
    suggestionPills.forEach(pill => {
        pill.addEventListener("click", () => {
            const question = pill.getAttribute("data-question");
            ragChatInput.value = question;
            ragChatInput.focus();
        });
    });

    // File Upload Handler
    ragFileInput.addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        ragUploadStatus.classList.remove("hidden");
        ragUploadStatusText.textContent = `Indexing ${file.name}...`;

        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await fetch("/api/chat/upload", {
                method: "POST",
                body: formData
            });

            if (!res.ok) throw new Error("Upload and index failed");
            
            const data = await res.json();
            showToast(`✅ ${file.name} uploaded and indexed successfully!`);
            
            // Reload evidence file lists
            loadRagEvidence();
            
            // Append a notification message in the chat
            appendChatMessage("ai", `ℹ️ System: Newly uploaded evidence **${file.name}** has been processed and indexed into the vector DB successfully. You can now query details inside it.`);

        } catch (err) {
            console.error("Upload error:", err);
            showToast("❌ Failed to upload evidence file.");
        } finally {
            ragUploadStatus.classList.add("hidden");
            e.target.value = null; // Reset file input
        }
    });

    // Sync models selection between both dropdowns
    const ragModelSelect = document.getElementById("rag-model-select");
    const modelSelect = document.getElementById("model-select");
    if (ragModelSelect && modelSelect) {
        ragModelSelect.addEventListener("change", () => {
            modelSelect.value = ragModelSelect.value;
        });
        modelSelect.addEventListener("change", () => {
            ragModelSelect.value = modelSelect.value;
        });
    }

    // 6. Init Calls & Loops
    loadSystemStats();
    loadOllamaStats();
    loadProcesses();
    loadArtifactsFiles();
    loadExistingReport();

    // Poll resource utilization every 3 seconds
    setInterval(loadSystemStats, 3000);

});

