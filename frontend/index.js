/* ═══════════════════════════════════════════════════════════════════════════
   VOID — Agentic Penetration Testing System
   Client-side JavaScript
   ═══════════════════════════════════════════════════════════════════════════ */

(() => {
  "use strict";

  // ── DOM References ───────────────────────────────────────────────────────
  const $  = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const views = {
    landing:  $("#view-landing"),
    pipeline: $("#view-pipeline"),
    report:   $("#view-report"),
  };

  // Landing
  const form         = $("#scan-form");
  const inputUrl     = $("#target-url");
  const selectApp    = $("#app-type");
  const selectMode   = $("#scan-mode");
  const inputUser    = $("#adv-username");
  const inputPass    = $("#adv-password");
  const inputRate    = $("#adv-rate");
  const checkNoAuth  = $("#adv-noauth");
  const checkAuth    = $("#auth-confirm");
  const btnStart     = $("#btn-start");

  // Pipeline
  const pipeTarget   = $("#pipe-target");
  const pipeMode     = $("#pipe-mode");
  const pipeTimer    = $("#pipe-timer");
  const agentList    = $("#agent-list");
  const terminalBody = $("#terminal-body");

  // Report
  const reportContent = $("#report-content");
  const btnExportPdf  = $("#btn-export-pdf");
  const btnPrint      = $("#btn-print");
  const btnNewScan    = $("#btn-new-scan");

  // ── State ────────────────────────────────────────────────────────────────
  let ws = null;
  let timerInterval = null;
  let timerSeconds = 0;
  let currentReportFile = null;

  // Agent detection keywords — maps log content to agent IDs
  const AGENT_MARKERS = [
    { pattern: /recon/i,          agent: "recon" },
    { pattern: /auth/i,           agent: "auth" },
    { pattern: /spider|scan|crawl|zap/i, agent: "scanner" },
    { pattern: /analy/i,          agent: "analyzer" },
    { pattern: /classif/i,        agent: "classifier" },
    { pattern: /report/i,         agent: "reporter" },
  ];

  // Phase detection — more specific patterns for phase transitions
  const PHASE_MARKERS = [
    { pattern: /\brecon(?:naissance)?\s*(?:agent|phase|node|start)/i,  agent: "recon" },
    { pattern: /\bauth(?:entication)?\s*(?:agent|phase|node|start)/i, agent: "auth" },
    { pattern: /\bscann(?:er|ing)\s*(?:agent|phase|node|start)/i,     agent: "scanner" },
    { pattern: /\bspider\s*(?:start|running|launch)/i,                agent: "scanner" },
    { pattern: /\bzap\s*(?:start|running|active|passive)/i,           agent: "scanner" },
    { pattern: /\banaly(?:zer|sis)\s*(?:agent|phase|node|start)/i,    agent: "analyzer" },
    { pattern: /\bclassif(?:ier|ication)\s*(?:agent|phase|node|start)/i, agent: "classifier" },
    { pattern: /\breport(?:er|ing)\s*(?:agent|phase|node|start)/i,    agent: "reporter" },
  ];

  // ── View Transitions ────────────────────────────────────────────────────
  function showView(name) {
    Object.entries(views).forEach(([key, el]) => {
      if (key === name) {
        el.classList.remove("exit-left");
        el.classList.add("active");
      } else if (el.classList.contains("active")) {
        el.classList.remove("active");
        el.classList.add("exit-left");
      }
    });
  }

  // ── Timer ────────────────────────────────────────────────────────────────
  function startTimer() {
    timerSeconds = 0;
    updateTimerDisplay();
    timerInterval = setInterval(() => {
      timerSeconds++;
      updateTimerDisplay();
    }, 1000);
  }

  function stopTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  }

  function updateTimerDisplay() {
    const h = String(Math.floor(timerSeconds / 3600)).padStart(2, "0");
    const m = String(Math.floor((timerSeconds % 3600) / 60)).padStart(2, "0");
    const s = String(timerSeconds % 60).padStart(2, "0");
    pipeTimer.textContent = `${h}:${m}:${s}`;
  }

  // ── Form Validation ─────────────────────────────────────────────────────
  function validateForm() {
    const urlValid = inputUrl.value.trim().match(/^https?:\/\/.+/);
    const authorized = checkAuth.checked;
    btnStart.disabled = !(urlValid && authorized);
  }

  inputUrl.addEventListener("input", validateForm);
  checkAuth.addEventListener("change", validateForm);

  // ── Agent Sidebar State ─────────────────────────────────────────────────
  let activeAgentIndex = -1;
  const agentOrder = ["recon", "auth", "scanner", "analyzer", "classifier", "reporter"];

  function setAgentState(agentId, state) {
    const el = agentList.querySelector(`[data-agent="${agentId}"]`);
    if (el) {
      el.className = `agent-item ${state}`;
    }
  }

  function activateAgent(agentId) {
    const idx = agentOrder.indexOf(agentId);
    if (idx <= activeAgentIndex) return; // Don't go backwards

    // Complete all agents before the new active one
    for (let i = 0; i <= activeAgentIndex; i++) {
      setAgentState(agentOrder[i], "completed");
    }

    activeAgentIndex = idx;
    setAgentState(agentId, "active");
  }

  function completeAllAgents() {
    agentOrder.forEach((id) => setAgentState(id, "completed"));
  }

  function resetAgents() {
    activeAgentIndex = -1;
    agentOrder.forEach((id) => setAgentState(id, "pending"));
  }

  // ── Log Line Classification ─────────────────────────────────────────────
  function classifyLine(text) {
    if (/\[error\]|error:|traceback|exception/i.test(text)) return "error";
    if (/\[warn\]|warning:/i.test(text)) return "warn";
    if (/\[success\]|✅|completed successfully/i.test(text)) return "success";
    if (/\[info\]|ℹ|→/i.test(text)) return "info";
    if (/^=+$|^-+$/.test(text.trim())) return "dim";
    return "";
  }

  function detectAgentTransition(text) {
    for (const { pattern, agent } of PHASE_MARKERS) {
      if (pattern.test(text)) {
        activateAgent(agent);
        return true;
      }
    }
    return false;
  }

  // ── Terminal Output ─────────────────────────────────────────────────────
  function appendLog(text, extraClass = "") {
    const cls = extraClass || classifyLine(text);
    const isAgentMarker = detectAgentTransition(text);

    const p = document.createElement("p");
    p.className = `log-line ${cls}${isAgentMarker ? " agent-marker" : ""}`;
    p.textContent = text;
    terminalBody.appendChild(p);

    // Auto-scroll
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  function clearTerminal() {
    terminalBody.innerHTML = "";
  }

  // ── WebSocket Connection ────────────────────────────────────────────────
  function startScan(config) {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${location.host}/ws/scan`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      clearTerminal();
      appendLog("[VOID] Connection established. Sending configuration...", "info");
      ws.send(JSON.stringify(config));
    };

    ws.onmessage = (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch {
        appendLog(event.data);
        return;
      }

      switch (msg.type) {
        case "log":
          appendLog(msg.data);
          break;

        case "status":
          if (msg.data === "scan_started") {
            appendLog(`[VOID] Scan initiated — target: ${msg.config?.target}`, "success");
          } else if (msg.data === "scan_complete") {
            stopTimer();
            appendLog("", "dim");
            appendLog("[VOID] ═══════════════════════════════════════", "success");

            if (msg.returncode !== 0) {
              appendLog(`[VOID] Scan exited with errors (code ${msg.returncode}). Check the logs above.`, "error");
            } else {
              completeAllAgents();
              appendLog("[VOID] Engagement complete.", "success");
            }

            if (msg.report) {
              currentReportFile = msg.report;
              appendLog(`[VOID] Report: ${msg.report}`, "success");
              // Auto-transition to report view after a brief pause
              setTimeout(() => loadAndShowReport(msg.report), 1500);
            } else if (msg.returncode !== 0) {
              appendLog("[VOID] No report generated — scan did not complete successfully.", "warn");
            }
          }
          break;

        case "error":
          appendLog(`[ERROR] ${msg.data}`, "error");
          stopTimer();
          break;
      }
    };

    ws.onerror = () => {
      appendLog("[ERROR] WebSocket connection error.", "error");
      stopTimer();
    };

    ws.onclose = () => {
      appendLog("[VOID] Connection closed.", "dim");
    };
  }

  // ── Report Loading ──────────────────────────────────────────────────────
  async function loadAndShowReport(filename) {
    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(filename)}`);
      const data = await res.json();

      if (data.error) {
        reportContent.innerHTML = `<p class="error">Failed to load report: ${data.error}</p>`;
      } else {
        reportContent.innerHTML = marked.parse(data.content);
      }
    } catch (err) {
      reportContent.innerHTML = `<p class="error">Failed to fetch report: ${err.message}</p>`;
    }

    showView("report");
  }

  // ── Form Submit Handler ─────────────────────────────────────────────────
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (btnStart.disabled) return;

    const config = {
      target:     inputUrl.value.trim(),
      app:        selectApp.value,
      mode:       selectMode.value,
      username:   inputUser.value.trim(),
      password:   inputPass.value.trim(),
      rate_limit: parseInt(inputRate.value, 10) || 5,
      no_auth:    checkNoAuth.checked,
    };

    // Update pipeline header
    pipeTarget.textContent = config.target;
    pipeMode.textContent = config.mode.toUpperCase();

    // Reset state
    resetAgents();
    clearTerminal();

    // Transition to pipeline view
    showView("pipeline");
    startTimer();
    startScan(config);
  });

  // ── Report Actions ──────────────────────────────────────────────────────
  btnPrint.addEventListener("click", () => {
    window.print();
  });

  btnExportPdf.addEventListener("click", () => {
    // Use print dialog as a PDF export mechanism
    window.print();
  });

  btnNewScan.addEventListener("click", () => {
    // Reset everything
    stopTimer();
    resetAgents();
    clearTerminal();
    currentReportFile = null;

    if (ws) {
      ws.close();
      ws = null;
    }

    // Reset form
    form.reset();
    btnStart.disabled = true;

    showView("landing");
  });

  // ── Initialize ──────────────────────────────────────────────────────────
  validateForm();

})();
