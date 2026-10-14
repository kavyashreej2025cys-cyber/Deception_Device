"use strict";

const REFRESH_INTERVAL_MS = 5000;

const state = {
  refreshing: false,
  chartRows: [],
  refreshTimer: null,
  alerts: [],
  alertPage: 1,
  alertPageSize: 5,
  selectedDecoy: null,
  selectedDecoyAction: null,
};

const elements = {
  connectionDot: document.querySelector("#connection-dot"),
  connectionText: document.querySelector("#connection-text"),
  refreshButton: document.querySelector("#refresh-button"),
  errorBanner: document.querySelector("#error-banner"),
  errorMessage: document.querySelector("#error-message"),
  approvalBanner: document.querySelector("#approval-banner"),
  approvalBannerCount: document.querySelector(
    "#approval-banner-count"
  ),
  lastUpdated: document.querySelector("#last-updated-value"),

  summaryEvents: document.querySelector("#summary-events"),
  summaryAttackers: document.querySelector("#summary-attackers"),
  summaryDecoys: document.querySelector("#summary-decoys"),
  summaryApprovals: document.querySelector("#summary-approvals"),
  summaryAlerts: document.querySelector("#summary-alerts"),
  summaryPredictions: document.querySelector(
    "#summary-predictions"
  ),

  attackersBody: document.querySelector(
    "#attackers-table-body"
  ),
  decoyList: document.querySelector("#decoy-list"),
  decoyEventDetail: document.querySelector("#decoy-event-detail"),
  latestPrediction: document.querySelector(
    "#latest-prediction"
  ),
  decisionsBody: document.querySelector(
    "#decisions-table-body"
  ),
  eventsBody: document.querySelector("#events-table-body"),
  lifecycleList: document.querySelector("#lifecycle-list"),
  alertList: document.querySelector("#alert-list"),
  overviewAlertList: document.querySelector("#overview-alert-list"),
  alertSearch: document.querySelector("#alert-search"),
  alertSeverity: document.querySelector("#alert-severity"),
  alertStatus: document.querySelector("#alert-status"),
  alertPrev: document.querySelector("#alert-prev"),
  alertNext: document.querySelector("#alert-next"),
  alertPageStatus: document.querySelector("#alert-page-status"),
  navAlertCount: document.querySelector("#nav-alert-count"),
  navApprovalCount: document.querySelector("#nav-approval-count"),
  eventLimit: document.querySelector("#event-limit"),

  chart: document.querySelector("#event-chart"),
  chartEmpty: document.querySelector("#chart-empty"),
  attackerDialog: document.querySelector("#attacker-dialog"),
  attackerDialogTitle: document.querySelector("#attacker-dialog-title"),
  attackerDialogContent: document.querySelector("#attacker-dialog-content"),
  confirmDialog: document.querySelector("#confirm-dialog"),
  deactivateReason: document.querySelector("#deactivate-reason"),
  decoyActionTitle: document.querySelector("#decoy-action-title"),
  decoyActionDescription: document.querySelector("#decoy-action-description"),
  decoyReasonLabel: document.querySelector("#decoy-reason-label"),
  confirmDecoyAction: document.querySelector("#confirm-decoy-action"),
};


function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


function formatName(value) {
  if (!value) {
    return "Unknown";
  }

  return String(value)
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (character) => character.toUpperCase());
}


function formatNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return new Intl.NumberFormat().format(number);
}


function formatPercent(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return `${Math.round(number * 100)}%`;
}


function formatTimestamp(value) {
  if (!value) {
    return "Not available";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "medium",
    }
  ).format(date);
}


function formatShortTimestamp(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(
    undefined,
    {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }
  ).format(date);
}


function riskBucket(score) {
  const value = Number(score) || 0;

  if (value <= 30) {
    return "low";
  }

  if (value <= 60) {
    return "medium";
  }

  if (value <= 80) {
    return "high";
  }

  return "critical";
}


function badge(value, styleName = "muted") {
  return `
    <span class="badge badge-${escapeHtml(styleName)}">
      ${escapeHtml(formatName(value))}
    </span>
  `;
}


function actionStyle(action) {
  const normalized = String(action || "").toUpperCase();

  if (normalized === "ACTIVATE_DECOY") {
    return "danger";
  }

  if (
    normalized === "PREPARE_DECOY"
    || normalized === "COLLECT_MORE_DATA"
  ) {
    return "warning";
  }

  if (normalized === "MONITOR") {
    return "success";
  }

  return "info";
}


function statusStyle(status) {
  const normalized = String(status || "").toLowerCase();

  if (
    normalized === "active"
    || normalized === "activated"
    || normalized === "completed"
  ) {
    return "success";
  }

  if (
    normalized.includes("fail")
    || normalized === "error"
  ) {
    return "danger";
  }

  if (
    normalized === "recommended"
    || normalized === "pending"
  ) {
    return "warning";
  }

  return "muted";
}


function serviceStyle(service) {
  const styles = {
    ssh: "info",
    web: "success",
    database: "warning",
    iot: "medium",
  };

  return styles[String(service || "").toLowerCase()] || "muted";
}


function safeDetails(details) {
  if (!details || typeof details !== "object") {
    return "";
  }

  const redacted = {};

  for (const [key, rawValue] of Object.entries(details)) {
    const normalizedKey = key.toLowerCase();

    if (
      normalizedKey.includes("password")
      || normalizedKey.includes("secret")
      || normalizedKey.includes("token")
    ) {
      redacted[key] = "[redacted]";
      continue;
    }

    const text = String(rawValue ?? "");
    redacted[key] = (
      text.length > 100
        ? `${text.slice(0, 100)}…`
        : text
    );
  }

  return JSON.stringify(redacted);
}


async function fetchJson(path) {
  const response = await fetch(
    path,
    {
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error(
      `${path} returned HTTP ${response.status}`
    );
  }

  return response.json();
}


async function postJson(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Dashboard-Action": "confirmed",
    },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(result.message || result.error || `HTTP ${response.status}`);
  }
  return result;
}


function showToast(message, isError = false) {
  const toast = document.createElement("div");
  toast.className = `toast${isError ? " toast-error" : ""}`;
  toast.textContent = message;
  document.body.append(toast);
  window.setTimeout(() => toast.remove(), 3600);
}


function setConnectionState(mode, message) {
  elements.connectionDot.className = (
    `status-dot status-dot-${mode}`
  );
  elements.connectionText.textContent = message;
}


function renderSummary(summary) {
  elements.summaryEvents.textContent = formatNumber(
    summary.total_events
  );
  elements.summaryAttackers.textContent = formatNumber(
    summary.attackers
  );
  elements.summaryDecoys.textContent = formatNumber(
    summary.active_decoys
  );
  elements.summaryApprovals.textContent = formatNumber(
    summary.pending_approvals
  );
  elements.summaryAlerts.textContent = formatNumber(
    summary.open_alerts
  );
  elements.summaryPredictions.textContent = formatNumber(
    summary.predictions
  );

  const approvalCount = Number(
    summary.pending_approvals
  ) || 0;

  elements.approvalBannerCount.textContent = approvalCount;
  elements.navApprovalCount.textContent = approvalCount;
  elements.navApprovalCount.classList.toggle("hidden", approvalCount === 0);
  const openAlertCount = Number(summary.open_alerts) || 0;
  elements.navAlertCount.textContent = openAlertCount;
  elements.navAlertCount.classList.toggle("hidden", openAlertCount === 0);
  elements.approvalBanner.classList.toggle(
    "hidden",
    approvalCount === 0
  );
}

function renderAlerts(alerts) {
  state.alerts = alerts;
  const openAlerts = alerts.filter((alert) => (
    String(alert.status).toLowerCase() === "open"
  ));

  if (!openAlerts.length) {
    elements.overviewAlertList.innerHTML = `<p class="empty-state">No open alerts. Your queue is clear.</p>`;
  } else {
    elements.overviewAlertList.innerHTML = openAlerts.slice(0, 3).map((alert) => `
      <button class="compact-alert" data-open-view="alerts">
        <i aria-hidden="true"></i>
        <span><strong>${escapeHtml(alert.title || "Security alert")}</strong><small>${escapeHtml(alert.source_ip || "Unknown source")} · ${escapeHtml(formatShortTimestamp(alert.created_at))}</small></span>
        ${badge(alert.severity, String(alert.severity || "medium").toLowerCase())}
      </button>
    `).join("");
  }

  renderAlertPage();
}


function renderAlertPage() {
  const query = elements.alertSearch.value.trim().toLowerCase();
  const severityFilter = elements.alertSeverity.value;
  const statusFilter = elements.alertStatus.value;
  const filtered = state.alerts.filter((alert) => {
    const severity = String(alert.severity || "").toLowerCase();
    const status = String(alert.status || "").toLowerCase();
    const searchable = `${alert.title || ""} ${alert.message || ""} ${alert.source_ip || ""} ${alert.alert_type || ""}`.toLowerCase();
    return (severityFilter === "all" || severity === severityFilter)
      && (statusFilter === "all" || status === statusFilter)
      && (!query || searchable.includes(query));
  });
  const pageCount = Math.max(1, Math.ceil(filtered.length / state.alertPageSize));
  state.alertPage = Math.min(state.alertPage, pageCount);
  const start = (state.alertPage - 1) * state.alertPageSize;
  const pageRows = filtered.slice(start, start + state.alertPageSize);

  if (!pageRows.length) {
    elements.alertList.innerHTML = `
      <div class="alert-empty">
        <span class="alert-empty-icon" aria-hidden="true">✓</span>
        <div>
          <strong>No matching alerts</strong>
          <p>Try changing the search or filters.</p>
        </div>
      </div>
    `;
  } else {
    elements.alertList.innerHTML = pageRows
    .map((alert) => {
      const severity = String(
        alert.severity || "medium"
      ).toLowerCase();

      return `
        <article class="alert-inbox-row alert-item-${escapeHtml(severity)}">
          <div class="alert-indicator" aria-hidden="true"></div>
          <div class="alert-content">
            <p class="alert-title">${escapeHtml(alert.title || "Security alert")}</p>
            <p class="alert-type">${escapeHtml(formatName(alert.alert_type))}</p>
          </div>
          <div class="alert-source"><small>Source</small><strong>${escapeHtml(alert.source_ip || "Unknown")}</strong></div>
          <time datetime="${escapeHtml(alert.created_at)}">${escapeHtml(formatShortTimestamp(alert.created_at))}</time>
          <div class="alert-row-badges">${badge(alert.severity, severity)}${badge(alert.status, statusStyle(alert.status))}</div>
          <div class="alert-row-actions"><button class="button button-small" data-alert-details="${Number(alert.alert_id)}">Details</button>${String(alert.status).toLowerCase() !== "acknowledged" ? `<button class="button button-small" data-alert-action="acknowledged" data-alert-id="${Number(alert.alert_id)}">Acknowledge</button>` : ""}${String(alert.status).toLowerCase() !== "resolved" ? `<button class="button button-small" data-alert-action="resolved" data-alert-id="${Number(alert.alert_id)}">Resolve</button>` : ""}${String(alert.status).toLowerCase() !== "open" ? `<button class="button button-small" data-alert-action="open" data-alert-id="${Number(alert.alert_id)}">Reopen</button>` : ""}</div>
          <div class="alert-expanded hidden" data-alert-panel="${Number(alert.alert_id)}"><p>${escapeHtml(alert.message || "No additional details")}</p><span>Decision #${formatNumber(alert.related_decision_id)} · Prediction #${formatNumber(alert.related_prediction_id)} · Created ${escapeHtml(formatTimestamp(alert.created_at))}</span></div>
        </article>
      `;
    })
    .join("");
  }
  elements.alertPageStatus.textContent = `${filtered.length} alerts · Page ${state.alertPage} of ${pageCount}`;
  elements.alertPrev.disabled = state.alertPage <= 1;
  elements.alertNext.disabled = state.alertPage >= pageCount;
}


function renderAttackers(attackers) {
  if (!attackers.length) {
    elements.attackersBody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">
          No external attacker profiles have been created.
        </td>
      </tr>
    `;
    return;
  }

  elements.attackersBody.innerHTML = attackers
    .map((attacker) => {
      const score = Math.max(
        0,
        Math.min(100, Number(attacker.risk_score) || 0)
      );
      const bucket = riskBucket(score);

      return `
        <tr class="attacker-row" data-attacker-id="${Number(attacker.attacker_id)}" tabindex="0" aria-label="View details for ${escapeHtml(attacker.source_ip)}">
          <td>
            <strong>${escapeHtml(attacker.source_ip)}</strong>
          </td>
          <td class="risk-cell">
            <div class="risk-score">
              <div
                class="risk-meter risk-meter-${bucket}"
                aria-label="Risk score ${score} out of 100"
              >
                <span style="width: ${score}%"></span>
              </div>
              <strong>${score}</strong>
            </div>
          </td>
          <td>
            ${badge(attacker.primary_attack_type, bucket)}
          </td>
          <td>
            ${escapeHtml(
              formatShortTimestamp(attacker.last_seen)
            )}
          </td>
        </tr>
      `;
    })
    .join("");
}


function renderDecoys(decoys) {
  if (!decoys.length) {
    elements.decoyList.innerHTML = `
      <p class="empty-state">
        No adaptive decoys have been registered yet.
      </p>
    `;
    return;
  }

  elements.decoyList.innerHTML = decoys
    .map((decoy) => `
      <div class="decoy-item">
        <div>
          <p class="decoy-name">
            ${escapeHtml(formatName(decoy.name))}
          </p>
          <p class="decoy-meta">
            ${escapeHtml(decoy.container_name || "No container")}
            · Activated
            ${escapeHtml(formatShortTimestamp(decoy.activated_at))}
          </p>
        </div>

        <div>
          ${badge(decoy.status, statusStyle(decoy.status))}
          <div class="decoy-actions">
            <button class="button button-small" data-decoy-events="${escapeHtml(decoy.name)}">View activity</button>
            ${String(decoy.status).toLowerCase() === "active" ? `<button class="button button-small button-danger" data-decoy-action="deactivate" data-decoy-key="${escapeHtml(decoy.name)}">Deactivate</button>` : `<button class="button button-small button-activate" data-decoy-action="activate" data-decoy-key="${escapeHtml(decoy.name)}">Activate</button>`}
          </div>
        </div>
      </div>
    `)
    .join("");
}


function renderLatestPrediction(predictions) {
  if (!predictions.length) {
    elements.latestPrediction.innerHTML = `
      <p class="empty-state">
        No contextual AI predictions are available.
      </p>
    `;
    return;
  }

  const prediction = predictions[0];
  const confidence = Math.max(
    0,
    Math.min(1, Number(prediction.confidence) || 0)
  );
  const confidenceDegrees = Math.round(confidence * 360);

  elements.latestPrediction.innerHTML = `
    <div class="prediction-primary">
      <div>
        <p class="summary-label">Predicted behavior</p>
        <p class="prediction-class">
          ${escapeHtml(formatName(prediction.predicted_class))}
        </p>
      </div>

      <div
        class="confidence-ring"
        style="--confidence: ${confidenceDegrees}deg"
        aria-label="Confidence ${formatPercent(confidence)}"
      >
        <strong>${escapeHtml(formatPercent(confidence))}</strong>
      </div>
    </div>

    <div class="prediction-meta">
      <div class="meta-block">
        <span>Source IP</span>
        <strong>${escapeHtml(prediction.source_ip)}</strong>
      </div>

      <div class="meta-block">
        <span>Events analyzed</span>
        <strong>${formatNumber(prediction.event_count)}</strong>
      </div>

      <div class="meta-block">
        <span>Window ended</span>
        <strong>
          ${escapeHtml(formatShortTimestamp(prediction.window_end))}
        </strong>
      </div>

      <div class="meta-block">
        <span>Model</span>
        <strong>${escapeHtml(prediction.model_version)}</strong>
      </div>
    </div>
  `;
}


function renderDecisions(decisions) {
  if (!decisions.length) {
    elements.decisionsBody.innerHTML = `
      <tr>
        <td colspan="8" class="empty-state">
          No adaptive decisions have been recorded.
        </td>
      </tr>
    `;
    return;
  }

  elements.decisionsBody.innerHTML = decisions
    .map((decision) => {
      const bucket = String(
        decision.risk_bucket || "low"
      ).toLowerCase();

      return `
        <tr title="${escapeHtml(decision.reason || "")}">
          <td>#${formatNumber(decision.decision_id)}</td>
          <td>${escapeHtml(decision.source_ip)}</td>
          <td>${badge(decision.attack_class, "info")}</td>
          <td>${escapeHtml(formatPercent(decision.confidence))}</td>
          <td>${badge(
            `${decision.risk_score} ${decision.risk_bucket}`,
            bucket
          )}</td>
          <td>${badge(
            decision.recommended_action,
            actionStyle(decision.recommended_action)
          )}</td>
          <td>${escapeHtml(
            decision.decoy_key
              ? formatName(decision.decoy_key)
              : "—"
          )}</td>
          <td>${badge(
            decision.execution_status,
            statusStyle(decision.execution_status)
          )}</td>
        </tr>
      `;
    })
    .join("");
}


function renderEvents(events) {
  if (!events.length) {
    elements.eventsBody.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">
          No security events have been captured.
        </td>
      </tr>
    `;
    return;
  }

  elements.eventsBody.innerHTML = events
    .map((event) => {
      const context = safeDetails(event.details);

      return `
        <tr>
          <td>
            ${escapeHtml(formatShortTimestamp(event.timestamp))}
          </td>
          <td>${escapeHtml(event.source_ip || "Unknown")}</td>
          <td>${badge(
            event.service,
            serviceStyle(event.service)
          )}</td>
          <td>${escapeHtml(formatName(event.event_type))}</td>
          <td>
            <span
              class="context-text"
              title="${escapeHtml(context)}"
            >
              ${escapeHtml(context || "No additional context")}
            </span>
          </td>
        </tr>
      `;
    })
    .join("");
}


function renderLifecycle(events) {
  if (!events.length) {
    elements.lifecycleList.innerHTML = `
      <li class="empty-state">
        No adaptive lifecycle events have been recorded.
      </li>
    `;
    return;
  }

  elements.lifecycleList.innerHTML = events
    .map((event) => {
      const reason = (
        event.details
        && typeof event.details === "object"
        && event.details.reason
      )
        ? event.details.reason
        : "Lifecycle action completed";

      return `
        <li class="timeline-item">
          <span class="timeline-marker" aria-hidden="true"></span>

          <div>
            <p class="timeline-title">
              ${escapeHtml(formatName(event.action))}
              ·
              ${escapeHtml(formatName(event.decoy_key))}
            </p>
            <p class="timeline-detail">
              ${escapeHtml(reason)}
              · ${escapeHtml(formatName(event.execution_mode))}
            </p>
          </div>

          <time
            class="timeline-time"
            datetime="${escapeHtml(event.created_at)}"
          >
            ${escapeHtml(formatShortTimestamp(event.created_at))}
          </time>
        </li>
      `;
    })
    .join("");
}


async function showAttackerDetail(attackerId) {
  elements.attackerDialogContent.innerHTML = `<p class="loading-cell">Loading attacker evidence…</p>`;
  elements.attackerDialog.showModal();
  try {
    const report = await fetchJson(`/api/attackers/${attackerId}`);
    const attacker = report.attacker;
    elements.attackerDialogTitle.textContent = attacker.source_ip;
    const serviceList = Object.entries(report.summary.services || {})
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${formatName(name)} (${count})`).join(", ") || "None";
    const recentRows = report.events.slice(0, 12).map((event) => `
      <tr><td>${escapeHtml(formatShortTimestamp(event.timestamp))}</td><td>${badge(event.service, serviceStyle(event.service))}</td><td>${escapeHtml(formatName(event.event_type))}</td><td><span class="context-text">${escapeHtml(safeDetails(event.details))}</span></td></tr>
    `).join("");
    elements.attackerDialogContent.innerHTML = `
      <div class="report-actions"><a class="button button-primary" href="/reports/attacker/${attackerId}" target="_blank" rel="noopener">Open analyst report</a><a class="button" href="/api/attackers/${attackerId}/report.json">Download JSON</a></div>
      <div class="detail-grid"><div class="detail-stat"><span>Risk</span><strong>${Number(attacker.risk_score)}/100</strong></div><div class="detail-stat"><span>Primary pattern</span><strong>${escapeHtml(formatName(attacker.primary_attack_type))}</strong></div><div class="detail-stat"><span>Captured events</span><strong>${formatNumber(report.summary.event_count)}</strong></div><div class="detail-stat"><span>Decoy interactions</span><strong>${formatNumber(report.summary.decoy_interactions)}</strong></div></div>
      <section class="detail-section"><h3>Observed behaviour</h3><p class="helper-note">Services targeted: ${escapeHtml(serviceList)}</p></section>
      <section class="detail-section"><h3>Recent attack sequence</h3><div class="table-scroll"><table><thead><tr><th>Time</th><th>Service</th><th>Action</th><th>Evidence</th></tr></thead><tbody>${recentRows || `<tr><td colspan="4" class="empty-state">No events recorded.</td></tr>`}</tbody></table></div></section>
    `;
  } catch (error) {
    elements.attackerDialogContent.innerHTML = `<p class="empty-state">Unable to load details: ${escapeHtml(error.message)}</p>`;
  }
}


async function showDecoyEvents(decoyKey) {
  elements.decoyEventDetail.innerHTML = `<p class="loading-cell">Loading ${escapeHtml(formatName(decoyKey))} evidence…</p>`;
  try {
    const [events, adaptiveStates] = await Promise.all([
      fetchJson(`/api/decoys/${encodeURIComponent(decoyKey)}/events?limit=100`),
      fetchJson(`/api/decoys/${encodeURIComponent(decoyKey)}/adaptive-content?limit=50`),
    ]);
    const sources = new Set(events.map((event) => event.source_ip).filter(Boolean));
    const attempts = events.filter((event) => ["login_attempt", "query_attempt", "table_access", "camera_access"].includes(event.event_type)).length;
    const rows = events.map((event) => `<tr><td>${escapeHtml(formatShortTimestamp(event.timestamp))}</td><td>${escapeHtml(event.source_ip || "Unknown")}</td><td>${escapeHtml(formatName(event.event_type))}</td><td><span class="context-text" title="${escapeHtml(safeDetails(event.details))}">${escapeHtml(safeDetails(event.details))}</span></td></tr>`).join("");
    const adaptiveCards = adaptiveStates.map((profile) => {
      const content = profile.content || {};
      const interests = Array.isArray(profile.interests) ? profile.interests : [];
      const assets = Array.isArray(content.visible_assets) ? content.visible_assets : [];
      return `<article class="adaptive-profile-card"><div class="adaptive-profile-heading"><div><small>Attacker source</small><strong>${escapeHtml(profile.source_ip || "Unknown")}</strong></div>${badge(profile.behavior_stage || "discovery", profile.behavior_stage === "exploitation" ? "danger" : "warning")}</div><div class="adaptive-profile-stats"><div><span>Interactions</span><strong>${formatNumber(profile.interaction_count || 0)}</strong></div><div><span>Last action</span><strong>${escapeHtml(formatName(profile.last_event_type || "unknown"))}</strong></div><div><span>Updated</span><strong>${escapeHtml(formatShortTimestamp(profile.updated_at))}</strong></div></div><p><b>Observed interests</b></p><div class="adaptive-chip-row">${interests.length ? interests.map((item) => `<span>${escapeHtml(formatName(item))}</span>`).join("") : "<em>None identified</em>"}</div><p><b>Synthetic content exposed</b></p><div class="adaptive-chip-row adaptive-assets">${assets.length ? assets.map((item) => `<span>${escapeHtml(item)}</span>`).join("") : "<em>Default decoy content</em>"}</div><p class="adaptive-last-command"><b>Latest captured input:</b> ${escapeHtml(profile.last_command || "No command text captured")}</p></article>`;
    }).join("");
    const adaptiveSection = `<section class="adaptive-content-section"><div class="adaptive-section-heading"><div><p class="eyebrow">Live adaptation</p><h3>Attacker-driven synthetic content</h3></div><span class="read-only-badge">Safe simulation</span></div>${adaptiveCards || `<p class="empty-state">No adaptive profile exists for this decoy yet. Interact with it from Kali, then refresh.</p>`}</section>`;
    elements.decoyEventDetail.innerHTML = `<div class="evidence-summary"><div><span>Decoy</span><strong>${escapeHtml(formatName(decoyKey))}</strong></div><div><span>Interactions</span><strong>${events.length}</strong></div><div><span>Sources</span><strong>${sources.size}</strong></div><div><span>High-value actions</span><strong>${attempts}</strong></div></div>${adaptiveSection}<div class="table-scroll"><table><thead><tr><th>Time</th><th>Source</th><th>Action</th><th>Captured evidence</th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="empty-state">No interactions recorded for this decoy.</td></tr>`}</tbody></table></div>`;
  } catch (error) {
    elements.decoyEventDetail.innerHTML = `<p class="empty-state">Unable to load decoy activity: ${escapeHtml(error.message)}</p>`;
  }
}


function drawChart(rows) {
  state.chartRows = rows;

  const canvas = elements.chart;
  const context = canvas.getContext("2d");
  const container = canvas.parentElement;

  if (!rows.length) {
    canvas.classList.add("hidden");
    elements.chartEmpty.classList.remove("hidden");
    return;
  }

  canvas.classList.remove("hidden");
  elements.chartEmpty.classList.add("hidden");

  const minuteMap = new Map();

  for (const row of rows) {
    if (!minuteMap.has(row.minute)) {
      minuteMap.set(
        row.minute,
        {
          ssh: 0,
          web: 0,
          database: 0,
          iot: 0,
        }
      );
    }

    const service = String(row.service || "").toLowerCase();

    if (service in minuteMap.get(row.minute)) {
      minuteMap.get(row.minute)[service] += (
        Number(row.event_count) || 0
      );
    }
  }

  const minutes = Array.from(minuteMap.keys()).slice(-30);
  const values = minutes.map((minute) => minuteMap.get(minute));

  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(320, container.clientWidth);
  const height = Math.max(220, container.clientHeight);

  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);

  const padding = {
    top: 15,
    right: 15,
    bottom: 38,
    left: 38,
  };

  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maximum = Math.max(
    1,
    ...values.flatMap((value) => Object.values(value))
  );

  context.strokeStyle = "rgba(97, 113, 138, 0.18)";
  context.fillStyle = "#718096";
  context.font = "11px system-ui";

  const gridLines = 4;

  for (let index = 0; index <= gridLines; index += 1) {
    const y = (
      padding.top
      + chartHeight
      - (chartHeight * index / gridLines)
    );

    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();

    const label = Math.round(
      maximum * index / gridLines
    );

    context.fillText(
      String(label),
      5,
      y + 4
    );
  }

  const services = [
    ["ssh", "#2677dc"],
    ["web", "#18a676"],
    ["database", "#e4962d"],
    ["iot", "#8d6bd3"],
  ];

  for (const [service, color] of services) {
    context.beginPath();
    context.strokeStyle = color;
    context.lineWidth = 2;
    context.lineJoin = "round";
    context.lineCap = "round";

    values.forEach((value, index) => {
      const x = (
        padding.left
        + (
          values.length === 1
            ? chartWidth / 2
            : chartWidth * index / (values.length - 1)
        )
      );

      const y = (
        padding.top
        + chartHeight
        - chartHeight * value[service] / maximum
      );

      if (index === 0) {
        context.moveTo(x, y);
      } else {
        context.lineTo(x, y);
      }
    });

    context.stroke();
  }

  if (minutes.length) {
    const first = minutes[0].slice(11);
    const last = minutes[minutes.length - 1].slice(11);

    context.fillStyle = "#718096";
    context.fillText(
      first,
      padding.left,
      height - 12
    );

    const lastWidth = context.measureText(last).width;

    context.fillText(
      last,
      width - padding.right - lastWidth,
      height - 12
    );
  }

  const total = rows.reduce(
    (sum, row) => sum + (Number(row.event_count) || 0),
    0
  );

  canvas.setAttribute(
    "aria-label",
    `Event activity chart containing ${total} events`
  );
}


async function refreshDashboard() {
  if (state.refreshing) {
    return;
  }

  state.refreshing = true;
  elements.refreshButton.disabled = true;
  elements.refreshButton.textContent = "Refreshing…";
  setConnectionState("pending", "Refreshing");

  try {
    const eventLimit = Number(
      elements.eventLimit.value
    ) || 50;

    const [
      summary,
      alerts,
      attackers,
      decoys,
      predictions,
      decisions,
      events,
      lifecycle,
      eventSeries,
    ] = await Promise.all([
      fetchJson("/api/summary"),
      fetchJson("/api/alerts?limit=50"),
      fetchJson("/api/attackers?limit=50"),
      fetchJson("/api/decoys"),
      fetchJson("/api/predictions?limit=20"),
      fetchJson("/api/decisions?limit=50"),
      fetchJson(`/api/events?limit=${eventLimit}`),
      fetchJson("/api/lifecycle?limit=50"),
      fetchJson("/api/event-series"),
    ]);

    renderSummary(summary);
    renderAlerts(alerts);
    renderAttackers(attackers);
    renderDecoys(decoys);
    renderLatestPrediction(predictions);
    renderDecisions(decisions);
    renderEvents(events);
    renderLifecycle(lifecycle);
    drawChart(eventSeries);

    elements.lastUpdated.textContent = (
      new Intl.DateTimeFormat(
        undefined,
        {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }
      ).format(new Date())
    );

    elements.errorBanner.classList.add("hidden");
    setConnectionState("online", "Live");
  } catch (error) {
    console.error(error);

    elements.errorMessage.textContent = error.message;
    elements.errorBanner.classList.remove("hidden");
    setConnectionState("offline", "Disconnected");
  } finally {
    state.refreshing = false;
    elements.refreshButton.disabled = false;
    elements.refreshButton.textContent = "Refresh now";
  }
}


function scheduleRefresh() {
  if (state.refreshTimer) {
    window.clearInterval(state.refreshTimer);
  }

  state.refreshTimer = window.setInterval(
    refreshDashboard,
    REFRESH_INTERVAL_MS
  );
}


const viewDetails = {
  overview: ["Overview", "Live security overview"],
  alerts: ["Alerts", "Security attention"],
  activity: ["Activity", "Captured telemetry"],
  attackers: ["Attackers", "Risk intelligence"],
  decisions: ["AI decisions", "Adaptive response"],
  decoys: ["Decoys", "Deception lifecycle"],
};


function openView(requestedView, updateHash = true) {
  const view = viewDetails[requestedView] ? requestedView : "overview";
  document.querySelectorAll(".app-view").forEach((section) => {
    section.classList.toggle("active", section.dataset.view === view);
  });
  document.querySelectorAll("[data-view-link]").forEach((link) => {
    link.classList.toggle("active", link.dataset.viewLink === view);
  });
  document.querySelector("#page-title").textContent = viewDetails[view][0];
  document.querySelector("#page-kicker").textContent = viewDetails[view][1];
  document.querySelector("#sidebar").classList.remove("open");
  document.querySelector("#sidebar-backdrop").classList.add("hidden");
  document.querySelector("#menu-button").setAttribute("aria-expanded", "false");
  if (updateHash && window.location.hash !== `#${view}`) {
    window.location.hash = view;
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (view === "activity") {
    window.setTimeout(() => drawChart(state.chartRows), 80);
  }
}


let resizeTimer = null;

window.addEventListener(
  "resize",
  () => {
    window.clearTimeout(resizeTimer);

    resizeTimer = window.setTimeout(
      () => drawChart(state.chartRows),
      120
    );
  }
);


elements.refreshButton.addEventListener(
  "click",
  refreshDashboard
);


elements.eventLimit.addEventListener(
  "change",
  refreshDashboard
);


document.addEventListener("click", async (event) => {
  const trigger = event.target.closest("[data-open-view], [data-view-link]");
  if (trigger) {
    event.preventDefault();
    openView(trigger.dataset.openView || trigger.dataset.viewLink);
    return;
  }

  const alertAction = event.target.closest("[data-alert-action]");
  if (alertAction) {
    alertAction.disabled = true;
    try {
      await postJson(`/api/alerts/${alertAction.dataset.alertId}/status`, {status: alertAction.dataset.alertAction});
      showToast(`Alert marked ${alertAction.dataset.alertAction}.`);
      await refreshDashboard();
    } catch (error) {
      showToast(`Alert update failed: ${error.message}`, true);
      alertAction.disabled = false;
    }
    return;
  }

  const alertDetails = event.target.closest("[data-alert-details]");
  if (alertDetails) {
    const panel = document.querySelector(`[data-alert-panel="${alertDetails.dataset.alertDetails}"]`);
    const opening = panel.classList.contains("hidden");
    document.querySelectorAll("[data-alert-panel]").forEach((item) => item.classList.add("hidden"));
    panel.classList.toggle("hidden", !opening);
    alertDetails.textContent = opening ? "Hide" : "Details";
    return;
  }

  const attackerRow = event.target.closest("[data-attacker-id]");
  if (attackerRow) {
    showAttackerDetail(attackerRow.dataset.attackerId);
    return;
  }

  const decoyEvents = event.target.closest("[data-decoy-events]");
  if (decoyEvents) {
    showDecoyEvents(decoyEvents.dataset.decoyEvents);
    return;
  }

  const decoyAction = event.target.closest("[data-decoy-action]");
  if (decoyAction) {
    state.selectedDecoy = decoyAction.dataset.decoyKey;
    state.selectedDecoyAction = decoyAction.dataset.decoyAction;
    elements.deactivateReason.value = "";
    const activating = state.selectedDecoyAction === "activate";
    elements.decoyActionTitle.textContent = activating ? "Activate decoy?" : "Deactivate decoy?";
    elements.decoyActionDescription.textContent = activating
      ? "This starts the decoy through the guarded orchestrator and records the action in lifecycle history."
      : "This stops the decoy container, preserves its logs and records the action in lifecycle history.";
    elements.decoyReasonLabel.classList.toggle("hidden", activating);
    elements.confirmDecoyAction.textContent = activating ? "Activate decoy" : "Deactivate decoy";
    elements.confirmDecoyAction.classList.toggle("button-danger", !activating);
    elements.confirmDecoyAction.classList.toggle("button-activate", activating);
    elements.confirmDialog.showModal();
  }
});


document.addEventListener("keydown", (event) => {
  const row = event.target.closest("[data-attacker-id]");
  if (row && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    showAttackerDetail(row.dataset.attackerId);
  }
});


elements.alertSearch.addEventListener("input", () => {
  state.alertPage = 1;
  renderAlertPage();
});
elements.alertSeverity.addEventListener("change", () => {
  state.alertPage = 1;
  renderAlertPage();
});
elements.alertStatus.addEventListener("change", () => {
  state.alertPage = 1;
  renderAlertPage();
});
elements.alertPrev.addEventListener("click", () => {
  state.alertPage = Math.max(1, state.alertPage - 1);
  renderAlertPage();
});
elements.alertNext.addEventListener("click", () => {
  state.alertPage += 1;
  renderAlertPage();
});


document.querySelector("#menu-button").addEventListener("click", () => {
  const sidebar = document.querySelector("#sidebar");
  const isOpen = sidebar.classList.toggle("open");
  document.querySelector("#sidebar-backdrop").classList.toggle("hidden", !isOpen);
  document.querySelector("#menu-button").setAttribute("aria-expanded", String(isOpen));
});
document.querySelector("#sidebar-backdrop").addEventListener("click", () => openView((window.location.hash || "#overview").slice(1), false));
window.addEventListener("hashchange", () => openView(window.location.hash.slice(1), false));
document.querySelector("#attacker-dialog-close").addEventListener("click", () => elements.attackerDialog.close());
elements.confirmDecoyAction.addEventListener("click", async (event) => {
  event.preventDefault();
  if (!state.selectedDecoy || !state.selectedDecoyAction) return;
  const button = event.currentTarget;
  const action = state.selectedDecoyAction;
  button.disabled = true;
  button.textContent = action === "activate" ? "Activating…" : "Deactivating…";
  try {
    await postJson(`/api/decoys/${encodeURIComponent(state.selectedDecoy)}/${action}`, {
      confirm: state.selectedDecoy,
      reason: elements.deactivateReason.value.trim() || "Manual dashboard deactivation",
    });
    elements.confirmDialog.close();
    showToast(action === "activate"
      ? `${formatName(state.selectedDecoy)} was activated successfully.`
      : `${formatName(state.selectedDecoy)} was deactivated. Logs were preserved.`);
    state.selectedDecoy = null;
    state.selectedDecoyAction = null;
    await refreshDashboard();
  } catch (error) {
    showToast(`${formatName(action)} failed: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = action === "activate" ? "Activate decoy" : "Deactivate decoy";
  }
});


document.addEventListener(
  "visibilitychange",
  () => {
    if (!document.hidden) {
      refreshDashboard();
    }
  }
);


openView(window.location.hash.slice(1), false);
refreshDashboard();
scheduleRefresh();
