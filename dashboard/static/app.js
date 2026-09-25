"use strict";

const REFRESH_INTERVAL_MS = 5000;

const state = {
  refreshing: false,
  chartRows: [],
  refreshTimer: null,
};

const elements = {
  connectionStatus: document.querySelector("#connection-status"),
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
  latestPrediction: document.querySelector(
    "#latest-prediction"
  ),
  decisionsBody: document.querySelector(
    "#decisions-table-body"
  ),
  eventsBody: document.querySelector("#events-table-body"),
  lifecycleList: document.querySelector("#lifecycle-list"),
  alertList: document.querySelector("#alert-list"),
  eventLimit: document.querySelector("#event-limit"),

  chart: document.querySelector("#event-chart"),
  chartEmpty: document.querySelector("#chart-empty"),
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
  elements.approvalBanner.classList.toggle(
    "hidden",
    approvalCount === 0
  );
}

function renderAlerts(alerts) {
  const openAlerts = alerts.filter(
    (alert) => String(alert.status).toLowerCase() === "open"
  );

  if (!openAlerts.length) {
    elements.alertList.innerHTML = `
      <div class="alert-empty">
        <span class="alert-empty-icon" aria-hidden="true">✓</span>
        <div>
          <strong>No open security alerts</strong>
          <p>The system has no unresolved alerts requiring review.</p>
        </div>
      </div>
    `;
    return;
  }

  elements.alertList.innerHTML = openAlerts
    .map((alert) => {
      const severity = String(
        alert.severity || "medium"
      ).toLowerCase();

      return `
        <article class="alert-item alert-item-${escapeHtml(severity)}">
          <div class="alert-indicator" aria-hidden="true"></div>

          <div class="alert-content">
            <div class="alert-heading">
              <div>
                <p class="alert-title">
                  ${escapeHtml(alert.title || "Security alert")}
                </p>
                <p class="alert-type">
                  ${escapeHtml(formatName(alert.alert_type))}
                </p>
              </div>

              ${badge(alert.severity, severity)}
            </div>

            <p class="alert-message">
              ${escapeHtml(alert.message || "No additional details")}
            </p>

            <div class="alert-meta">
              <span>
                Source:
                <strong>${escapeHtml(alert.source_ip || "Unknown")}</strong>
              </span>

              <span>
                Decision:
                <strong>#${formatNumber(alert.related_decision_id)}</strong>
              </span>

              <span>
                Prediction:
                <strong>#${formatNumber(alert.related_prediction_id)}</strong>
              </span>

              <time datetime="${escapeHtml(alert.created_at)}">
                ${escapeHtml(formatTimestamp(alert.created_at))}
              </time>
            </div>
          </div>
        </article>
      `;
    })
    .join("");
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
        <tr>
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

        ${badge(decoy.status, statusStyle(decoy.status))}
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

  context.strokeStyle = "rgba(114, 136, 164, 0.20)";
  context.fillStyle = "#7288a4";
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
    ["ssh", "#53a7ff"],
    ["web", "#35d49a"],
    ["database", "#ffbe55"],
    ["iot", "#ad8cff"],
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

    context.fillStyle = "#7288a4";
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


document.addEventListener(
  "visibilitychange",
  () => {
    if (!document.hidden) {
      refreshDashboard();
    }
  }
);


refreshDashboard();
scheduleRefresh();
