/**
 * JuiceSec Analyzer - Client Engine 2.0
 * Pure Vanilla ES6+ • WCAG 2.2 AA • WAI-ARIA • CSP Compliant (Zero Inline)
 */

'use strict';

const $ = (id) => document.getElementById(id);

// ============================================================================
// 1. STATE MANAGEMENT
// ============================================================================
let csrfToken = '';
let knowledgeCache = [];

const THEME_KEY = 'juicesec_theme';
const THEMES = ['auto', 'dark', 'light'];
const THEME_CONFIG = {
  auto: { label: 'Tự động', icon: '🌓' },
  dark: { label: 'Tối', icon: '🌙' },
  light: { label: 'Sáng', icon: '☀️' }
};

let currentTheme = 'auto';

// ============================================================================
// 2. SAFE DOM UTILITIES
// ============================================================================
function createElement(tag, attributes = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (value === null || value === undefined) continue;
    if (key === 'className' || key === 'class') {
      el.className = value;
    } else if (key === 'textContent') {
      el.textContent = value;
    } else if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (typeof value === 'boolean') {
      if (value) el.setAttribute(key, '');
    } else {
      el.setAttribute(key, String(value));
    }
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    if (typeof child === 'string' || typeof child === 'number') {
      el.appendChild(document.createTextNode(String(child)));
    } else if (child instanceof Node) {
      el.appendChild(child);
    }
  }
  return el;
}

function copyToClipboard(text, triggerButton) {
  const originalText = triggerButton.textContent;
  const onSuccess = () => {
    triggerButton.textContent = '✓ Đã chép!';
    triggerButton.disabled = true;
    setTimeout(() => {
      triggerButton.textContent = originalText;
      triggerButton.disabled = false;
    }, 2000);
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(() => {
      fallbackCopy(text, onSuccess);
    });
  } else {
    fallbackCopy(text, onSuccess);
  }
}

function fallbackCopy(text, callback) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand('copy');
    callback();
  } catch (err) {
    console.error('Không thể sao chép văn bản:', err);
  } finally {
    document.body.removeChild(textarea);
  }
}

// ============================================================================
// 3. THEME CONTROLLER
// ============================================================================
const ThemeController = {
  mediaQuery: window.matchMedia('(prefers-color-scheme: dark)'),

  init() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved && THEMES.includes(saved)) {
      currentTheme = saved;
    } else {
      currentTheme = 'auto';
    }

    this.applyTheme(currentTheme);
    this.updateUI();

    this.mediaQuery.addEventListener('change', () => {
      if (currentTheme === 'auto') {
        this.applyTheme('auto');
      }
    });

    const toggleBtn = $('themeToggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => this.cycleTheme());
    }
  },

  applyTheme(theme) {
    if (theme === 'auto') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', theme);
    }
    localStorage.setItem(THEME_KEY, theme);
  },

  cycleTheme() {
    const idx = THEMES.indexOf(currentTheme);
    currentTheme = THEMES[(idx + 1) % THEMES.length];
    this.applyTheme(currentTheme);
    this.updateUI();
  },

  updateUI() {
    const conf = THEME_CONFIG[currentTheme];
    const iconEl = $('themeIcon');
    const textEl = $('themeText');
    if (iconEl) iconEl.textContent = conf.icon;
    if (textEl) textEl.textContent = conf.label;
    const btn = $('themeToggle');
    if (btn) {
      btn.setAttribute('aria-label', `Chế độ giao diện: ${conf.label}. Nhấp để đổi.`);
    }
  }
};

// ============================================================================
// 4. WAI-ARIA TAB CONTROLLER
// ============================================================================
const TabController = {
  init() {
    const tablist = document.querySelector('[role="tablist"]');
    if (!tablist) return;

    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));

    tabs.forEach((tab) => {
      tab.addEventListener('click', (e) => {
        e.preventDefault();
        this.activateTab(tab, tabs);
      });

      tab.addEventListener('keydown', (e) => {
        this.handleKeydown(e, tab, tabs);
      });
    });
  },

  handleKeydown(e, currentTab, tabs) {
    const index = tabs.indexOf(currentTab);
    let targetTab = null;

    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault();
      targetTab = tabs[(index + 1) % tabs.length];
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault();
      targetTab = tabs[(index - 1 + tabs.length) % tabs.length];
    } else if (e.key === 'Home') {
      e.preventDefault();
      targetTab = tabs[0];
    } else if (e.key === 'End') {
      e.preventDefault();
      targetTab = tabs[tabs.length - 1];
    }

    if (targetTab) {
      targetTab.focus();
      this.activateTab(targetTab, tabs);
    }
  },

  activateTab(activeTab, tabs) {
    tabs.forEach((tab) => {
      const isSelected = (tab === activeTab);
      tab.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      tab.setAttribute('tabindex', isSelected ? '0' : '-1');

      const panelId = tab.dataset.tab || tab.getAttribute('aria-controls');
      if (panelId) {
        const panel = $(panelId);
        if (panel) {
          if (isSelected) {
            panel.removeAttribute('hidden');
            panel.setAttribute('tabindex', '0');
          } else {
            panel.setAttribute('hidden', '');
            panel.removeAttribute('tabindex');
          }
        }
      }
    });
  }
};

// ============================================================================
// 5. NATIVE MODAL MANAGER (<dialog id="detailModal">)
// ============================================================================
const ModalManager = {
  dialog: null,
  bodyEl: null,
  titleEl: null,

  init() {
    this.dialog = $('detailModal');
    if (!this.dialog) return;

    this.bodyEl = $('modalBody');
    this.titleEl = $('modalTitle');

    const closeBtn = $('modalCloseBtn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.close());
    }

    // Đóng khi click ngoài backdrop
    this.dialog.addEventListener('click', (e) => {
      const rect = this.dialog.getBoundingClientRect();
      const isInDialog = (
        rect.top <= e.clientY &&
        e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX &&
        e.clientX <= rect.left + rect.width
      );
      if (!isInDialog) {
        this.close();
      }
    });
  },

  show(data, title = 'Chi tiết chỉ dấu') {
    if (!this.dialog) return;
    if (this.titleEl) this.titleEl.textContent = title;

    if (this.bodyEl) {
      this.bodyEl.replaceChildren();
      const codeBlock = createElement('pre', { class: 'modal-code-block' },
        createElement('code', {
          textContent: typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data)
        })
      );
      this.bodyEl.appendChild(codeBlock);
    }

    if (typeof this.dialog.showModal === 'function') {
      this.dialog.showModal();
    } else {
      this.dialog.setAttribute('open', '');
    }
  },

  close() {
    if (!this.dialog) return;
    if (typeof this.dialog.close === 'function') {
      this.dialog.close();
    } else {
      this.dialog.removeAttribute('open');
    }
  }
};

// ============================================================================
// 6. REPORT RENDERER
// ============================================================================
function getSeverityBadgeClass(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH') return 'badge-danger';
  if (s === 'MEDIUM') return 'badge-warning';
  return 'badge-info';
}

function updateCircularGauge(fillElement, scoreTextElement, badgeElement, confidence, riskLevel) {
  const conf = Math.max(0, Math.min(1, Number(confidence) || 0));
  const percent = Math.round(conf * 100);
  const circumference = 251.2;
  const offset = circumference * (1 - conf);

  if (fillElement) {
    fillElement.setAttribute('stroke-dashoffset', offset.toFixed(1));
    let riskClass = 'risk-clean';
    if (percent >= 85) riskClass = 'risk-critical';
    else if (percent >= 70) riskClass = 'risk-high';
    else if (percent >= 50) riskClass = 'risk-medium';
    else if (percent >= 20) riskClass = 'risk-low';

    fillElement.setAttribute('class', `gauge-fill ${riskClass}`);
  }

  if (scoreTextElement) {
    scoreTextElement.textContent = `${percent}%`;
  }

  if (badgeElement) {
    let badgeClass = 'badge-sanitizer';
    let text = riskLevel || 'AN TOÀN';
    if (riskLevel === 'CRITICAL') { badgeClass = 'badge-danger'; text = 'RẤT NGUY HIỂM (CRITICAL)'; }
    else if (riskLevel === 'HIGH') { badgeClass = 'badge-danger'; text = 'NGUY HIỂM CAO (HIGH)'; }
    else if (riskLevel === 'MEDIUM') { badgeClass = 'badge-warning'; text = 'CẢNH BÁO (MEDIUM)'; }
    else if (riskLevel === 'LOW') { badgeClass = 'badge-info'; text = 'RỦI RO THẤP (LOW)'; }
    else { badgeClass = 'badge-sanitizer'; text = 'AN TOÀN (CLEAN)'; }

    badgeElement.setAttribute('class', `badge ${badgeClass}`);
    badgeElement.textContent = text;
  }
}

let aiGaugeAnimationId = null;

function setAiRiskGaugeLoading(isHybrid) {
  const container = $('aiRiskGaugeContainer');
  const svg = $('aiRiskGaugeSvg');
  const progress = $('aiRiskGaugeProgress');
  const valEl = $('aiRiskGaugeValue');
  const spinnerText = $('aiRiskGaugeSpinnerText');
  const badge = $('aiRiskLevelBadge');
  const ratio = $('aiRiskFindingsRatio');
  const desc = $('aiRiskDescription');
  const statusEl = $('status');

  if (!isHybrid) {
    if (container) container.hidden = true;
    return;
  }

  if (statusEl) statusEl.hidden = true;
  if (container) {
    container.hidden = false;
    container.classList.remove('risk-low', 'risk-medium', 'risk-high');
  }
  if (svg) {
    svg.classList.add('loading');
    svg.removeAttribute('aria-label');
  }
  if (progress) {
    progress.style.strokeDashoffset = '326.7';
    progress.style.stroke = 'var(--color-primary)';
  }
  if (valEl) valEl.hidden = true;
  if (spinnerText) {
    spinnerText.hidden = false;
    spinnerText.textContent = 'AI đang phân tích...';
  }
  if (badge) {
    badge.textContent = 'Đang phân tích...';
    badge.className = 'risk-badge';
  }
  if (ratio) ratio.textContent = '-- / --';
  if (desc) desc.textContent = 'Mô hình Bayesian đang phân tích các mẫu mã nguồn và lưu lượng HTTP...';
}

function clearAiRiskGaugeLoading() {
  const svg = $('aiRiskGaugeSvg');
  const spinnerText = $('aiRiskGaugeSpinnerText');
  const valEl = $('aiRiskGaugeValue');
  if (svg) svg.classList.remove('loading');
  if (spinnerText) spinnerText.hidden = true;
  if (valEl) valEl.hidden = false;
}

function renderAiRiskGauge(gaugeData) {
  const container = $('aiRiskGaugeContainer');
  if (!container) return;

  if (aiGaugeAnimationId) {
    cancelAnimationFrame(aiGaugeAnimationId);
    aiGaugeAnimationId = null;
  }

  if (!gaugeData) {
    container.hidden = true;
    return;
  }

  clearAiRiskGaugeLoading();
  container.hidden = false;

  const risk = Math.max(0, Math.min(100, Math.round(Number(gaugeData.risk_percent) || 0)));
  const findings = gaugeData.findings ?? 0;
  const total = gaugeData.total ?? 0;

  // Thresholds: <40% (#0f8b7d, Thấp), 40-69% (#f29900, Trung bình), >=70% (#d93025, Cao)
  let level = 'low';
  let label = 'Thấp';
  let color = '#0f8b7d';
  let descText = 'Mức độ rủi ro thấp. Không phát hiện chỉ dấu bất thường hoặc nguy cơ bảo mật cao.';

  if (risk >= 70) {
    level = 'high';
    label = 'Cao';
    color = '#d93025';
    descText = 'Mức độ rủi ro cao! Phát hiện các điểm yếu hoặc mẫu mã nguồn tiềm ẩn nguy cơ bảo mật nghiêm trọng.';
  } else if (risk >= 40) {
    level = 'medium';
    label = 'Trung bình';
    color = '#f29900';
    descText = 'Mức độ rủi ro trung bình. Cần rà soát và đánh giá lại các cảnh báo đã phát hiện.';
  }

  container.classList.remove('risk-low', 'risk-medium', 'risk-high');
  container.classList.add(`risk-${level}`);

  const badge = $('aiRiskLevelBadge');
  if (badge) {
    badge.textContent = label;
    badge.className = `risk-badge badge-${level}`;
  }

  const ratio = $('aiRiskFindingsRatio');
  if (ratio) {
    ratio.textContent = `${findings} / ${total}`;
  }

  const desc = $('aiRiskDescription');
  if (desc) {
    desc.textContent = descText;
  }

  const svg = $('aiRiskGaugeSvg');
  if (svg) {
    svg.setAttribute('aria-label', `Độ rủi ro AI: ${risk}%, Mức độ: ${label}, Điểm nghi ngờ: ${findings}/${total}`);
  }

  const valEl = $('aiRiskGaugeValue');
  const progress = $('aiRiskGaugeProgress');
  const CIRCUMFERENCE = 326.7;
  const targetOffset = CIRCUMFERENCE * (1 - risk / 100);

  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (progress) {
    progress.style.stroke = color;
    if (prefersReduced) {
      progress.style.transition = 'none';
      progress.style.strokeDashoffset = targetOffset.toFixed(1);
    } else {
      progress.style.transition = 'stroke-dashoffset 1.6s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.4s ease';
      progress.style.strokeDashoffset = '326.7';
      requestAnimationFrame(() => {
        progress.style.strokeDashoffset = targetOffset.toFixed(1);
      });
    }
  }

  if (valEl) {
    valEl.hidden = false;
    if (prefersReduced) {
      valEl.textContent = `${risk}%`;
    } else {
      valEl.textContent = '0%';
      const startTime = performance.now();
      const duration = 1600;

      function updateCounter(now) {
        const elapsed = now - startTime;
        const progressFrac = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progressFrac, 3);
        const currentVal = Math.round(risk * ease);
        valEl.textContent = `${currentVal}%`;

        if (progressFrac < 1) {
          aiGaugeAnimationId = requestAnimationFrame(updateCounter);
        } else {
          valEl.textContent = `${risk}%`;
          aiGaugeAnimationId = null;
        }
      }
      aiGaugeAnimationId = requestAnimationFrame(updateCounter);
    }
  }
}

function renderReport(report) {
  const resultsContainer = $('results');
  const summaryContainer = $('summary');
  const telemetryContainer = $('aiTelemetryContainer');
  const statusEl = $('status');
  if (!resultsContainer) return;

  // Render AI Risk Gauge if present
  if (report.ai_gauge) {
    if (statusEl) statusEl.hidden = true;
    renderAiRiskGauge(report.ai_gauge);
  } else {
    renderAiRiskGauge(null);
    if (statusEl) {
      statusEl.hidden = false;
      statusEl.textContent = 'Đã hoàn tất phân tích. Xem chỉ dấu và chi tiết bên dưới:';
    }
  }

  resultsContainer.replaceChildren();

  // Render AI Telemetry Banner if available in report
  if (telemetryContainer) {
    telemetryContainer.replaceChildren();
    if (report.ai_telemetry) {
      const tel = report.ai_telemetry;
      const conf = tel.confidence || 0;
      const risk = tel.risk_level || 'CLEAN';

      const banner = createElement('div', { class: 'ai-telemetry-banner' });
      const head = createElement('div', { class: 'ai-telemetry-header' },
        createElement('div', { class: 'ai-telemetry-title' },
          createElement('span', { textContent: '🧠 Phân tích AI Giải thích được (Explainable AI Telemetry)' })
        ),
        createElement('span', { class: 'badge badge-indicator', textContent: `Mô hình: ${tel.model_name || 'Calibrated Ensemble'}` })
      );

      const gaugeContainer = createElement('div', { class: 'ai-gauge-container' });
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('class', 'ai-gauge-svg');
      svg.setAttribute('viewBox', '0 0 100 100');
      svg.setAttribute('aria-hidden', 'true');

      const circleTrack = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circleTrack.setAttribute('class', 'gauge-track');
      circleTrack.setAttribute('cx', '50');
      circleTrack.setAttribute('cy', '50');
      circleTrack.setAttribute('r', '40');

      const circleFill = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circleFill.setAttribute('class', 'gauge-fill risk-clean');
      circleFill.setAttribute('cx', '50');
      circleFill.setAttribute('cy', '50');
      circleFill.setAttribute('r', '40');
      circleFill.setAttribute('stroke-dasharray', '251.2');
      circleFill.setAttribute('stroke-dashoffset', '251.2');

      svg.appendChild(circleTrack);
      svg.appendChild(circleFill);

      const textContainer = createElement('div', { class: 'gauge-text-container' });
      const scoreText = createElement('div', { class: 'gauge-score', textContent: `${Math.round(conf * 100)}%` });
      const label = createElement('div', { class: 'gauge-label', textContent: 'Chỉ số Nguy cơ Mã nguồn AI' });
      const badge = createElement('span', { class: 'badge badge-sanitizer', textContent: risk });

      updateCircularGauge(circleFill, scoreText, badge, conf, risk);

      textContainer.appendChild(scoreText);
      textContainer.appendChild(label);
      textContainer.appendChild(badge);

      gaugeContainer.appendChild(svg);
      gaugeContainer.appendChild(textContainer);

      // Active AST Features
      const activeFeats = tel.active_features || [];
      const featsWrapper = createElement('div', { class: 'mt-md' },
        createElement('div', { class: 'text-xs text-muted font-bold mb-xs', textContent: `Đặc trưng AST Kích hoạt (${activeFeats.length}):` })
      );

      const activeList = createElement('div', { class: 'flex flex-wrap gap-xs' });
      if (activeFeats.length === 0) {
        activeList.appendChild(createElement('span', { class: 'text-xs', textContent: 'Không có đặc trưng rủi ro nào kích hoạt.' }));
      } else {
        for (const feat of activeFeats) {
          activeList.appendChild(createElement('span', {
            class: `badge badge-${feat.category || 'flow'}`,
            textContent: `${feat.name} (${feat.category})`
          }));
        }
      }
      featsWrapper.appendChild(activeList);

      banner.appendChild(head);
      banner.appendChild(gaugeContainer);
      banner.appendChild(featsWrapper);
      telemetryContainer.appendChild(banner);
    }
  }

  const findings = report.findings || [];
  if (summaryContainer) {
    summaryContainer.textContent = `${findings.length} chỉ dấu cần thẩm định`;
  }

  for (let i = 0; i < findings.length; i++) {
    const item = findings[i];
    const severityClass = getSeverityBadgeClass(item.severity);

    const card = createElement('article', { class: 'finding-card', tabindex: '0' });

    // Card Header
    const headerGroup = createElement('div', { class: 'finding-header' },
      createElement('div', { class: 'finding-title-group' },
        createElement('span', { class: 'finding-index', textContent: `#${i + 1}` }),
        createElement('h3', { class: 'finding-title', textContent: item.title || 'Chỉ dấu không tên' })
      ),
      createElement('div', { class: 'finding-badges' },
        createElement('span', { class: `badge ${severityClass}`, textContent: item.severity || 'INFO' }),
        createElement('span', { class: 'badge badge-confidence', textContent: `Tin cậy: ${item.confidence || 'MEDIUM'}` }),
        item.ai_rescored ? createElement('span', { class: 'badge badge-sanitizer', textContent: `AI Fused: ${(item.ai_confidence * 100).toFixed(0)}%` }) : null,
        item.potential_false_positive ? createElement('span', { class: 'badge badge-warning', textContent: 'Audit: Low AI' }) : null,
        item.rule_id ? createElement('span', { class: 'badge badge-neutral', textContent: item.rule_id }) : null
      )
    );
    card.appendChild(headerGroup);

    // Evidence
    const evidenceVal = item.evidence;
    if (evidenceVal !== undefined && evidenceVal !== null) {
      const evidenceStr = typeof evidenceVal === 'object' ? JSON.stringify(evidenceVal, null, 2) : String(evidenceVal);
      const copyBtn = createElement('button', {
        type: 'button',
        class: 'btn btn-sm btn-secondary',
        textContent: 'Sao chép bằng chứng',
        onClick: (e) => copyToClipboard(evidenceStr, e.currentTarget)
      });

      const evidenceBlock = createElement('div', { class: 'evidence-wrapper' },
        createElement('div', { class: 'evidence-header' },
          createElement('span', { textContent: 'Bằng chứng phát hiện:' }),
          copyBtn
        ),
        createElement('pre', { class: 'code-preview' },
          createElement('code', { textContent: evidenceStr })
        )
      );
      card.appendChild(evidenceBlock);
    }

    // Remediation
    if (item.remediation) {
      const remBox = createElement('div', { class: 'remediation-box' },
        createElement('div', { class: 'remediation-header' },
          createElement('span', { textContent: '💡 Biện pháp khắc phục:' })
        ),
        createElement('p', { class: 'remediation-content', textContent: item.remediation })
      );
      card.appendChild(remBox);
    }

    // Actions
    const actionGroup = createElement('div', { class: 'finding-actions' },
      createElement('button', {
        type: 'button',
        class: 'btn btn-outline btn-sm',
        onClick: () => ModalManager.show(item, `Chỉ dấu: ${item.title || item.rule_id}`)
      }, '🔍 Xem JSON chi tiết')
    );
    card.appendChild(actionGroup);

    resultsContainer.appendChild(card);
  }

  if (!findings.length) {
    const emptyAlert = createElement('div', { class: 'alert alert-info', role: 'status' },
      createElement('p', {
        textContent: 'Không có chỉ dấu theo bộ quy tắc hiện tại. Kết quả này không chứng minh ứng dụng an toàn tuyệt đối.'
      })
    );
    resultsContainer.appendChild(emptyAlert);
  }

  // Scan or Connection Errors
  for (const err of report.errors || []) {
    const errAlert = createElement('div', { class: 'alert alert-danger', role: 'alert' },
      createElement('strong', { textContent: `${err.path}: ` }),
      createElement('span', { textContent: err.type || 'Lỗi không xác định' })
    );
    resultsContainer.appendChild(errAlert);
  }
}

// ============================================================================
// 7. API SUBMIT CONTROLLER
// ============================================================================
async function submit(path, body, button) {
  button.disabled = true;
  const originalText = button.textContent;
  button.textContent = 'Đang phân tích…';
  const statusEl = $('status');
  const isScan = (path === '/api/scan');
  const isHybrid = isScan && Boolean(body.ai_hybrid);

  if (isHybrid) {
    setAiRiskGaugeLoading(true);
  } else {
    setAiRiskGaugeLoading(false);
    if (statusEl) {
      statusEl.hidden = false;
      statusEl.textContent = 'Đang phân tích…';
    }
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 35000);

  try {
    const response = await fetch(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || `Lỗi máy chủ (${response.status})`);
    }

    clearAiRiskGaugeLoading();
    renderReport(result);
  } catch (e) {
    clearTimeout(timeoutId);
    clearAiRiskGaugeLoading();
    const gaugeContainer = $('aiRiskGaugeContainer');
    if (gaugeContainer) gaugeContainer.hidden = true;
    if (statusEl) {
      statusEl.hidden = false;
      if (e.name === 'AbortError') {
        statusEl.textContent = 'Lỗi kết nối hoặc yêu cầu quá thời gian. Vui lòng kiểm tra lại địa chỉ mục tiêu.';
      } else {
        statusEl.textContent = `Lỗi kết nối: ${e.message}. Vui lòng kiểm tra lại địa chỉ mục tiêu.`;
      }
    }
  } finally {
    clearTimeout(timeoutId);
    button.disabled = false;
    button.textContent = originalText;
  }
}

// ============================================================================
// 8. KNOWLEDGE BASE RENDERER
// ============================================================================
function renderKnowledge() {
  const searchInput = $('search');
  const knowledgeList = $('knowledgeList');
  if (!knowledgeList) return;

  const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
  knowledgeList.replaceChildren();

  const filtered = knowledgeCache.filter((x) =>
    JSON.stringify(x).toLowerCase().includes(q)
  );

  if (filtered.length === 0) {
    knowledgeList.appendChild(
      createElement('div', { class: 'alert alert-info', textContent: 'Không tìm thấy tri thức phù hợp với từ khóa.' })
    );
    return;
  }

  for (const k of filtered) {
    const card = createElement('article', { class: 'knowledge-card' },
      createElement('div', { class: 'knowledge-card-header' },
        createElement('h3', { class: 'knowledge-title', textContent: k.name || 'Lỗ hổng' }),
        k.cwe ? createElement('span', { class: 'badge badge-cwe', textContent: k.cwe }) : null
      ),
      createElement('p', { class: 'knowledge-desc', textContent: k.mechanism || '' }),
      createElement('div', { class: 'remediation-box' },
        createElement('div', { class: 'remediation-header' },
          createElement('span', { textContent: '🛡️ Phòng ngừa:' })
        ),
        createElement('p', { class: 'remediation-content', textContent: k.defense || '' })
      )
    );

    const footerLinks = [];
    if (k.url) {
      footerLinks.push(
        createElement('a', {
          href: k.url,
          target: '_blank',
          rel: 'noopener noreferrer',
          class: 'btn-link',
          textContent: '📖 Tài liệu PortSwigger Web Security Academy ↗'
        })
      );
    }
    if (k.cwe && k.cwe.toUpperCase().startsWith('CWE-')) {
      const cweNum = k.cwe.replace(/[^0-9]/g, '');
      if (cweNum) {
        footerLinks.push(
          createElement('a', {
            href: `https://cwe.mitre.org/data/definitions/${cweNum}.html`,
            target: '_blank',
            rel: 'noopener noreferrer',
            class: 'btn-link',
            textContent: `Tra cứu ${k.cwe} ↗`
          })
        );
      }
    }

    if (footerLinks.length > 0) {
      card.appendChild(createElement('div', { class: 'knowledge-card-footer' }, ...footerLinks));
    }

    knowledgeList.appendChild(card);
  }
}

// ============================================================================
// 8b. AI MODEL HUB & XAI CONTROLLER
// ============================================================================
let aiDataCache = null;

const SANDBOX_SNIPPETS = {
  sql_vuln: `// Lỗ hổng SQL Injection trực tiếp qua nối chuỗi
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(query, (err, rows) => {
    res.json(rows);
  });
});`,
  sql_safe: `// Truy vấn an toàn với tham số hóa (Parameterized Query)
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";
  db.query(query, [req.query.id], (err, rows) => {
    res.json(rows);
  });
});`,
  xss_vuln: `// Lỗ hổng DOM XSS qua gán innerHTML trực tiếp
function renderComment(userInput) {
  const commentDiv = document.getElementById('comment');
  commentDiv.innerHTML = "<b>" + userInput + "</b>";
}`,
  xss_safe: `// An toàn với textContent và bóc tách thực thể
function renderComment(userInput) {
  const commentDiv = document.getElementById('comment');
  commentDiv.textContent = userInput;
}`,
  eval_vuln: `// RCE / Code Execution qua hàm eval hoặc Function constructor
app.post('/calculate', (req, res) => {
  const expression = req.body.formula;
  const result = eval(expression);
  res.send({ result });
});`
};

function renderFeaturesList(features, filter = 'all') {
  const container = $('aiFeaturesContainer');
  if (!container) return;
  container.replaceChildren();

  const filtered = filter === 'all'
    ? features
    : features.filter((f) => f.category === filter);

  if (filtered.length === 0) {
    container.appendChild(createElement('div', { class: 'text-sm text-muted', textContent: 'Không có đặc trưng phù hợp bộ lọc.' }));
    return;
  }

  for (const feat of filtered) {
    const chip = createElement('div', {
      class: 'feature-chip',
      'data-ast': feat.category,
      tabindex: '0',
      role: 'button',
      'aria-label': `${feat.label}: ${feat.description}`
    },
      createElement('div', { class: 'feature-chip-header' },
        createElement('strong', { class: 'feature-name', textContent: feat.label }),
        createElement('span', { class: `badge badge-${feat.category}`, textContent: feat.category.toUpperCase() })
      ),
      createElement('div', { class: 'feature-desc', textContent: feat.description }),
      feat.cwe ? createElement('div', { class: 'feature-cwe', textContent: feat.cwe }) : null
    );

    chip.addEventListener('click', () => {
      ModalManager.show({
        'Mã đặc trưng AST': feat.id,
        'Tên nhãn': feat.label,
        'Phân loại AST': feat.category.toUpperCase(),
        'Mô tả chi tiết': feat.description,
        'CWE liên kết': feat.cwe || 'Không áp dụng'
      }, `Đặc trưng AST: ${feat.label}`);
    });

    chip.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        chip.click();
      }
    });

    container.appendChild(chip);
  }
}

async function loadAiHubData() {
  try {
    const res = await fetch('/api/ai');
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const data = await res.json();
    aiDataCache = data;

    const badge = $('aiIntegrityBadge');
    if (badge) {
      if (data.integrity_verified) {
        badge.className = 'badge badge-sanitizer';
        badge.textContent = '✅ SHA-256 Khớp';
      } else {
        badge.className = 'badge badge-danger';
        badge.textContent = '⚠️ Checksum Sai lệch';
      }
    }

    const checksumEl = $('aiChecksumVal');
    if (checksumEl) checksumEl.textContent = data.sha256_checksum || 'N/A';

    const modeEl = $('aiModelMode');
    if (modeEl) modeEl.textContent = data.architecture ? 'Calibrated Ensemble' : 'Ensemble';

    const countEl = $('aiFeaturesCount');
    if (countEl) countEl.textContent = Array.isArray(data.feature_taxonomy) ? data.feature_taxonomy.length : 30;

    if (Array.isArray(data.feature_taxonomy)) {
      renderFeaturesList(data.feature_taxonomy, 'all');
    }
  } catch (err) {
    console.error('Không thể nạp dữ liệu AI Hub:', err);
    const badge = $('aiIntegrityBadge');
    if (badge) {
      badge.className = 'badge badge-neutral';
      badge.textContent = 'Mô hình Cục bộ';
    }
  }
}

function initAiHub() {
  // Feature filters
  const filterBtns = document.querySelectorAll('.features-filter-bar .btn-preset');
  filterBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      filterBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter || 'all';
      if (aiDataCache && Array.isArray(aiDataCache.feature_taxonomy)) {
        renderFeaturesList(aiDataCache.feature_taxonomy, filter);
      }
    });
  });

  // Sandbox presets
  const presetBtns = document.querySelectorAll('.sandbox-presets .btn-preset');
  const sandboxTextarea = $('sandboxCode');
  presetBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.sandbox;
      if (key && SANDBOX_SNIPPETS[key] && sandboxTextarea) {
        sandboxTextarea.value = SANDBOX_SNIPPETS[key];
        sandboxTextarea.focus();
      }
    });
  });

  // Sandbox Predict Button
  const predictBtn = $('sandboxPredictBtn');
  if (predictBtn) {
    predictBtn.addEventListener('click', async () => {
      const code = sandboxTextarea ? sandboxTextarea.value.trim() : '';
      if (!code) return;

      predictBtn.disabled = true;
      const originalText = predictBtn.textContent;
      predictBtn.textContent = 'Đang phân tích AST & suy luận...';

      try {
        const res = await fetch('/api/ai/predict', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
          },
          body: JSON.stringify({ snippet: code })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        // Update Gauge
        updateCircularGauge(
          $('sandboxGaugeFill'),
          $('sandboxScoreText'),
          $('sandboxRiskBadge'),
          data.confidence || 0,
          data.risk_level || 'CLEAN'
        );

        // Update Active Features
        const activeListEl = $('sandboxActiveFeaturesList');
        if (activeListEl) {
          activeListEl.replaceChildren();
          const activeFeatures = data.active_features || [];
          if (activeFeatures.length === 0) {
            activeListEl.appendChild(createElement('span', { class: 'text-sm text-muted', textContent: 'Không phát hiện chỉ dấu AST bất thường (Mã nguồn an toàn)' }));
          } else {
            for (const feat of activeFeatures) {
              const chip = createElement('span', {
                class: `badge badge-${feat.category || 'flow'}`,
                textContent: `${feat.label} (khối lượng: ${feat.weight ? (feat.weight > 0 ? '+' : '') + feat.weight.toFixed(2) : '1.0'})`
              });
              activeListEl.appendChild(chip);
            }
          }
        }
      } catch (err) {
        console.error('Lỗi phân tích Sandbox AI:', err);
        const scoreText = $('sandboxScoreText');
        if (scoreText) scoreText.textContent = 'Lỗi';
      } finally {
        predictBtn.disabled = false;
        predictBtn.textContent = originalText;
      }
    });
  }
}

// ============================================================================
// 9. APP INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  ThemeController.init();
  TabController.init();
  ModalManager.init();
  initAiHub();

  const scanBtn = $('scanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', () => {
      const targetInput = $('target');
      const activeInput = $('active');
      const hybridAiInput = $('hybridAi');
      submit('/api/scan', {
        target: targetInput ? targetInput.value : 'http://127.0.0.1:3000',
        active: activeInput ? activeInput.checked : false,
        ai_hybrid: hybridAiInput ? hybridAiInput.checked : true
      }, scanBtn);
    });
  }

  const sourceBtn = $('sourceBtn');
  if (sourceBtn) {
    sourceBtn.addEventListener('click', () => {
      const filenameInput = $('filename');
      const codeInput = $('code');
      submit('/api/source', {
        filename: filenameInput ? filenameInput.value : 'example.js',
        source: codeInput ? codeInput.value : ''
      }, sourceBtn);
    });
  }

  const searchInput = $('search');
  if (searchInput) {
    searchInput.addEventListener('input', renderKnowledge);
  }

  // Load Session CSRF Token, Knowledge Base, and AI Hub Data in parallel
  Promise.all([
    fetch('/api/session').then((r) => r.json()),
    fetch('/api/knowledge').then((r) => r.json()),
    loadAiHubData()
  ])
    .then(([session, data]) => {
      csrfToken = session.csrf || '';
      knowledgeCache = Array.isArray(data) ? data : [];
      renderKnowledge();
    })
    .catch((err) => {
      const statusEl = $('status');
      if (statusEl) {
        statusEl.textContent = 'Không tải được một số thành phần phiên. Hãy mở lại ứng dụng bằng địa chỉ http://127.0.0.1:8000.';
      }
      console.error('Lỗi nạp phiên:', err);
    });
});
