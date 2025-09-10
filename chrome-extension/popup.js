// Popup script for extension interface
class CipherCopPopup {
  constructor() {
    this.currentTab = null;
    this.init();
  }

  async init() {
    try {
      // Wait for DOM to be ready
      if (document.readyState !== 'complete') {
        await new Promise(resolve => {
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', resolve);
          } else {
            resolve();
          }
        });
      }

      // Get current tab first
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tab;

      // Load latest analysis
      await this.loadLatestAnalysis();
      
      // Setup event listeners
      this.setupEventListeners();
      
      // Load settings
      await this.loadSettings();
    } catch (error) {
      console.error('Error initializing popup:', error);
    }
  }

  async loadLatestAnalysis() {
    try {
  // Always request a fresh analysis for the active tab when the popup
  // opens. This avoids showing a recently-analyzed URL from another tab
  // (race condition between background analysis and popup open).
  await this.requestAnalysis(this.currentTab.url);
    } catch (error) {
      console.error('Error loading analysis:', error);
      this.showError('Unable to load site analysis');
    }
  }

  async requestAnalysis(url) {
    const statusCard = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    
    statusText.innerHTML = `
      <strong>🔍 Analyzing ${new URL(url).hostname}...</strong>
      <p style="margin: 5px 0 0 0; font-size: 12px;">Please wait...</p>
    `;

    try {
      const response = await fetch('http://localhost:5000/analyze/website', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      const result = await response.json();
      this.displayAnalysis(result);
    } catch (error) {
      console.error('Analysis failed:', error);
      statusCard.className = 'status-card warning';
      statusText.innerHTML = `
        <strong>⚠️ Analysis Unavailable</strong>
        <p style="margin: 5px 0 0 0; font-size: 12px;">Backend service offline</p>
      `;
    }
  }

  displayAnalysis(result) {
    const statusCard = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    const siteInfo = document.getElementById('site-info');
    const analysisDetails = document.getElementById('analysis-details');

    if (!result) {
      this.showError('No analysis available');
      return;
    }

    // Support multiple backend shapes
    const domain = (result.url && (() => { try { return new URL(result.url).hostname; } catch(e){ return new URL(this.currentTab.url).hostname; } })()) || new URL(this.currentTab.url).hostname;
    const verdict = result.verdict || result.classification || result.analysis_summary?.classification || 'UNKNOWN';
  // Prefer analysis_summary.combined_risk_score if available; fall back to top-level confidence_score
  const combinedScore = (typeof result.combined_score === 'number') ? result.combined_score : (typeof result.analysis_summary?.combined_risk_score === 'number' ? result.analysis_summary.combined_risk_score : (typeof result.confidence_score === 'number' ? result.confidence_score : 0));
    const heuristicScore = result.heuristic_classification?.risk_score || result.analysis_summary?.combined_risk_score || 'N/A';

    // ML prediction/probability detection
    const mlPrediction = (result.ml_model && (result.ml_model.prediction != null)) ? result.ml_model.prediction : (result.ml_prediction ?? null);
    const mlProbRaw = result.ml_model?.proba || result.ml_model?.probability || result.ml_proba || result.ml_probability || null;
    const mlProb = (typeof mlProbRaw === 'number') ? Math.round(mlProbRaw * 100) : (typeof mlProbRaw === 'string' ? Math.round(Number(mlProbRaw) * 100) : (typeof mlProbRaw === 'object' && mlProbRaw?.[1] ? Math.round(Number(mlProbRaw[1]) * 100) : null));

    const safeBrowsing = result.safe_browsing?.threat_found ?? result.analysis_summary?.safe_browsing_threat ?? result.safe_browsing?.malicious ?? false;
    const threatSources = result.threat_sources || result.analysis_summary?.threat_sources || result.analysis_summary?.threat_sources || [];

    // Update status card
    statusCard.className = 'status-card';
    let subtitle = 'No threats detected';
    if (verdict === 'FRAUDULENT' || combinedScore >= 75) {
      statusCard.className = 'status-card danger';
      statusText.innerHTML = `\n        <strong>🚨 ${domain} is dangerous</strong>\n        <p style="margin: 5px 0 0 0; font-size: 12px;">Avoid this site</p>\n      `;
      subtitle = 'High risk - take action';
    } else if (verdict === 'SUSPICIOUS' || combinedScore >= 45) {
      statusCard.className = 'status-card warning';
      statusText.innerHTML = `\n        <strong>⚠️ ${domain} may be suspicious</strong>\n        <p style="margin: 5px 0 0 0; font-size: 12px;">Exercise caution</p>\n      `;
      subtitle = 'Suspicious activity detected';
    } else {
      statusCard.className = 'status-card';
      statusText.innerHTML = `\n        <strong>✅ ${domain} appears safe</strong>\n        <p style="margin: 5px 0 0 0; font-size: 12px;">${subtitle}</p>\n      `;
    }

    // Build details block
    siteInfo.style.display = 'block';
    const sourcesHtml = (Array.isArray(threatSources) && threatSources.length) ? `<p><strong>Threat Sources:</strong> ${threatSources.join(', ')}</p>` : '';
  // Always show that the ML model was used when a prediction is present
  const mlHtml = (mlPrediction != null) ? `<p><strong>Model detected:</strong> ${mlPrediction === 1 ? 'Phishing' : 'Legitimate'}${mlProb != null ? ` (${mlProb}% confidence)` : ''}</p>` : '';
    const safeBrowsingHtml = safeBrowsing ? `<p><strong>Google Safe Browsing:</strong> ⚠️ Threat detected</p>` : `<p><strong>Google Safe Browsing:</strong> ✅ Clean</p>`;

  const combinedScoreDisplay = (typeof combinedScore === 'number') ? `${Math.round(combinedScore)} / 100` : 'N/A';

  // Show 'stale' marker if the analysis is older than CACHE_TTL_MS
  const CACHE_TTL_MS = 60 * 1000; // 60s
  const resTimestamp = result.timestamp ? new Date(result.timestamp).getTime() : Date.now();
  const isStale = (Date.now() - resTimestamp) > CACHE_TTL_MS;

  analysisDetails.innerHTML = `
      <div style="font-size: 12px; background: #f8f9fa; padding: 10px; border-radius: 5px;">
        <p><strong>Verdict:</strong> ${verdict}</p>
        <p><strong>Combined Risk Score:</strong> ${combinedScoreDisplay}</p>
        <p><strong>Heuristic Score:</strong> ${heuristicScore}</p>
  ${mlHtml}
        ${safeBrowsingHtml}
        ${sourcesHtml}
    <p><strong>Analysis Time:</strong> ${new Date(result.timestamp || Date.now()).toLocaleString()} ${isStale ? '<span style="color:#777; font-size:11px;">(stale)</span>' : ''}</p>
      </div>
    `;

    // Mirror background warning logic: if the result is suspicious/fraudulent
    // and crosses display thresholds, ask the content script to show the
    // appropriate warning overlay so the user sees the yellow page immediately
    // when they open the popup.
    try {
      const numericScore = (typeof combinedScore === 'number') ? combinedScore : (result.analysis_summary && result.analysis_summary.combined_risk_score) || 0;
      let intensity = null;
      if (verdict === 'FRAUDULENT' || numericScore >= 75) {
        intensity = 'STRONG';
      } else if (verdict === 'SUSPICIOUS' && numericScore >= 60) {
        intensity = 'MEDIUM';
      } else if (verdict === 'SUSPICIOUS' && numericScore >= 45) {
        intensity = 'LIGHT';
      }

      if (intensity) {
        // send message to active tab to show the warning overlay
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          try {
            if (tabs && tabs[0] && tabs[0].id) {
              chrome.tabs.sendMessage(tabs[0].id, { action: 'showWarning', data: { url: result.url || this.currentTab.url, result, type: verdict, intensity, confidence: numericScore, sources: result.threat_sources || [] } }, (resp) => {
                if (chrome.runtime.lastError) {
                  console.warn('Failed to send showWarning to content script:', chrome.runtime.lastError.message);
                  // Fallback: open the warning page if content script not present
                  try {
                    const warningURL = chrome.runtime.getURL('warning.html') + '?' + new URLSearchParams({ url: result.url || this.currentTab.url, confidence: numericScore }).toString();
                    chrome.tabs.create({ url: warningURL });
                  } catch (e) {
                    console.error('Failed to open fallback warning page:', e);
                  }
                } else {
                  console.log('showWarning acknowledged by content script', resp);
                }
              });
            } else {
              console.warn('No active tab found to send showWarning');
            }
          } catch (e) {
            console.error('Error querying tabs or sending showWarning:', e);
          }
        });
      }
    } catch (e) {
      console.debug('Warning overlay trigger failed:', e);
    }

    // Send visit log to backend (best-effort)
    try {
      const visitPayload = {
        url: result.url || this.currentTab.url,
        domain: (result.url ? (new URL(result.url)).hostname : (new URL(this.currentTab.url)).hostname),
        title: result.title || this.currentTab.title || '',
        is_threat: (verdict === 'FRAUDULENT' || safeBrowsing || combinedScore >= 75),
        threat_type: verdict || null,
        risk_score: combinedScore || 0,
        blocked: false,
        warning_shown: !!intensity,
        user_action: null,
        timestamp: new Date().toISOString()
      };

      // fire-and-forget but include auth token if available
      chrome.storage.sync.get(['authToken'], (res) => {
        if (res && res.authToken) visitPayload.session_token = res.authToken;

        fetch('http://localhost:5000/extension/log-visit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(visitPayload)
        }).then(async (r) => {
          if (!r.ok) {
            const t = await r.text().catch(()=>'');
            console.debug('log-visit response not ok', r.status, t);
          }
        }).catch(e => console.debug('Failed to send visit log from popup:', e));
      });
    } catch (e) {
      console.debug('Popup visit log error', e);
    }
  }

  setupEventListeners() {
    try {
      // Check if elements exist before adding listeners
      const protectionToggle = document.getElementById('protection-toggle');
      if (protectionToggle) {
        protectionToggle.addEventListener('change', async (e) => {
          await chrome.runtime.sendMessage({
            action: 'toggleEnabled'
          });
        });
      }

      // Age selection
      const ageSelect = document.getElementById('age-select');
      if (ageSelect) {
        ageSelect.addEventListener('change', async (e) => {
          await chrome.runtime.sendMessage({
            action: 'setAge',
            age: parseInt(e.target.value)
          });
        });
      }

      // Adult filter toggle
      const adultFilterToggle = document.getElementById('adult-filter-toggle');
      if (adultFilterToggle) {
        adultFilterToggle.addEventListener('change', async (e) => {
          await chrome.storage.sync.set({
            blockAdultContent: e.target.checked
          });
        });
      }

      // Whitelist current site
      const whitelistBtn = document.getElementById('whitelist-btn');
      if (whitelistBtn) {
        whitelistBtn.addEventListener('click', async () => {
          await chrome.runtime.sendMessage({
            action: 'addToWhitelist',
            url: this.currentTab.url
          });
          // also send to backend as user_action 'trust'
          try {
            chrome.storage.sync.get(['authToken'], (res) => {
              const payload = {
                url: this.currentTab.url,
                domain: (new URL(this.currentTab.url)).hostname,
                title: this.currentTab.title || '',
                is_threat: false,
                threat_type: null,
                risk_score: 0,
                blocked: false,
                warning_shown: false,
                user_action: 'trust',
                timestamp: new Date().toISOString()
              };
              if (res && res.authToken) payload.session_token = res.authToken;

              fetch('http://localhost:5000/extension/log-visit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
              }).catch(e => console.debug('Failed to log trust action:', e));
            });
          } catch (e) { console.debug('Whitelist logging error', e); }

          this.showNotification('✅ Site added to whitelist');
        });
      }

      // Report malicious site
      const reportBtn = document.getElementById('report-btn');
      if (reportBtn) {
        reportBtn.addEventListener('click', () => {
          // send a user_action 'report' and mark is_threat true
          try {
            chrome.storage.sync.get(['authToken'], (res) => {
              const payload = {
                url: this.currentTab.url,
                domain: (new URL(this.currentTab.url)).hostname,
                title: this.currentTab.title || '',
                is_threat: true,
                threat_type: 'USER_REPORTED',
                risk_score: 100,
                blocked: false,
                warning_shown: false,
                user_action: 'report',
                timestamp: new Date().toISOString()
              };
              if (res && res.authToken) payload.session_token = res.authToken;

              fetch('http://localhost:5000/extension/log-visit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
              }).catch(e => console.debug('Failed to log report action:', e));
            });
          } catch (e) { console.debug('Report logging error', e); }

          // keep existing behavior (report endpoint) as well
          this.reportMaliciousSite();
        });
      }

      // Open dashboard
      const dashboardBtn = document.getElementById('dashboard-btn');
      if (dashboardBtn) {
        dashboardBtn.addEventListener('click', () => {
          // frontend runs on port 3000 in this workspace
          chrome.tabs.create({ url: 'http://localhost:3000' });
        });
      }

      // Allow clicking status text to force-refresh analysis
      const statusText = document.getElementById('status-text');
      if (statusText) {
        statusText.style.cursor = 'pointer';
        statusText.title = 'Click to refresh analysis';
        statusText.addEventListener('click', async () => {
          if (this.currentTab && this.currentTab.url) {
            await this.requestAnalysis(this.currentTab.url);
          }
        });
      }
    } catch (error) {
      console.error('Error setting up event listeners:', error);
    }
  }

  async loadSettings() {
    const settings = await chrome.storage.sync.get([
      'isEnabled', 'userAge', 'blockAdultContent'
    ]);

    // Update UI based on settings
    document.getElementById('protection-toggle').checked = settings.isEnabled !== false;
    document.getElementById('age-select').value = settings.userAge || 18;
    document.getElementById('adult-filter-toggle').checked = settings.blockAdultContent || false;

    // Try to load dashboard summary if user signed in
    this.loadDashboard();
  }

  async loadDashboard() {
    try {
      chrome.storage.sync.get(['authToken'], async (res) => {
        const token = res?.authToken || null;
        const payload = token ? { session_token: token } : {};

        try {
          const response = await fetch('http://localhost:5000/extension/dashboard', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });

          if (!response.ok) {
            console.debug('Popup dashboard fetch not ok', response.status);
            return;
          }

          const data = await response.json();
          if (data && data.status === 'success' && data.data) {
            this.renderDashboard(data.data);
          }
        } catch (err) {
          console.debug('Popup dashboard fetch error', err);
        }
      });
    } catch (e) {
      console.debug('loadDashboard error', e);
    }
  }

  renderDashboard(dashboardData) {
    try {
      const el = document.getElementById('popup-dashboard');
      if (!el) return;

      const stats = dashboardData.stats || {};
      document.getElementById('pc-pagesScanned').textContent = stats.pages_visited || stats.pages_scanned || 0;
      document.getElementById('pc-threatsDetected').textContent = stats.threats_detected || 0;
      document.getElementById('pc-threatsBlocked').textContent = stats.threats_blocked || 0;
      document.getElementById('pc-trustedCount').textContent = dashboardData.trusted_count || 0;
      document.getElementById('pc-untrustedCount').textContent = dashboardData.untrusted_count || 0;

      // Recent visits (if any)
      const recent = dashboardData.recent_visits || [];
      const listEl = document.getElementById('pc-recentList');
      listEl.innerHTML = '';
      if (!recent.length) {
        listEl.innerHTML = '<div style="color:#666">No recent visits</div>';
      } else {
        recent.slice(0,10).forEach(r => {
          const d = document.createElement('div');
          d.style.padding = '6px 0';
          d.style.borderBottom = '1px solid #eee';
          d.innerHTML = `<div style="font-weight:600;">${r.domain}</div><div style="color:#666; font-size:11px;">${new Date(r.visit_time).toLocaleString()}</div>`;
          listEl.appendChild(d);
        });
      }

      el.style.display = 'block';
    } catch (e) {
      console.debug('renderDashboard error', e);
    }
  }

  async reportMaliciousSite() {
    try {
      const response = await fetch('http://localhost:5000/report/malicious', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: this.currentTab.url,
          userAgent: navigator.userAgent,
          timestamp: new Date().toISOString()
        })
      });

      if (response.ok) {
        this.showNotification('🚨 Site reported successfully');
      } else {
        this.showNotification('❌ Failed to report site');
      }
    } catch (error) {
      console.error('Report failed:', error);
      this.showNotification('❌ Report failed - offline');
    }
  }

  showNotification(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      background: #28a745;
      color: white;
      padding: 10px;
      border-radius: 5px;
      font-size: 12px;
      z-index: 1000;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => notification.remove(), 3000);
  }

  showError(message) {
    const statusCard = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    
    statusCard.className = 'status-card warning';
    statusText.innerHTML = `
      <strong>⚠️ ${message}</strong>
      <p style="margin: 5px 0 0 0; font-size: 12px;">Check connection and try again</p>
    `;
  }
}

// Initialize popup when loaded
document.addEventListener('DOMContentLoaded', () => {
  new CipherCopPopup();
});
