// Background Service Worker for URL monitoring
class CipherCopSecurity {
  constructor() {
    this.API_BASE = 'http://localhost:5000';
    this.isEnabled = true;
    this.userAge = 18; // Default, will be set by user
    this.whitelist = new Set(); // User-defined whitelist only
    this.blacklist = new Set(); // User-defined blacklist only
    this.cache = new Map(); // URL analysis cache
    
    // Only keep critical system domains that should never be analyzed
    // These are for extension functionality, not security bypasses
    this.systemDomains = new Set([
      'chrome.google.com', // Chrome Web Store
      'chromewebstore.google.com'
    ]);
  }

  async init() {
    // Load settings from storage
    const settings = await chrome.storage.sync.get([
      'isEnabled', 'userAge', 'whitelist', 'blacklist'
    ]);
    
    // Storage may return plain objects/arrays; normalize to our expected types
    if (settings) {
      if (settings.whitelist && !(settings.whitelist instanceof Set)) {
        try {
          this.whitelist = new Set(Array.isArray(settings.whitelist) ? settings.whitelist : Object.values(settings.whitelist));
        } catch (e) {
          this.whitelist = new Set();
        }
      }
      if (settings.blacklist && !(settings.blacklist instanceof Set)) {
        try {
          this.blacklist = new Set(Array.isArray(settings.blacklist) ? settings.blacklist : Object.values(settings.blacklist));
        } catch (e) {
          this.blacklist = new Set();
        }
      }
      // assign other settings
      this.isEnabled = typeof settings.isEnabled === 'boolean' ? settings.isEnabled : this.isEnabled;
      this.userAge = typeof settings.userAge === 'number' ? settings.userAge : this.userAge;
    }
    
    // Set up listeners
    this.setupListeners();
    console.log('🛡️ CipherCop Security Extension initialized');
  }

  setupListeners() {
    // Monitor navigation to new URLs
    chrome.webNavigation.onBeforeNavigate.addListener(
      (details) => this.handleNavigation(details),
      { url: [{ schemes: ['http', 'https'] }] }
    );

    // Handle tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'loading' && tab.url) {
        this.analyzeURL(tab.url, tabId);
      }
    });

    // Listen for messages from content script
    chrome.runtime.onMessage.addListener(
      (request, sender, sendResponse) => {
        this.handleMessage(request, sender, sendResponse);
      }
    );
  }

  async handleNavigation(details) {
    if (!this.isEnabled || details.frameId !== 0) return;
    
    const url = details.url;
    
    // Skip our own extension URLs
    if (url.startsWith('chrome-extension://') || url.includes('warning.html')) {
      return;
    }
    
    console.log('🌐 Navigating to:', url);
    
    // Check whitelist/blacklist first
    if (this.isWhitelisted(url)) {
      console.log('✅ URL whitelisted:', url);
      return;
    }
    
    if (this.isBlacklisted(url)) {
      this.blockURL(details.tabId, url, 'BLACKLISTED');
      return;
    }

    // Analyze URL for threats
    await this.analyzeURL(url, details.tabId);
  }

  async analyzeURL(url, tabId) {
    try {
      // Only skip system domains (Chrome Web Store, etc.)
      const domain = new URL(url).hostname.toLowerCase();
      // Skip localhost/internal network to prevent self-analysis loops
      if (domain === 'localhost' || domain === '127.0.0.1' || domain.startsWith('192.168.')) {
        console.log('ℹ️ Skipping analysis for internal host:', domain);
        return;
      }
      if (this.systemDomains.has(domain)) {
        console.log('✅ System domain, skipping analysis:', domain);
        return;
      }
      
      // Check user-defined whitelist/blacklist
      if (this.whitelist.has(url) || this.whitelist.has(domain)) {
        console.log('✅ User whitelisted:', url);
        return;
      }
      
      if (this.blacklist.has(url) || this.blacklist.has(domain)) {
        console.log('🚫 User blacklisted:', url);
        this.blockURL(tabId, url, 'USER_BLACKLISTED');
        return;
      }
      
      // Check cache first
      if (this.cache.has(url)) {
        const cached = this.cache.get(url);
        if (Date.now() - cached.timestamp < 300000) { // 5 min cache
          this.handleAnalysisResult(cached.result, url, tabId);
          return;
        }
      }

      // Try backend analysis first, fallback to client-side
      console.log('🔍 Analyzing URL:', url);
      let result = await this.callBackendAPI(url);
      if (!result) {
        console.log('📱 Backend unavailable, using client-side analysis');
        result = this.clientSideAnalysis(url);
      }
      
      // Cache result
      this.cache.set(url, {
        result,
        timestamp: Date.now()
      });

      this.handleAnalysisResult(result, url, tabId);
    } catch (error) {
      console.error('❌ URL analysis failed:', error);
      // Use client-side analysis as fallback
      const result = this.clientSideAnalysis(url);
      this.handleAnalysisResult(result, url, tabId);
    }
  }

  async callBackendAPI(url) {
    try {
      const response = await fetch(`${this.API_BASE}/analyze/website`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(5000) // 5 second timeout
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.log('⚠️ Backend API unavailable:', error.message);
      return null;
    }
  }

  clientSideAnalysis(url) {
    // Lightweight client-side analysis when backend/ML model is unavailable
    // This should mirror some features from your URLFeatureExtraction.py
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      const path = urlObj.pathname.toLowerCase();
      const search = urlObj.search.toLowerCase();
      const fullUrl = url.toLowerCase();
      
      let features = {
        // URL-based features (similar to your ML model)
        hasIP: this.hasIPAddress(domain),
        urlLength: url.length,
        domainLength: domain.length,
        pathLength: path.length,
        queryLength: search.length,
        
        // Suspicious patterns
        hasDoubleSlash: fullUrl.includes('//') && !fullUrl.startsWith('http'),
        hasSuspiciousChars: /[<>'"&%]/.test(fullUrl),
        hasUnicodeChars: /[^\x00-\x7F]/.test(fullUrl),
        
        // Domain analysis
        subdomainCount: domain.split('.').length - 2,
        hasNumericDomain: /\d/.test(domain.split('.')[0]),
        hasHyphenDomain: domain.includes('-'),
        
        // Suspicious TLDs (basic check)
        suspiciousTLD: /\.(tk|ml|ga|cf|pw)$/.test(domain),
        
        // URL shorteners
        isShortener: this.isKnownShortener(domain)
      };
      
      // Calculate risk score based on features (simplified ML-like scoring)
      let riskScore = this.calculateRiskScore(features);
      
      // Determine classification based on risk score
      let classification = 'LEGITIMATE';
      let confidence = Math.abs(riskScore - 50); // Distance from neutral
      
      if (riskScore >= 70) {
        classification = 'FRAUDULENT';
        confidence = Math.min(riskScore, 95);
      } else if (riskScore >= 40) {
        classification = 'SUSPICIOUS'; 
        confidence = Math.min(riskScore - 20, 80);
      } else {
        confidence = Math.min(50 - riskScore, 90);
      }
      
      return {
        classification,
        confidence_score: confidence,
        threat_sources: this.getActiveThreatSources(features),
        analysis_summary: {
          combined_risk_score: riskScore,
          client_side_analysis: true,
          features_analyzed: Object.keys(features).length,
          ml_model_available: false
        }
      };
    } catch (error) {
      console.error('Client-side analysis failed:', error);
      return {
        classification: 'UNKNOWN',
        confidence_score: 0,
        threat_sources: ['analysis_error'],
        analysis_summary: { 
          client_side_analysis: true,
          error: error.message 
        }
      };
    }
  }

  hasIPAddress(domain) {
    // Check if domain is an IP address
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(domain) || ipv6Regex.test(domain);
  }

  isKnownShortener(domain) {
    const shorteners = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link',
      'ow.ly', 'buff.ly', 'is.gd', 'tiny.cc', 'rb.gy'
    ];
    return shorteners.some(s => domain.includes(s));
  }

  calculateRiskScore(features) {
    let score = 30; // Start neutral
    
    // High-risk indicators
    if (features.hasIP) score += 25;
    if (features.suspiciousTLD) score += 20;
    if (features.isShortener) score += 15;
    if (features.hasUnicodeChars) score += 15;
    
    // Medium-risk indicators  
    if (features.urlLength > 100) score += 10;
    if (features.subdomainCount > 3) score += 10;
    if (features.hasNumericDomain) score += 8;
    if (features.hasSuspiciousChars) score += 8;
    
    // Low-risk indicators
    if (features.hasHyphenDomain) score += 5;
    if (features.hasDoubleSlash) score += 5;
    if (features.pathLength > 50) score += 3;
    
    return Math.min(score, 100);
  }

  getActiveThreatSources(features) {
    let sources = [];
    
    if (features.hasIP) sources.push('ip_address_domain');
    if (features.suspiciousTLD) sources.push('suspicious_tld');
    if (features.isShortener) sources.push('url_shortener');
    if (features.hasUnicodeChars) sources.push('unicode_characters');
    if (features.urlLength > 100) sources.push('long_url');
    if (features.subdomainCount > 3) sources.push('excessive_subdomains');
    if (features.hasNumericDomain) sources.push('numeric_domain');
    if (features.hasSuspiciousChars) sources.push('suspicious_characters');
    
    return sources.length > 0 ? sources : ['heuristic_analysis'];
  }

  handleAnalysisResult(result, url, tabId) {
    const verdict = result.verdict || result.classification || 'UNKNOWN';
    // Prefer the combined_risk_score from the analysis_summary when available
    // as it represents the final combined risk used by backend logic.
    const combinedScore = (result.analysis_summary && typeof result.analysis_summary.combined_risk_score === 'number')
      ? result.analysis_summary.combined_risk_score
      : (typeof result.combined_score === 'number' ? result.combined_score : (typeof result.confidence_score === 'number' ? result.confidence_score : 0));
    const confidence = combinedScore || 0;
    const threatSources = result.threat_sources || (result.analysis_summary && result.analysis_summary.threat_sources) || [];

    // Debug: surface key fields to help trace reversed warnings
    try {
      console.debug('🔎 handleAnalysisResult debug', { url, verdict, combinedScore, threatSources, ml_proba: result.ml_model?.proba ?? result.ml_proba ?? null, whois: result.whois, html: result.html });
    } catch (e) {
      console.debug('🔎 handleAnalysisResult debug (partial)', { url, verdict, combinedScore });
    }
    
    console.log(`🔍 Analysis result for ${url}:`, {
      verdict,
      confidence,
      sources: threatSources
    });
    
    // Enhanced decision logic based on confidence and sources
    // Use combinedScore-driven thresholds to decide action. This aligns the
    // extension's behavior with backend scoring and reduces confusion.
    switch (verdict) {
      case 'FRAUDULENT':
        if (combinedScore >= 80 || threatSources.includes('Google Safe Browsing')) {
          this.blockURL(tabId, url, 'FRAUDULENT', result);
        } else {
          this.warnUser(tabId, url, result, 'STRONG');
        }
        break;

      case 'SUSPICIOUS':
        if (combinedScore >= 60) {
          this.warnUser(tabId, url, result, 'MEDIUM');
        } else {
          this.warnUser(tabId, url, result, 'LIGHT');
        }
        break;

      case 'LEGITIMATE':
        if (combinedScore < 10) {
          console.log('✅ Low-risk/legitimate site, no action taken for', url);
          return;
        }
        if (this.userAge < 18) {
          this.checkAdultContent(url, result, tabId);
        }
        this.logThreat(url, 'LEGITIMATE', 'ALLOWED', result);
        break;
    }

    // Update popup with analysis
    this.updatePopup(result, url);
    
    // Cache result for performance
    this.cache.set(url, {
      result,
      timestamp: Date.now()
    });

    // Send visit log to backend (best-effort, include session token if available)
    try {
      chrome.storage.sync.get(['authToken'], (res) => {
        const payload = {
          url,
          domain: (new URL(url)).hostname,
          title: '',
          is_threat: (result.verdict || result.classification || '').toUpperCase() !== 'LEGITIMATE',
          threat_type: result.verdict || result.classification || null,
          risk_score: result.analysis_summary?.combined_risk_score || result.confidence_score || 0,
          blocked: false,
          warning_shown: false,
          user_action: null
        };
        if (res && res.authToken) payload.session_token = res.authToken;

        fetch(`${this.API_BASE}/extension/log-visit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }).catch(e => console.debug('Extension visit log failed:', e));
      });
    } catch (e) {
      console.debug('Failed to send visit log:', e);
    }
  }

  async blockURL(tabId, url, reason, analysisResult) {
    console.log('🚫 Blocking URL:', url, 'Reason:', reason);
    
    // Prevent blocking our own warning page
    if (url.includes('warning.html') || url.includes('chrome-extension://')) {
      console.log('⚠️ Prevented blocking warning page or extension URL');
      return;
    }
    
    // Create enhanced warning URL with analysis data
    const warningData = {
      url: encodeURIComponent(url),
      reason: reason,
      confidence: analysisResult?.confidence_score || 0,
      sources: analysisResult?.threat_sources?.join(', ') || '',
      riskScore: analysisResult?.analysis_summary?.combined_risk_score || 0,
      safeBrowsingThreat: analysisResult?.analysis_summary?.safe_browsing_threat || false,
      mlDetected: analysisResult?.analysis_summary?.ml_phishing_detected || false
    };
    
    const warningURL = chrome.runtime.getURL('warning.html') + 
      '?' + new URLSearchParams(warningData).toString();
    
    await chrome.tabs.update(tabId, { url: warningURL });
    
    // Log the block with enhanced details
    this.logThreat(url, reason, 'BLOCKED', analysisResult);
  }

  async warnUser(tabId, url, result, intensity = 'MEDIUM') {
    console.log(`⚠️ Warning user about ${url} (intensity: ${intensity})`);

    try {
      // If tabId is missing or invalid, fallback to the currently active tab
      if (!tabId) {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        tabId = (tabs && tabs[0] && tabs[0].id) ? tabs[0].id : null;
      }

      if (!tabId) {
        console.warn('No tab id available to show warning; aborting overlay injection');
        return;
      }

      // Inject warning overlay with different intensities
      chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        data: {
          url,
          result,
          type: result.verdict || 'SUSPICIOUS',
          intensity: intensity,
          confidence: result.confidence_score || 0,
          sources: result.threat_sources || [],
          canProceed: intensity !== 'STRONG' // Allow proceeding for non-critical warnings
        }
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Failed to send showWarning message:', chrome.runtime.lastError.message);
        } else {
          console.log('showWarning message acknowledged:', response);
        }
      });
    } catch (e) {
      console.error('warnUser failed:', e);
      return;
    }
    
    this.logThreat(url, result.verdict || 'SUSPICIOUS', 'WARNED', result);
  }

  async checkAdultContent(url, result, tabId) {
    try {
      // Get adult content filter setting
      const { blockAdultContent } = await chrome.storage.sync.get(['blockAdultContent']);
      
      if (!blockAdultContent && this.userAge >= 18) return;

      const domain = new URL(url).hostname.toLowerCase();
      
      // Enhanced adult content keywords and domains
      const adultKeywords = [
        'porn', 'xxx', 'sex', 'adult', 'nude', 'naked', 'erotic', 'nsfw',
        'webcam', 'cam', 'dating', 'hookup', 'escort', 'massage', 'strip',
        'fetish', 'bdsm', 'mature', 'milf', 'teen', 'amateur', 'hardcore',
        'softcore', 'lingerie', 'bikini', 'swimsuit', 'underwear'
      ];
      
      const adultDomains = [
        'pornhub.com', 'xvideos.com', 'xnxx.com', 'redtube.com', 'youporn.com',
        'tube8.com', 'spankbang.com', 'xhamster.com', 'beeg.com', 'tnaflix.com',
        'chaturbate.com', 'cam4.com', 'bongacams.com', 'stripchat.com',
        'onlyfans.com', 'fansly.com', 'manyvids.com', 'clips4sale.com'
      ];

      // Check domain against known adult sites
      if (adultDomains.some(adultDomain => domain.includes(adultDomain))) {
        console.log('🔞 Adult content detected by domain:', domain);
        await this.blockURL(tabId, url, 'ADULT_CONTENT');
        return;
      }

      // Check URL and domain for adult keywords
      const urlLower = url.toLowerCase();
      const domainLower = domain.toLowerCase();
      
      const foundKeywords = adultKeywords.filter(keyword => 
        urlLower.includes(keyword) || domainLower.includes(keyword)
      );

      if (foundKeywords.length > 0) {
        console.log('🔞 Adult content detected by keywords:', foundKeywords);
        
        // More strict blocking for users under 18
        if (this.userAge < 18) {
          await this.blockURL(tabId, url, 'ADULT_CONTENT');
        } else if (blockAdultContent) {
          // Show warning for adults with filter enabled
          await chrome.tabs.sendMessage(tabId, {
            action: 'showWarning',
            data: {
              url,
              result: { verdict: 'ADULT_CONTENT', keywords: foundKeywords },
              type: 'ADULT_CONTENT'
            }
          });
        }
        
        this.logThreat(url, 'ADULT_CONTENT', this.userAge < 18 ? 'BLOCKED' : 'WARNED');
      }

      // Additional check using AI/ML if available
      await this.checkAdultContentML(url, tabId);
      
    } catch (error) {
      console.error('Error checking adult content:', error);
    }
  }

  async checkAdultContentML(url, tabId) {
    try {
      // Send URL to backend for AI-based adult content detection
      const response = await fetch(`${this.API_BASE}/analyze/adult-content`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, userAge: this.userAge })
      });

      if (response.ok) {
        const result = await response.json();
        
        if (result.isAdultContent && result.confidence > 0.7) {
          console.log('🔞 Adult content detected by AI:', result.confidence);
          
          if (this.userAge < 18 || (await chrome.storage.sync.get(['blockAdultContent'])).blockAdultContent) {
            await this.blockURL(tabId, url, 'ADULT_CONTENT_AI');
          }
        }
      }
    } catch (error) {
      // Silently fail if backend is unavailable
      console.debug('Adult content ML check unavailable:', error.message);
    }
  }

  fallbackAnalysis(url, tabId) {
    // Basic heuristic analysis when API is unavailable
    const suspiciousPatterns = [
      /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, // IP addresses
      /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./i, // Suspicious domains
      /\.(tk|ml|ga|cf)$/i, // Suspicious TLDs
      /bit\.ly|tinyurl|t\.co/i, // URL shorteners
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => 
      pattern.test(url)
    );
    
    if (isSuspicious) {
      this.warnUser(tabId, url, {
        verdict: 'SUSPICIOUS',
        reason: 'Heuristic analysis detected suspicious patterns'
      });
    }
  }

  isWhitelisted(url) {
    const domain = new URL(url).hostname.toLowerCase();
    return this.whitelist.has(domain) || 
           this.whitelist.has(url);
  }

  isBlacklisted(url) {
    const domain = new URL(url).hostname;
    return this.blacklist.has(domain) || this.blacklist.has(url);
  }

  logThreat(url, reason, action, analysisResult = null) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      url,
      reason,
      action,
      userAgent: navigator.userAgent,
      confidence: analysisResult?.confidence_score || null,
      sources: analysisResult?.threat_sources || [],
      riskScore: analysisResult?.analysis_summary?.combined_risk_score || null,
      safeBrowsingThreat: analysisResult?.analysis_summary?.safe_browsing_threat || false,
      mlDetected: analysisResult?.analysis_summary?.ml_phishing_detected || false
    };
    
    // Try to include session token if available
    chrome.storage.sync.get(['authToken'], (res) => {
      const payload = Object.assign({}, logEntry);
      if (res && res.authToken) payload.session_token = res.authToken;

      fetch(`${this.API_BASE}/log/threat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).catch(console.error);
    });
  }

  updatePopup(result, url) {
    try {
      // Normalize common fields so popup can render reliably
      const normalized = {
        url,
        timestamp: Date.now(),
        verdict: result.verdict || result.classification || result.analysis_summary?.classification || 'UNKNOWN',
        combined_score: (typeof result.combined_score === 'number') ? result.combined_score : result.analysis_summary?.combined_risk_score || result.confidence_score || 0,
        heuristic_classification: result.heuristic_classification || result.analysis_summary?.heuristic_classification || null,
        confidence_score: result.confidence_score || result.analysis_summary?.confidence_score || null,
        ml_model: result.ml_model || (result.ml_prediction != null ? { prediction: result.ml_prediction, proba: result.ml_proba } : null),
        ml_prediction: result.ml_prediction ?? null,
        ml_proba: result.ml_proba ?? result.ml_probability ?? null,
        safe_browsing: result.safe_browsing || { threat_found: !!result.analysis_summary?.safe_browsing_threat },
        threat_sources: result.threat_sources || result.analysis_summary?.threat_sources || result.threat_sources || [] ,
        analysis_summary: result.analysis_summary || null,
        raw: result
      };

      chrome.storage.local.set({ latestAnalysis: { result: normalized, url, timestamp: normalized.timestamp } });
    } catch (e) {
      // Fallback to raw storage if normalization fails
      chrome.storage.local.set({ latestAnalysis: { result, url, timestamp: Date.now() } });
    }
  }

  handleMessage(request, sender, sendResponse) {
    switch (request.action) {
      case 'getStatus':
        sendResponse({
          isEnabled: this.isEnabled,
          userAge: this.userAge
        });
        break;
      case 'toggleEnabled':
        this.isEnabled = !this.isEnabled;
        chrome.storage.sync.set({ isEnabled: this.isEnabled });
        sendResponse({ isEnabled: this.isEnabled });
        break;
      case 'setAge':
        this.userAge = request.age;
        chrome.storage.sync.set({ userAge: this.userAge });
        sendResponse({ success: true });
        break;
      case 'addToWhitelist':
        this.whitelist.add(request.url);
        chrome.storage.sync.set({ whitelist: Array.from(this.whitelist) });
        sendResponse({ success: true });
        break;
      case 'overrideWarning':
        try {
          const entry = {
            timestamp: new Date().toISOString(),
            url: request.url,
            reason: request.reason || 'UNKNOWN',
            action: 'OVERRIDE',
            userAgent: navigator.userAgent
          };
          // Append to local dashboard history
          chrome.storage.local.get(['dashboardHistory'], (res) => {
            const hist = Array.isArray(res.dashboardHistory) ? res.dashboardHistory : [];
            hist.unshift(entry);
            // keep recent 500 entries
            chrome.storage.local.set({ dashboardHistory: hist.slice(0, 500) });
          });

          // Forward to backend log endpoint (best-effort)
              chrome.storage.sync.get(['authToken'], (res) => {
                const payload = { url: request.url, reason: 'USER_OVERRIDE', action: 'OVERRIDE', userAgent: navigator.userAgent };
                if (res && res.authToken) payload.session_token = res.authToken;
                fetch(`${this.API_BASE}/log/threat`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(payload)
                }).catch(console.error);
              });

          sendResponse({ success: true });
        } catch (e) {
          sendResponse({ success: false, error: String(e) });
        }
        break;
    }
  }
}

// Initialize when extension starts
const cipherCopSecurity = new CipherCopSecurity();
cipherCopSecurity.init();
