// Lightweight client script (extracted from inline index.html) to run without bundling
const API_BASE = 'http://localhost:5000';

function createParticles() {
    const particlesContainer = document.getElementById('particles');
    if (!particlesContainer) return;
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 6 + 's';
        particle.style.animationDuration = (6 + Math.random() * 4) + 's';
        particlesContainer.appendChild(particle);
    }
}

function showLoading() { document.getElementById('loading').style.display = 'block'; document.getElementById('result').style.display = 'none'; }
function hideLoading() { document.getElementById('loading').style.display = 'none'; }

function showResult(data, isError = false) {
    hideLoading();
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = 'block';
    resultDiv.className = isError ? 'result-card result-error' : 'result-card result-success';
    
    if (isError) {
        resultDiv.innerHTML = `
            <div class="result-header">
                <i class="fas fa-exclamation-triangle result-icon" style="color: #dc3545;"></i>
                <h4 class="result-title">Analysis Error</h4>
            </div>
            <div class="analysis-text">${data.error || 'Unknown error occurred'}</div>
        `;
        return;
    }

    // Normal success path: try to render structured analysis data if available
    const status = data.status || (data.verdict ? 'success' : 'unknown');
    
    if (status === 'success' && (data.verdict || data.final_verdict || data.analysis_summary || data.ml_model || data.ml_analysis)) {
        const verdict = data.verdict || data.final_verdict || 'UNKNOWN';
        const score = (data.analysis_summary && typeof data.analysis_summary.combined_risk_score !== 'undefined')
            ? data.analysis_summary.combined_risk_score
            : (data.combined_score ?? 'N/A');
        const ml = data.ml_model || data.ml_analysis || null;
        const llm = data.gemini || data.llm || null;

        // Choose icon and color by verdict
        let icon = 'fa-question-circle';
        let color = '#ffc107';
        if (/LEGITIMAT|SAFE|CLEAN|BENIGN/i.test(verdict)) { icon = 'fa-check-circle'; color = '#28a745'; }
        else if (/SUSPIC|WARN/i.test(verdict)) { icon = 'fa-exclamation-triangle'; color = '#ff8c00'; }
        else if (/FRAUD|PHISH|MALICIOUS|MALWARE/i.test(verdict)) { icon = 'fa-skull-crossbones'; color = '#dc3545'; }

        let mlHtml = '';
        if (ml) {
            const pred = ml.prediction !== undefined ? ml.prediction : (ml.label || 'model');
            const proba = (ml.proba || ml.probability || ml.confidence);
            let probaText = 'N/A';
            
            if (typeof proba === 'number') {
                probaText = `${proba.toFixed(1)}%`;
            } else if (Array.isArray(proba) && proba.length >= 2) {
                probaText = `${(Math.max(...proba) * 100).toFixed(1)}%`;
            }
            
            const predText = ml.classification || (pred === 1 ? 'Malware' : pred === 0 ? 'Benign' : pred);
            mlHtml = `
                <div style="margin-top:10px;font-weight:600">Model detected: ${predText} &nbsp; <span style="font-weight:500;color:#666;">(Confidence: ${probaText})</span></div>
            `;
        }

        let llmHtml = '';
        if (llm && typeof llm === 'object') {
            const llmVerdict = llm.verdict || llm.label || null;
            if (llmVerdict) llmHtml = `<div style="margin-top:6px;font-size:13px;color:#444">LLM assistant: ${llmVerdict}</div>`;
        }

        // Evidence block (show a concise summary if present)
        let evidenceHtml = '';
        // Prepare safety variables outside inner blocks so they are available later when rendering displayedVerdict
        let safety = null;
        let badgeColor = null;
        let safetyBadgeHtml = '';
        if (data.analysis_summary) {
            const as = data.analysis_summary;
            evidenceHtml = `<div style="margin-top:12px;">
                <strong>Combined risk score:</strong> ${score}<br/>
                <strong>Heuristic score:</strong> ${as.heuristic_score ?? 'N/A'} &nbsp; <strong>ML score:</strong> ${as.ml_score ?? 'N/A'}
            </div>`;
        } else if (data.file_info) {
            // APK analysis result - Mobile App Security Scan
            const fileInfo = data.file_info;
            const secRec = data.security_recommendation || {};
            
            // Compute safety status
            safety = 'Unknown';
            badgeColor = '#6c757d';
            let glassBackground = 'rgba(255, 255, 255, 0.15)';
            let borderColor = 'rgba(255, 255, 255, 0.2)';
            
            const combinedScoreNum = (typeof score === 'number') ? score : (typeof score === 'string' && !isNaN(Number(score)) ? Number(score) : null);
            const mlClass = ml && (ml.classification || ml.prediction || ml.label) ? String(ml.classification || ml.prediction || ml.label).toLowerCase() : null;
            const verdictStr = verdict ? String(verdict).toLowerCase() : '';

            // Priority 1: Check ML classification (most reliable)
            if (mlClass && /benign|clean|0|false/.test(mlClass)) {
                safety = 'Safe'; 
                badgeColor = '#10b981';
                glassBackground = 'rgba(16, 185, 129, 0.1)';
                borderColor = 'rgba(16, 185, 129, 0.3)';
            } else if (mlClass && /malware|malicious|1|true/.test(mlClass)) {
                safety = 'Unsafe'; 
                badgeColor = '#ef4444';
                glassBackground = 'rgba(239, 68, 68, 0.1)';
                borderColor = 'rgba(239, 68, 68, 0.3)';
            } 
            // Priority 2: Check backend verdict
            else if (/benign|safe|legit|clean/.test(verdictStr)) {
                safety = 'Safe'; 
                badgeColor = '#10b981';
                glassBackground = 'rgba(16, 185, 129, 0.1)';
                borderColor = 'rgba(16, 185, 129, 0.3)';
            } else if (/malware|malicious|phish|fraud|suspicious|risk/.test(verdictStr)) {
                safety = 'Unsafe'; 
                badgeColor = '#ef4444';
                glassBackground = 'rgba(239, 68, 68, 0.1)';
                borderColor = 'rgba(239, 68, 68, 0.3)';
            } 
            // Priority 3: Fall back to combined score threshold
            else if (combinedScoreNum !== null) {
                if (combinedScoreNum >= 0.5) { 
                    safety = 'Unsafe'; 
                    badgeColor = '#ef4444';
                    glassBackground = 'rgba(239, 68, 68, 0.1)';
                    borderColor = 'rgba(239, 68, 68, 0.3)';
                } else { 
                    safety = 'Safe'; 
                    badgeColor = '#10b981';
                    glassBackground = 'rgba(16, 185, 129, 0.1)';
                    borderColor = 'rgba(16, 185, 129, 0.3)';
                }
            }

            // Create user-friendly explanation
            let riskExplanation = '';
            let safetyIcon = '';
            if (safety === 'Safe') {
                riskExplanation = '✅ This app appears safe to install based on our security analysis.';
                safetyIcon = '🛡️';
            } else if (safety === 'Unsafe') {
                riskExplanation = '⚠️ Warning: This app may contain malware or malicious code. Do not install.';
                safetyIcon = '🚨';
            } else {
                riskExplanation = '❓ Security status unclear. Please scan with additional tools before installing.';
                safetyIcon = '⚠️';
            }

            // Get confidence percentage
            const confidencePercent = ml && ml.confidence ? Math.round(ml.confidence) : 0;
            const riskPercent = combinedScoreNum !== null ? Math.round(combinedScoreNum * 100) : 0;

            evidenceHtml = `
                <div style="margin-top: 16px;">
                    <!-- Main Safety Card with Strong Background -->
                    <div style="
                        background: ${safety === 'Safe' ? 'linear-gradient(135deg, #10b981, #059669)' : safety === 'Unsafe' ? 'linear-gradient(135deg, #ef4444, #dc2626)' : 'linear-gradient(135deg, #f59e0b, #d97706)'};
                        border-radius: 20px;
                        padding: 24px;
                        margin-bottom: 20px;
                        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
                        color: white;
                        text-align: center;
                    ">
                        <!-- Status Badge -->
                        <div style="
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin-bottom: 16px;
                        ">
                            <div style="
                                background: rgba(255, 255, 255, 0.2);
                                color: white;
                                padding: 12px 24px;
                                border-radius: 50px;
                                font-size: 18px;
                                font-weight: 700;
                                display: flex;
                                align-items: center;
                                gap: 8px;
                                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
                                border: 2px solid rgba(255, 255, 255, 0.3);
                            ">
                                <span style="font-size: 20px;">${safetyIcon}</span>
                                ${safety.toUpperCase()}
                            </div>
                        </div>
                        
                        <!-- Explanation Text -->
                        <div style="
                            font-size: 16px;
                            font-weight: 500;
                            line-height: 1.6;
                            margin-bottom: 20px;
                            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
                        ">
                            ${riskExplanation}
                        </div>

                        <!-- Confidence Meter -->
                        ${confidencePercent > 0 ? `
                        <div style="margin-bottom: 16px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <span style="font-size: 14px; font-weight: 600;">AI Confidence</span>
                                <span style="font-size: 14px; font-weight: 700;">${confidencePercent}%</span>
                            </div>
                            <div style="
                                width: 100%;
                                height: 8px;
                                background: rgba(255, 255, 255, 0.3);
                                border-radius: 10px;
                                overflow: hidden;
                            ">
                                <div style="
                                    width: ${confidencePercent}%;
                                    height: 100%;
                                    background: rgba(255, 255, 255, 0.8);
                                    border-radius: 10px;
                                    transition: width 0.8s ease;
                                "></div>
                            </div>
                        </div>
                        ` : ''}
                    </div>

                    <!-- File Details Card -->
                    <div style="
                        background: rgba(255, 255, 255, 0.95);
                        border-radius: 16px;
                        padding: 20px;
                        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                    ">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; color: #374151;">
                            <div>
                                <div style="font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">📁 Filename</div>
                                <div style="font-size: 14px; font-weight: 500; word-break: break-all;">${fileInfo.filename || 'Unknown'}</div>
                            </div>
                            <div>
                                <div style="font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">📊 File Size</div>
                                <div style="font-size: 14px; font-weight: 500;">${fileInfo.size_mb || 'N/A'} MB</div>
                            </div>
                            ${riskPercent > 0 ? `
                            <div>
                                <div style="font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">⚡ Risk Score</div>
                                <div style="font-size: 14px; font-weight: 600; color: ${riskPercent >= 50 ? '#ef4444' : '#10b981'};">${riskPercent}%</div>
                            </div>
                            ` : ''}
                            <div>
                                <div style="font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">🔒 Recommendation</div>
                                <div style="font-size: 14px; font-weight: 500; color: ${secRec.install_safe ? '#10b981' : '#ef4444'};">
                                    ${secRec.install_safe ? 'Safe to Install' : 'Do Not Install'}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            evidenceHtml = `<pre style="margin-top:12px;white-space:pre-wrap;background:rgba(0,0,0,0.03);padding:12px;border-radius:8px;">${JSON.stringify(data, null, 2)}</pre>`;
        }

        // For APK responses, prefer the simple Safe/Unsafe label we computed above
        const analysisType = data.file_info ? 'Mobile App Security Analysis' : 'Website Threat Analysis';
        // displayedVerdict: for APK show 'Safe'/'Unsafe'/'Unknown' (friendly). For websites keep original verdict text.
        let displayedVerdict = verdict;
        if (data.file_info) {
            // Use the safety value we computed in the APK section, fallback to verdict analysis
            if (safety) {
                displayedVerdict = safety;
            } else {
                // Fallback: analyze the verdict directly
                if (/benign|safe|legit|clean/i.test(verdict)) {
                    displayedVerdict = 'Safe';
                    badgeColor = '#10b981';
                } else if (/malware|malicious|phish|fraud|suspicious|risk/i.test(verdict)) {
                    displayedVerdict = 'Unsafe';
                    badgeColor = '#ef4444';
                } else {
                    displayedVerdict = 'Unknown';
                    badgeColor = '#6c757d';
                }
            }
            
            // override the color/icon for APK to match the badge we computed
            color = badgeColor || color;
            if (displayedVerdict === 'Safe') icon = 'fa-shield-alt';
            else if (displayedVerdict === 'Unsafe') icon = 'fa-exclamation-triangle';
            else icon = 'fa-question-circle';
        }

        resultDiv.innerHTML = `
            <div class="result-header" style="
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.95), rgba(255, 255, 255, 0.85));
                backdrop-filter: blur(15px);
                -webkit-backdrop-filter: blur(15px);
                border-radius: 20px 20px 0 0;
                padding: 24px;
                display: flex;
                align-items: center;
                gap: 16px;
                margin-bottom: 0;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
                border: 1px solid rgba(255, 255, 255, 0.6);
            ">
                <div style="
                    background: ${color};
                    color: white;
                    width: 48px;
                    height: 48px;
                    border-radius: 12px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
                ">
                    <i class="fas ${icon}" style="font-size: 20px;"></i>
                </div>
                <h4 class="result-title" style="
                    margin: 0;
                    color: #1f2937;
                    font-size: 22px;
                    font-weight: 700;
                    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
                ">${analysisType}</h4>
            </div>
            <div class="analysis-text" style="
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.92), rgba(255, 255, 255, 0.88));
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border-top: none;
                border-radius: 0 0 20px 20px;
                padding: 28px;
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.6);
                border-top: none;
                min-height: 120px;
            ">
                <div style="font-size:20px;font-weight:800;margin-bottom:16px;color:#1f2937;text-align:center;text-transform:uppercase;letter-spacing:1px;">
                    Status: <span style="color:${color}; text-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">${displayedVerdict}</span>
                </div>
                ${data.file_info ? '' : `<div style="font-size:14px;color:#4b5563;text-align:center;margin-bottom:20px;font-weight:500;">Combined risk score: <strong style="color:${color};">${score}</strong></div>`}
                ${mlHtml}
                ${llmHtml}
                ${evidenceHtml}
            </div>
        `;
        return;
    }

    // Fallback: unexpected response
    resultDiv.innerHTML = `
        <div class="result-header">
            <i class="fas fa-question-circle result-icon" style="color: #ffc107;"></i>
            <h4 class="result-title">Unexpected Response</h4>
        </div>
        <pre class="analysis-text">${JSON.stringify(data, null, 2)}</pre>
    `;
}

async function analyzeWebsite() {
    const url = document.getElementById('websiteUrl').value.trim();
    if (!url) { alert('Please enter a website URL'); return; }
    showLoading();
    // Clear previous result to avoid stale UI and search for the correct button
    const resultDiv = document.getElementById('result');
    if (resultDiv) { resultDiv.style.display = 'none'; resultDiv.innerHTML = ''; }

    // Robustly locate the analyze button associated with the website input.
    let analyzeBtn = null;
    const inputEl = document.getElementById('websiteUrl');
    if (inputEl) {
        // Walk up to the containing .analysis-card then find its .analyze-btn
        let p = inputEl.parentElement;
        while (p && !p.classList.contains('analysis-card')) p = p.parentElement;
        if (p) analyzeBtn = p.querySelector('.analyze-btn');
    }
    // Fallback: use the first analyze button on the page (site-level UI)
    if (!analyzeBtn) analyzeBtn = document.querySelector('.analysis-card .analyze-btn');
    if (analyzeBtn) analyzeBtn.disabled = true;
    try {
        const response = await fetch(`${API_BASE}/analyze/website`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url })
        });
        let data;
        try { data = await response.json(); } catch (err) { showResult({ error: 'Invalid JSON response from server' }, true); return; }
        if (response.ok && (data.status === 'success' || data.verdict)) showResult(data); else showResult(data, true);
    } catch (error) { showResult({ error: `Network error: ${error.message}` }, true); }
    finally {
        // Ensure loading UI hidden and button re-enabled
        hideLoading();
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
}

async function analyzeAPK() {
    const fileInput = document.getElementById('apkFile');
    const appName = document.getElementById('appName').value.trim();
    
    if (!fileInput.files || fileInput.files.length === 0) {
        alert('Please select an APK file to analyze');
        return;
    }
    
    const file = fileInput.files[0];
    
    // Validate file type
    if (!file.name.toLowerCase().endsWith('.apk')) {
        alert('Please select a valid APK file (.apk extension required)');
        return;
    }
    
    // Validate file size (50MB limit)
    const maxSize = 50 * 1024 * 1024; // 50MB
    if (file.size > maxSize) {
        alert('File too large. Please select an APK file smaller than 50MB');
        return;
    }
    
    showLoading();
    
    // Clear previous result
    const resultDiv = document.getElementById('result');
    if (resultDiv) { resultDiv.style.display = 'none'; resultDiv.innerHTML = ''; }

    // Find and disable the analyze button
    let analyzeBtn = null;
    const fileInputEl = document.getElementById('apkFile');
    if (fileInputEl) {
        let p = fileInputEl.parentElement;
        while (p && !p.classList.contains('analysis-card')) p = p.parentElement;
        if (p) analyzeBtn = p.querySelector('.analyze-btn');
    }
    if (!analyzeBtn) analyzeBtn = document.querySelector('.analysis-card .analyze-btn');
    if (analyzeBtn) analyzeBtn.disabled = true;
    
    try {
        // Create FormData for file upload
        const formData = new FormData();
        formData.append('file', file);  // Backend expects 'file' field name
        if (appName) formData.append('app_name', appName);
        
        const response = await fetch(`${API_BASE}/analyze/apk-file`, {
            method: 'POST',
            body: formData
        });
        
        let data;
        try { 
            data = await response.json(); 
        } catch (err) { 
            showResult({ error: 'Invalid JSON response from server' }, true); 
            return; 
        }
        
        if (response.ok && (data.status === 'success' || data.verdict)) {
            showResult(data);
        } else {
            showResult(data, true);
        }
    } catch (error) {
        showResult({ error: `Network error: ${error.message}` }, true);
    } finally {
        hideLoading();
        if (analyzeBtn) analyzeBtn.disabled = false;
        // Reset the file input so the user can upload another APK without reloading.
        try {
            const fileEl = document.getElementById('apkFile');
            if (fileEl) {
                fileEl.value = null;
            }
        } catch (e) { /* ignore reset errors */ }
    }
}

async function analyzeApp() {
    // Legacy function - redirect to APK analysis
    showNotification('Please use the APK file upload above for mobile app analysis');
}

// Add simple helpers used by the page
function showNotification(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `position: fixed; top: 20px; right: 20px; background: linear-gradient(135deg, #00ff41, #008f2f); color: #000; padding: 15px 20px; border-radius: 10px; z-index: 10000; font-weight: 600; box-shadow: 0 5px 20px rgba(0, 255, 65, 0.4); animation: slideInRight 0.5s ease-out;`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => { notification.style.animation = 'slideOutRight 0.5s ease-in forwards'; setTimeout(() => notification.remove(), 500); }, 3000);
}

// Bind events on load
window.addEventListener('load', () => {
    createParticles();
    document.getElementById('websiteUrl')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') analyzeWebsite(); });
    document.getElementById('appName')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') analyzeAPK(); });
    
    // Initialize authentication system first
    initializeAuth();
    
    // Initialize sidebar toggle
    initializeSidebar();
    
    // Try to restore user session (will show auth form if no valid session)
    restoreUserSession();
});

// Authentication and User Management System
let currentUser = null;
let sessionToken = null;

function initializeAuth() {
    console.log('🔐 Initializing authentication system');
    
    // Keep main container visible by default
    const mainContainer = document.querySelector('.container');
    if (mainContainer) mainContainer.style.display = 'block';
    
    // Set up form event listeners
    const signInForm = document.getElementById('signInForm');
    const signUpForm = document.getElementById('signUpForm');
    
    if (signInForm) {
        signInForm.addEventListener('submit', handleSignIn);
    }
    
    if (signUpForm) {
        signUpForm.addEventListener('submit', handleSignUp);
    }
    
    // Set up navigation buttons
    const showSignUpBtn = document.getElementById('showSignUp');
    const showSignInBtn = document.getElementById('showSignIn');
    const signOutBtn = document.getElementById('signOutBtn');
    
    if (showSignUpBtn) {
        showSignUpBtn.addEventListener('click', () => showAuthForm('signup'));
    }
    
    if (showSignInBtn) {
        showSignInBtn.addEventListener('click', () => showAuthForm('signin'));
    }
    
    if (signOutBtn) {
        signOutBtn.addEventListener('click', handleSignOut);
    }
}

function initializeSidebar() {
    console.log('📋 Initializing sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('cyberSidebar');
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
            console.log('📋 Sidebar toggled');
        });
    }
}

async function handleSignIn(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const login = formData.get('login');
    const password = formData.get('password');
    
    if (!login || !password) {
        showAuthError('Please fill in all fields');
        return;
    }
    
    try {
        showAuthLoading(true);
        
        const response = await fetch(`${API_BASE}/auth/signin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ login, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            console.log('✅ Sign in successful');
            
            // Store user data and session
            currentUser = data.user;
            sessionToken = data.session_token;
            localStorage.setItem('ciphercop_session', sessionToken);
            localStorage.setItem('ciphercop_user', JSON.stringify(currentUser));
            
            // Show success message
            showAuthSuccess('Signed in successfully!');
            
            // Switch to dashboard
            setTimeout(() => {
                showDashboard();
            }, 1000);
            
        } else {
            showAuthError(data.error || 'Sign in failed');
        }
    } catch (error) {
        console.error('❌ Sign in error:', error);
        showAuthError('Network error. Please try again.');
    } finally {
        showAuthLoading(false);
    }
}

async function handleSignUp(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const username = formData.get('username');
    const email = formData.get('email');
    const password = formData.get('password');
    const confirmPassword = formData.get('confirmPassword');
    
    if (!username || !email || !password || !confirmPassword) {
        showAuthError('Please fill in all fields');
        return;
    }
    
    if (password !== confirmPassword) {
        showAuthError('Passwords do not match');
        return;
    }
    
    if (password.length < 6) {
        showAuthError('Password must be at least 6 characters long');
        return;
    }
    
    try {
        showAuthLoading(true);
        
        const response = await fetch(`${API_BASE}/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            console.log('✅ Sign up successful');
            
            // Store user data and session
            currentUser = data.user;
            sessionToken = data.session_token;
            localStorage.setItem('ciphercop_session', sessionToken);
            localStorage.setItem('ciphercop_user', JSON.stringify(currentUser));
            
            // Show success message
            showAuthSuccess('Account created successfully! Welcome to CipherCop!');
            
            // Switch to dashboard
            setTimeout(() => {
                showDashboard();
            }, 1000);
            
        } else {
            showAuthError(data.error || 'Sign up failed');
        }
    } catch (error) {
        console.error('❌ Sign up error:', error);
        showAuthError('Network error. Please try again.');
    } finally {
        showAuthLoading(false);
    }
}

async function handleSignOut() {
    try {
        // Support both key names used in the app
        const tokenKeys = ['ciphercop_session', 'authToken'];
        let token = sessionToken;
        if (!token) {
            for (const k of tokenKeys) {
                const t = localStorage.getItem(k);
                if (t) { token = t; break; }
            }
        }

        if (token) {
            await fetch(`${API_BASE}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ session_token: token })
            }).catch(e => console.warn('Logout network error', e));
        }
    } catch (error) {
        console.error('❌ Sign out error:', error);
    }
    
    // Clear local storage and reset state
    currentUser = null;
    sessionToken = null;
    try { localStorage.removeItem('ciphercop_session'); } catch(_) {}
    try { localStorage.removeItem('ciphercop_user'); } catch(_) {}
    try { localStorage.removeItem('authToken'); } catch(_) {}
    try { localStorage.removeItem('ciphercop_user'); } catch(_) {}
    
    // Show sign in form
    showAuthForm('signin');
    
    console.log('🚪 Signed out successfully');
}

async function restoreUserSession() {
    console.log('🔄 Attempting to restore user session...');
    
    const storedToken = localStorage.getItem('ciphercop_session');
    const storedUser = localStorage.getItem('ciphercop_user');
    
    console.log('📦 Stored token:', storedToken ? 'Found' : 'None');
    console.log('📦 Stored user:', storedUser ? 'Found' : 'None');
    
    if (!storedToken || !storedUser) {
        // No session, show auth form
        console.log('❌ No session found, showing auth form');
        showAuthForm('signin');
        return;
    }
    
    try {
        console.log('🔍 Validating session with backend...');
        // Validate session with backend
        const response = await fetch(`${API_BASE}/auth/validate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ session_token: storedToken })
        });
        
        const data = await response.json();
        
        if (response.ok && data.valid) {
            // Session is valid, restore user
            currentUser = data.user;
            sessionToken = storedToken;
            
            console.log('✅ Session restored for user:', currentUser.username);
            showDashboard();
        } else {
            // Session invalid, clear storage and show auth
            console.log('❌ Session invalid, clearing storage');
            localStorage.removeItem('ciphercop_session');
            localStorage.removeItem('ciphercop_user');
            showAuthForm('signin');
        }
    } catch (error) {
        console.error('❌ Session validation error:', error);
        // On error, clear storage and show auth
        console.log('🧹 Clearing storage due to error');
        localStorage.removeItem('ciphercop_session');
        localStorage.removeItem('ciphercop_user');
        showAuthForm('signin');
    }
}

function showAuthForm(type) {
    console.log('🔐 Showing auth form:', type);
    
    const authSection = document.getElementById('authSection');
    const dashboardSection = document.getElementById('dashboard-section');
    const signInForm = document.getElementById('signInForm');
    const signUpForm = document.getElementById('signUpForm');
    const mainContainer = document.querySelector('.container');
    
    if (!authSection || !dashboardSection) {
        console.error('❌ Auth sections not found');
        return;
    }
    
    // Show auth section, hide dashboard, keep main container visible
    authSection.style.display = 'block';
    dashboardSection.style.display = 'none';
    if (mainContainer) mainContainer.style.display = 'block';
    
    console.log('✅ Auth section visible, dashboard hidden');
    
    // Show appropriate form
    if (type === 'signup') {
        if (signInForm) signInForm.style.display = 'none';
        if (signUpForm) {
            signUpForm.style.display = 'block';
            signUpForm.classList.remove('hidden');
        }
        console.log('📝 Sign up form visible');
    } else {
        if (signUpForm) {
            signUpForm.style.display = 'none';
            signUpForm.classList.add('hidden');
        }
        if (signInForm) signInForm.style.display = 'block';
        console.log('🔑 Sign in form visible');
    }
    
    // Clear any previous messages
    clearAuthMessages();
}

async function showDashboard() {
    // Redirect to dashboard page instead of showing inline dashboard
    console.log('🚀 Redirecting to dashboard page...');
    window.location.href = 'dashboard.html';
}

function updateUserProfile() {
    const usernameDisplay = document.getElementById('usernameDisplay');
    const emailDisplay = document.getElementById('emailDisplay');
    
    if (usernameDisplay && currentUser) {
        usernameDisplay.textContent = currentUser.username;
    }
    
    if (emailDisplay && currentUser) {
        emailDisplay.textContent = currentUser.email;
    }
}

async function loadDashboardData() {
    if (!sessionToken) return;
    
    try {
        const response = await fetch(`${API_BASE}/dashboard/data`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ session_token: sessionToken })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            updateDashboardUI(data.dashboard);
        } else {
            console.error('❌ Failed to load dashboard data:', data.error);
        }
    } catch (error) {
        console.error('❌ Dashboard data error:', error);
    }
}

function updateDashboardUI(dashboardData) {
    // Update analytics cards
    const totalScansElement = document.getElementById('totalScans');
    const threatsBlockedElement = document.getElementById('threatsBlocked');
    const lastScanElement = document.getElementById('lastScan');
    
    if (totalScansElement) {
        totalScansElement.textContent = dashboardData.total_scans || 0;
    }
    
    if (threatsBlockedElement) {
        threatsBlockedElement.textContent = dashboardData.threats_blocked || 0;
    }
    
    if (lastScanElement && dashboardData.last_scan_date) {
        const lastScanDate = new Date(dashboardData.last_scan_date);
        lastScanElement.textContent = lastScanDate.toLocaleDateString();
    }
    
    // Update recent activity
    updateRecentActivity(dashboardData.recent_scans || []);
    
    console.log('📊 Dashboard UI updated with data:', dashboardData);
}

function updateRecentActivity(recentScans) {
    const activityList = document.getElementById('activityList');
    if (!activityList) return;
    
    if (recentScans.length === 0) {
        activityList.innerHTML = '<div class="activity-item">No recent activity</div>';
        return;
    }
    
    activityList.innerHTML = recentScans.map(scan => {
        const scanDate = new Date(scan.scan_date);
        const statusColor = scan.verdict === 'LEGITIMATE' ? '#28a745' : 
                           scan.verdict === 'SUSPICIOUS' ? '#ffc107' : '#dc3545';
        
        return `
            <div class="activity-item">
                <div class="activity-url">${scan.url}</div>
                <div class="activity-meta">
                    <span class="activity-verdict" style="color: ${statusColor}">
                        ${scan.verdict}
                    </span>
                    <span class="activity-date">${scanDate.toLocaleDateString()}</span>
                </div>
            </div>
        `;
    }).join('');
}

function showAuthLoading(show) {
    const signInBtn = document.querySelector('#signInForm button[type="submit"]');
    const signUpBtn = document.querySelector('#signUpForm button[type="submit"]');
    
    if (signInBtn) {
        signInBtn.textContent = show ? 'Signing In...' : 'Sign In';
        signInBtn.disabled = show;
    }
    
    if (signUpBtn) {
        signUpBtn.textContent = show ? 'Creating Account...' : 'Sign Up';
        signUpBtn.disabled = show;
    }
}

function showAuthError(message) {
    const errorDiv = document.getElementById('authError');
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        errorDiv.style.color = '#dc3545';
    }
}

function showAuthSuccess(message) {
    const errorDiv = document.getElementById('authError');
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        errorDiv.style.color = '#28a745';
    }
}

function clearAuthMessages() {
    const errorDiv = document.getElementById('authError');
    if (errorDiv) {
        errorDiv.style.display = 'none';
    }
}

// Override the existing analyzeWebsite function to support user tracking
const originalAnalyzeWebsite = window.analyzeWebsite;

window.analyzeWebsite = async function() {
    const urlInput = document.getElementById('websiteUrl');
    const url = urlInput?.value?.trim();
    
    if (!url) {
        alert('Please enter a URL to analyze');
        return;
    }
    
    showLoading();
    
    try {
        let endpoint = '/analyze/website';
        let requestBody = { url };
        
        // If user is authenticated, use the user-tracking endpoint
        if (sessionToken && currentUser) {
            endpoint = '/analyze/website/user';
            requestBody.session_token = sessionToken;
        }
        
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        const data = await response.json();
        showResult(data, !response.ok);
        
        // Refresh dashboard data if user is authenticated
        if (sessionToken && currentUser && data.status === 'success') {
            setTimeout(loadDashboardData, 1000);
        }
        
    } catch (error) {
        showResult({ error: 'Network error occurred' }, true);
    }
};

// Make functions globally available for onclick handlers
window.analyzeWebsite = analyzeWebsite;
window.analyzeAPK = analyzeAPK;
window.analyzeApp = analyzeApp;
