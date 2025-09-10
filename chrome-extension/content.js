// Content script for injecting warnings and overlays
class CipherCopContentScript {
  constructor() {
    this.warningShown = false;
    this.setupMessageListener();
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      console.debug('CipherCop content script received message:', request, sender);
      if (request.action === 'showWarning') {
        try {
          this.showWarningOverlay(request.data);
          sendResponse({ success: true });
        } catch (e) {
          console.error('Error showing warning overlay:', e);
          sendResponse({ success: false, error: String(e) });
        }
      }
    });
  }

  showWarningOverlay(data) {
    console.debug('showWarningOverlay called with data:', data);
    if (this.warningShown) {
      console.debug('Warning overlay already shown, updating content instead of re-creating');
      // Optionally update existing overlay content here; for now just return
      return;
    }
    this.warningShown = true;

    const intensity = data.intensity || 'MEDIUM';
    const confidence = data.confidence || 0;
    const sources = data.sources || [];
    
    // Different colors based on intensity
    let bgGradient = 'linear-gradient(135deg, #ff6b6b, #ff8e8e)'; // Default red
    let icon = '⚠️';
    let canProceed = data.canProceed !== false;
    
    switch (intensity) {
      case 'STRONG':
        bgGradient = 'linear-gradient(135deg, #dc3545, #e74c3c)'; // Strong red
        icon = '🚨';
        canProceed = false;
        break;
      case 'MEDIUM':
        bgGradient = 'linear-gradient(135deg, #ff6b6b, #ff8e8e)'; // Medium red
        icon = '⚠️';
        break;
      case 'LIGHT':
        bgGradient = 'linear-gradient(135deg, #ffc107, #ffdb4d)'; // Yellow warning
        icon = '⚠️';
        break;
    }

    // Create warning overlay with advanced design
    const overlay = document.createElement('div');
    overlay.id = 'ciphercop-warning-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(135deg, rgba(0, 0, 0, 0.9), rgba(20, 20, 20, 0.95));
      backdrop-filter: blur(10px);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
      animation: overlayFadeIn 0.3s ease-out;
    `;

    const warningBox = document.createElement('div');
    warningBox.style.cssText = `
      background: linear-gradient(145deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05));
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255,255,255,0.2);
      color: white;
      padding: 50px 40px;
      border-radius: 24px;
      max-width: 650px;
      width: 90%;
      text-align: center;
      box-shadow: 
        0 25px 50px -12px rgba(0, 0, 0, 0.8),
        0 0 0 1px rgba(255,255,255,0.1),
        inset 0 1px 0 rgba(255,255,255,0.2);
      animation: warningBoxSlide 0.5s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
      overflow: hidden;
    `;

    warningBox.innerHTML = `
      <div style="position: absolute; top: 0; left: 0; right: 0; height: 4px; background: ${bgGradient}; border-radius: 24px 24px 0 0;"></div>
      
      <div style="
        width: 120px; 
        height: 120px; 
        background: ${bgGradient}; 
        border-radius: 50%; 
        margin: 0 auto 30px; 
        display: flex; 
        align-items: center; 
        justify-content: center;
        font-size: 48px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        animation: iconPulse 2s ease-in-out infinite;
      ">${icon}</div>
      
      <h1 style="
        margin-bottom: 16px; 
        font-size: 32px; 
        font-weight: 700;
        background: ${bgGradient};
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-shadow: none;
      ">Security Alert</h1>
      
      <h2 style="
        margin-bottom: 24px; 
        font-size: 18px; 
        font-weight: 500;
        color: rgba(255,255,255,0.9);
        letter-spacing: 0.5px;
      ">${intensity} Risk Detected</h2>
      
      <div style="
        background: rgba(255,255,255,0.08);
        border: 1px solid rgba(255,255,255,0.12);
        padding: 24px;
        border-radius: 16px;
        margin: 24px 0;
        text-align: left;
      ">
        <p style="margin: 0 0 12px 0; font-size: 16px; line-height: 1.6; color: rgba(255,255,255,0.9);">
          <strong style="color: #fff;">Potentially ${data.type} Website Detected</strong>
        </p>
        <p style="margin: 0; font-size: 14px; color: rgba(255,255,255,0.7); word-break: break-all;">
          <strong>URL:</strong> ${data.url}
        </p>
      </div>
      
      ${confidence > 0 ? `
        <div style="
          background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05));
          border: 1px solid rgba(255,255,255,0.15);
          padding: 20px;
          border-radius: 12px;
          margin: 20px 0;
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          text-align: center;
        ">
          <div>
            <div style="font-size: 24px; font-weight: 700; color: #fff; margin-bottom: 4px;">${confidence}%</div>
            <div style="font-size: 12px; color: rgba(255,255,255,0.7); text-transform: uppercase; letter-spacing: 1px;">Threat Confidence</div>
          </div>
          ${sources.length > 0 ? `
            <div>
              <div style="font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 4px;">${sources.length}</div>
              <div style="font-size: 12px; color: rgba(255,255,255,0.7); text-transform: uppercase; letter-spacing: 1px;">Detection Sources</div>
            </div>
          ` : `
            <div>
              <div style="font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 4px;">Model</div>
              <div style="font-size: 12px; color: rgba(255,255,255,0.7); text-transform: uppercase; letter-spacing: 1px;">Model detected</div>
            </div>
          `}
        </div>
      ` : ''}
      
      <div style="margin: 32px 0 24px; display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
        <button id="ciphercop-goback" style="
          background: linear-gradient(135deg, #10b981, #059669);
          color: white;
          border: none;
          padding: 16px 32px;
          border-radius: 12px;
          cursor: pointer;
          font-size: 16px;
          font-weight: 600;
          min-width: 160px;
          transition: all 0.2s ease;
          box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 20px rgba(16, 185, 129, 0.4)'"
           onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 12px rgba(16, 185, 129, 0.3)'">
          🛡️ Go Back Safely
        </button>
        
        ${canProceed ? `
          <button id="ciphercop-proceed" style="
            background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05));
            color: rgba(255,255,255,0.9);
            border: 1px solid rgba(255,255,255,0.2);
            padding: 16px 32px;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            min-width: 160px;
            transition: all 0.2s ease;
          " onmouseover="this.style.background='rgba(255,255,255,0.15)'; this.style.transform='translateY(-2px)'"
             onmouseout="this.style.background='linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05))'; this.style.transform='translateY(0)'">
            ⚠️ Continue Anyway
          </button>
        ` : ''}
      </div>
      
      <div style="
        font-size: 12px; 
        color: rgba(255,255,255,0.5); 
        margin-top: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
      ">
        <span style="
          width: 8px;
          height: 8px;
          background: #10b981;
          border-radius: 50%;
          animation: statusBlink 2s ease-in-out infinite;
        "></span>
        Protected by CipherCop AI Security Engine
      </div>
    `;

    // Add enhanced CSS animations
    const style = document.createElement('style');
    style.textContent = `
      @keyframes overlayFadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      
      @keyframes warningBoxSlide {
        from { 
          transform: scale(0.8) translateY(20px); 
          opacity: 0; 
        }
        to { 
          transform: scale(1) translateY(0); 
          opacity: 1; 
        }
      }
      
      @keyframes iconPulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.05); }
      }
      
      @keyframes statusBlink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
      }
      
      #ciphercop-warning-overlay * {
        box-sizing: border-box;
      }
    `;
    document.head.appendChild(style);

    overlay.appendChild(warningBox);
    document.body.appendChild(overlay);

    // Add event listeners with enhanced interactions
    const proceedBtn = document.getElementById('ciphercop-proceed');
    const goBackBtn = document.getElementById('ciphercop-goback');
    
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        overlay.style.animation = 'overlayFadeOut 0.3s ease-out forwards';
        setTimeout(() => {
          overlay.remove();
          this.warningShown = false;
        }, 300);
      });
    }

    goBackBtn.addEventListener('click', () => {
      overlay.style.animation = 'overlayFadeOut 0.3s ease-out forwards';
      setTimeout(() => {
        window.history.back();
      }, 300);
    });
    
    // Add fadeout animation
    style.textContent += `
      @keyframes overlayFadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
      }
    `;
  }

  // Inject real-time protection indicators
  injectProtectionIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'ciphercop-indicator';
    indicator.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: linear-gradient(135deg, #007bff, #0056b3);
      color: white;
      padding: 10px 15px;
      border-radius: 25px;
      font-size: 12px;
      font-weight: bold;
      z-index: 999998;
      box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);
      cursor: pointer;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    `;
    
    indicator.innerHTML = '🛡️ Protected by CipherCop';
    indicator.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'openPopup' });
    });
    
    document.body.appendChild(indicator);
  }
}

// Initialize content script
const cipherCopContent = new CipherCopContentScript();

// Inject protection indicator when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    cipherCopContent.injectProtectionIndicator();
  });
} else {
  cipherCopContent.injectProtectionIndicator();
}
