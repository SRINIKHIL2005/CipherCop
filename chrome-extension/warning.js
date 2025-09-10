// Warning page JavaScript (separate file to avoid CSP violations)
document.addEventListener('DOMContentLoaded', function() {
    // Parse URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');
    const reason = urlParams.get('reason');
    
    // Prevent infinite redirect loops by checking if URL contains warning pattern
    if (blockedUrl && blockedUrl.includes('warning.html')) {
        console.log('⚠️ Preventing infinite redirect loop');
        document.getElementById('blocked-url').textContent = 'Infinite redirect prevented';
        return;
    }
    
    // Display blocked URL
    document.getElementById('blocked-url').textContent = blockedUrl || 'Unknown URL';
    
    // Update warning message based on reason
    const warningMessage = document.getElementById('warning-message');
    const riskFactors = document.getElementById('risk-factors');
    
    switch (reason) {
        case 'FRAUDULENT':
            warningMessage.innerHTML = `
                <h2>🚨 Fraudulent Website Detected</h2>
                <p>This website appears to be designed to steal your personal information, passwords, or money. It may be impersonating a legitimate service.</p>
            `;
            riskFactors.innerHTML = `
                <li>Matches known phishing patterns</li>
                <li>Suspicious domain characteristics</li>
                <li>May contain malicious scripts</li>
            `;
            break;
        case 'BLACKLISTED':
            warningMessage.innerHTML = `
                <h2>🔒 Blacklisted Website</h2>
                <p>This website has been manually blocked due to confirmed malicious activity.</p>
            `;
            riskFactors.innerHTML = `
                <li>Previously reported as malicious</li>
                <li>Added to security blacklist</li>
                <li>Known to host malware or scams</li>
            `;
            break;
        case 'ADULT_CONTENT':
            warningMessage.innerHTML = `
                <h2>🔞 Adult Content Blocked</h2>
                <p>This website contains adult content and has been blocked based on your age settings.</p>
            `;
            riskFactors.innerHTML = `
                <li>Contains mature content</li>
                <li>Blocked by parental controls</li>
                <li>Age verification required</li>
            `;
            break;
        default:
            riskFactors.innerHTML = `
                <li>Unknown risk detected</li>
                <li>Potential security threat</li>
                <li>Blocked as a precautionary measure</li>
            `;
    }
    
    // Set up button event listeners
    document.getElementById('go-back-btn').addEventListener('click', function() {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = 'https://www.google.com';
        }
    });
    
    document.getElementById('proceed-btn').addEventListener('click', function() {
        // Show additional warning and notify background (so we can record override)
        if (confirm('Are you absolutely sure? This could put your device and personal information at risk.')) {
            if (blockedUrl && !blockedUrl.includes('warning.html')) {
                // Inform background of the user's override decision so it can be stored and logged
                try {
                    chrome.runtime.sendMessage({
                        action: 'overrideWarning',
                        url: blockedUrl,
                        reason: reason || 'UNKNOWN'
                    }, function(resp) {
                        // Navigate after background acknowledges
                        window.location.href = decodeURIComponent(blockedUrl);
                    });
                } catch (e) {
                    // Fallback: navigate directly
                    window.location.href = decodeURIComponent(blockedUrl);
                }
            }
        }
    });
    
    // Prevent accidental navigation
    window.addEventListener('beforeunload', function(e) {
        const activeElement = document.activeElement;
        if (activeElement && activeElement.tagName !== 'BUTTON') {
            e.preventDefault();
            e.returnValue = 'Are you sure you want to leave this safety page?';
        }
    });
});
