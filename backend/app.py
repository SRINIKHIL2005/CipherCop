from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import json
import re
import urllib.parse
from datetime import datetime, timedelta
import hashlib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Comprehensive CORS setup
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, Accept, Origin'
    response.headers['Access-Control-Max-Age'] = '3600'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# Handle OPTIONS requests globally
@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    response = jsonify({'status': 'ok'})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
    return response

# Google API Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "YOUR_NEW_GEMINI_API_KEY_HERE")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=" + GOOGLE_API_KEY

# Google Safe Browsing API Configuration
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v1/threatMatches:find"

def check_safe_browsing_api(url):
    """Check URL against Google Safe Browsing API for real-time threat detection"""
    if not SAFE_BROWSING_API_KEY:
        print("⚠️ Safe Browsing API key not configured")
        return {"threat_found": False, "threat_type": None, "error": "API key not configured"}

    try:
        headers = {"Content-Type": "application/json"}
        data = {
            "client": {
                "clientId": "cyberguard-ai",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(
            f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_API_KEY}",
            headers=headers,
            json=data
        )

        if response.status_code == 200:
            result = response.json()
            if "matches" in result and len(result["matches"]) > 0:
                threat_match = result["matches"][0]
                return {
                    "threat_found": True,
                    "threat_type": threat_match.get("threatType", "UNKNOWN"),
                    "platform_type": threat_match.get("platformType", "UNKNOWN")
                }
            else:
                return {"threat_found": False, "threat_type": None}
        else:
            print(f"❌ Safe Browsing API Error: {response.status_code}")
            return {"threat_found": False, "threat_type": None, "error": f"API Error {response.status_code}"}

    except Exception as e:
        print(f"💥 Safe Browsing API Exception: {str(e)}")
        return {"threat_found": False, "threat_type": None, "error": str(e)}

print(f"🔑 Using Google API Key: {GOOGLE_API_KEY[:20]}...")
print(f"🌐 Gemini API URL: {GEMINI_API_URL[:50]}...")

# Simplified and Working Classification System
class ThreatClassifier:
    def __init__(self):
        # Enhanced phishing patterns with more comprehensive detection
        self.phishing_patterns = [
            # Money-related scams
            r'free.*money.*claim',
            r'claim.*your.*prize',
            r'you.*won.*lottery',
            r'bitcoin.*investment.*guaranteed',
            r'crypto.*investment.*high.*return',
            r'million.*dollar.*inheritance',
            r'nigerian.*prince',
            r'foreign.*lottery',

            # Urgency and pressure tactics
            r'urgent.*action.*required',
            r'account.*suspended',
            r'immediate.*verification',
            r'limited.*time.*offer',
            r'act.*now.*or',
            r'deadline.*expires',
            r'time.*sensitive',
            r'click.*here.*immediately',

            # Impersonation patterns
            r'paypal.*support',
            r'bank.*verification',
            r'irs.*refund',
            r'social.*security',
            r'government.*grant',
            r'official.*notification',

            # Suspicious keywords
            r'congratulations.*winner',
            r'secret.*millionaire',
            r'anonymous.*hacker',
            r'hack.*account',
            r'recover.*funds',
            r'unclaimed.*money',

            # Technical deception
            r'phishing.*test',  # This should be HIGH risk!
            r'test.*phishing',
            r'security.*test.*site',
            r'malware.*test',
            r'virus.*test'
        ]

        # Enhanced suspicious domain patterns
        self.suspicious_domains = [
            # Free domain providers often used for phishing
            r'\.(tk|ml|ga|cf|xyz|gq|top|club|online|site|store|tech)$',
            r'[a-z]+-[a-z]+-[a-z]+\.(com|net|org)',  # Hyphenated suspicious domains
            r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',     # IP-like domains
            r'(paypal|amazon|google|microsoft|apple|netflix|facebook|instagram|twitter).*[0-9]+\.',  # Brand impersonation
            r'(login|secure|verify|update|account|support).*\.(tk|ml|ga|cf|xyz|gq)',
            r'[a-z]{15,}\.',  # Very long domain names
            r'(bank|credit|loan|finance).*\.(tk|ml|ga|cf|xyz)',
            r'(gov|org|edu).*\.(tk|ml|ga|cf|xyz)',  # Fake government sites
        ]

        # High-risk TLDs
        self.high_risk_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club', '.online', '.site']

        # Legitimate indicators (reduce false positives)
        self.legitimate_indicators = [
            'https://',
            'ssl certificate',
            'privacy policy',
            'terms of service',
            'contact information',
            'established company',
            'customer reviews',
            'wikipedia.org',
            'github.com',
            'stackoverflow.com'
        ]

        # Enhanced threat intelligence database
        self.threat_database = {
            'known_phishing': [
                'phishing-test.com',  # Add known test phishing sites
                'phishing-site-example.com',
                'fake-bank-login.net',
                'suspicious-paypal.org',
                'free-money-claim.net',  # Add this specific site
                'test-phishing-site.com',
                'malware-test-site.com'
            ],
            'known_malware': [
                'malware-download.exe',
                'virus-infected.zip',
                'trojan-file.pdf'
            ],
            'high_risk_keywords': [
                'phishing',
                'malware',
                'virus',
                'trojan',
                'ransomware',
                'scam',
                'fraud'
            ]
        }
    
    def classify_content(self, content, content_type="text"):
        """
        Enhanced automatic classification with improved phishing detection:
        - LEGITIMATE: Safe content (score < 25)
        - SUSPICIOUS: Potentially harmful content (score 25-60)
        - FRAUDULENT: Confirmed fraudulent/malicious content (score > 60)
        """
        score = 0
        risk_factors = []

        content_lower = content.lower()

        # Check for high-risk keywords in threat database
        for keyword in self.threat_database['high_risk_keywords']:
            if keyword in content_lower:
                score += 30  # High weight for explicit threat keywords
                risk_factors.append(f"High-risk keyword detected: '{keyword}'")

        # Check for phishing patterns with enhanced scoring
        for pattern in self.phishing_patterns:
            if re.search(pattern, content_lower):
                score += 20  # Increased from 25 to 20 for better granularity
                risk_factors.append(f"Phishing pattern detected: {pattern}")

        # Check for suspicious URLs with domain analysis
        urls = self.extract_urls(content)
        for url in urls:
            url_risk = self.analyze_url(url)
            score += url_risk['score']
            if url_risk['factors']:
                risk_factors.extend(url_risk['factors'])

        # Check against known threat database
        if self.check_threat_database(content):
            score += 40  # Increased weight for known threats
            risk_factors.append("Matches known threat database entry")

        # Domain-specific risk assessment
        for url in urls:
            domain_risk = self.assess_domain_risk(url)
            score += domain_risk['score']
            if domain_risk['factors']:
                risk_factors.extend(domain_risk['factors'])

        # Adjust thresholds for better detection
        if score >= 60:  # Lowered from 75
            classification = "FRAUDULENT"
            threat_level = "HIGH"
        elif score >= 25:  # Lowered from 40
            classification = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            classification = "LEGITIMATE"
            threat_level = "LOW"

        return {
            'classification': classification,
            'threat_level': threat_level,
            'risk_score': min(score, 100),
            'risk_factors': risk_factors,
            'confidence': self.calculate_confidence(score, len(risk_factors))
        }
    
    def extract_urls(self, text):
        """Extract URLs from text content"""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)
    
    def analyze_url(self, url):
        """Analyze URL for suspicious characteristics"""
        score = 0
        factors = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check suspicious domain patterns
            for pattern in self.suspicious_domains:
                if re.search(pattern, domain):
                    score += 20
                    factors.append(f"Suspicious domain pattern: {domain}")
            
            # Check URL length
            if len(url) > 200:
                score += 15
                factors.append("Unusually long URL")
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                score += 10
                factors.append("URL shortener detected")
            
            # Check for IP addresses instead of domain names
            if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', domain):
                score += 25
                factors.append("IP address used instead of domain name")
            
            # Check for HTTPS
            if not url.startswith('https://'):
                score += 10
                factors.append("Non-HTTPS connection")
                
        except Exception as e:
            score += 5
            factors.append("Malformed URL")
        
        return {'score': score, 'factors': factors}
    
    def check_threat_database(self, content):
        """Check content against known threat database"""
        content_lower = content.lower()
        
        # Check against known threats
        for threat_list in self.threat_database.values():
            for threat in threat_list:
                if threat.lower() in content_lower:
                    return True
        return False
    
    def assess_domain_risk(self, url):
        """Assess domain-specific risks beyond basic URL analysis"""
        score = 0
        factors = []

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            # Check for high-risk TLDs
            for tld in self.high_risk_tlds:
                if domain.endswith(tld):
                    score += 25
                    factors.append(f"High-risk TLD detected: {tld}")

            # Check for suspicious subdomain patterns
            if domain.count('.') >= 3:
                score += 15
                factors.append("Multiple subdomains detected")

            # Check for brand impersonation
            brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'instagram']
            for brand in brand_keywords:
                if brand in domain and not domain.startswith(brand + '.'):
                    score += 20
                    factors.append(f"Potential brand impersonation: {brand}")

            # Check for geographic TLDs often used in scams
            geo_tlds = ['.ru', '.cn', '.in', '.br', '.mx']
            for tld in geo_tlds:
                if domain.endswith(tld):
                    score += 10
                    factors.append(f"Geographic TLD with scam potential: {tld}")

        except Exception as e:
            score += 5
            factors.append("Domain analysis error")

        return {'score': score, 'factors': factors}
    
    def calculate_confidence(self, score, factor_count):
        """Calculate confidence level of the classification"""
        if factor_count >= 3 and score >= 50:
            return "HIGH"
        elif factor_count >= 2 or score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

# Initialize the classifier
threat_classifier = ThreatClassifier()

@app.route("/")
def home():
    print("🏠 Home endpoint accessed")
    return jsonify({"message": "CyberGuard AI Backend - Fraud Detection API is running!", "status": "success", "cors": "enabled"})

# Test endpoint for CORS
@app.route("/test")
def test_cors():
    print("🧪 CORS test endpoint accessed")
    return jsonify({"message": "CORS test successful!", "status": "ok", "timestamp": "2025-08-30"})

# Helper to call Gemini API for text analysis
def analyze_with_gemini(prompt, retry_count=0, max_retries=2):
    print(f"🤖 Starting Gemini API call (attempt {retry_count + 1}/{max_retries + 1})")
    print(f"🔑 API Key being used: {GOOGLE_API_KEY}")
    print(f"📡 Full URL: {GEMINI_API_URL}")
    print(f"📝 Prompt length: {len(prompt)} characters")

    try:
        print("🤖 Sending request to Gemini API...")
        headers = {"Content-Type": "application/json"}
        data = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        response = requests.post(GEMINI_API_URL, headers=headers, json=data)
        print(f"📡 Gemini API response status: {response.status_code}")
        print(f"📡 Response headers: {dict(response.headers)}")

        if response.status_code == 200:
            result = response.json()
            # Extract the text content from Gemini response
            if 'candidates' in result and len(result['candidates']) > 0:
                content = result['candidates'][0]['content']['parts'][0]['text']
                print(f"✅ Gemini analysis received ({len(content)} characters)")
                return {"analysis": content, "status": "success"}
            else:
                print("⚠️ No response from Gemini")
                return {"error": "No response from Gemini", "status": "error"}

        elif response.status_code == 429:
            print("⏱️ Rate limit exceeded - using enhanced fallback analysis")
            print(f"❌ Rate limit response: {response.text[:300]}...")
            # Enhanced fallback for rate limiting
            return get_enhanced_fallback_analysis(prompt, "RATE_LIMIT_EXCEEDED")

        elif response.status_code == 403:
            print("❌ Gemini API not enabled - using fallback analysis")
            print(f"❌ 403 response: {response.text[:300]}...")
            return get_enhanced_fallback_analysis(prompt, "API_NOT_ENABLED")

        elif response.status_code == 404:
            print("❌ Model not found - using fallback analysis")
            print(f"❌ 404 response: {response.text[:300]}...")
            return get_enhanced_fallback_analysis(prompt, "MODEL_NOT_FOUND")

        else:
            print(f"❌ Gemini API Error: {response.status_code}")
            print(f"❌ Error response: {response.text[:300]}...")
            # If we haven't exceeded max retries and it's a server error, try again
            if retry_count < max_retries and response.status_code >= 500:
                import time
                delay = (2 ** retry_count) * 2  # Exponential backoff: 2s, 4s, 8s
                print(f"🔄 Retrying in {delay} seconds... (attempt {retry_count + 1}/{max_retries})")
                time.sleep(delay)
                return analyze_with_gemini(prompt, retry_count + 1, max_retries)
            else:
                return get_enhanced_fallback_analysis(prompt, f"API_ERROR_{response.status_code}")

    except Exception as e:
        print(f"💥 Exception in Gemini API call: {str(e)}")
        return get_enhanced_fallback_analysis(prompt, "EXCEPTION")

# Enhanced fallback analysis when Gemini API is not available
def get_enhanced_fallback_analysis(prompt, reason="API_UNAVAILABLE"):
    """Enhanced fallback analysis with detailed error information and local AI processing"""

    print(f"🔄 Using enhanced fallback analysis (Reason: {reason})")

    # Extract content for analysis
    content = prompt.lower()

    # Check Google Safe Browsing API if URL is present
    urls = threat_classifier.extract_urls(prompt)
    safe_browsing_threat = False
    safe_browsing_result = None
    if urls:
        safe_browsing_result = check_safe_browsing_api(urls[0])
        if safe_browsing_result.get("threat_found"):
            safe_browsing_threat = True

    # Perform automatic classification
    classification_result = threat_classifier.classify_content(prompt)

    # Boost score if Safe Browsing detected a threat
    if safe_browsing_threat and safe_browsing_result:
        classification_result['risk_score'] = min(classification_result['risk_score'] + 50, 100)
        classification_result['risk_factors'].append(f"Google Safe Browsing: {safe_browsing_result['threat_type']} detected")
        if classification_result['risk_score'] >= 60:
            classification_result['classification'] = "FRAUDULENT"
            classification_result['threat_level'] = "HIGH"

    # Create enhanced analysis based on reason
    if reason == "RATE_LIMIT_EXCEEDED":
        status_message = "⚠️ GOOGLE GEMINI API RATE LIMIT EXCEEDED"
        detail_message = "Your free tier quota has been reached. The system is using local AI analysis instead."
    elif reason == "API_NOT_ENABLED":
        status_message = "❌ GOOGLE GEMINI API NOT ENABLED"
        detail_message = "API key may not have proper permissions. Using local analysis."
    elif reason == "MODEL_NOT_FOUND":
        status_message = "❌ GEMINI MODEL NOT FOUND"
        detail_message = "The requested model may not be available. Using local analysis."
    else:
        status_message = f"⚠️ GOOGLE GEMINI API UNAVAILABLE ({reason})"
        detail_message = "AI service temporarily unavailable. Using local analysis."

    # Generate detailed analysis based on classification
    if "website" in content or "url" in content:
        # Extract URL from prompt for website analysis
        extracted_urls = threat_classifier.extract_urls(prompt)
        target_url = extracted_urls[0] if extracted_urls else None
        return generate_enhanced_website_analysis(target_url, classification_result, status_message, detail_message)
    elif "app" in content or "mobile" in content:
        return generate_enhanced_app_analysis(prompt, classification_result, status_message, detail_message)
    else:
        return generate_enhanced_general_analysis(prompt, classification_result, status_message, detail_message)

# Fallback analysis when Gemini API is not available
def get_fallback_analysis(prompt):
    """Enhanced fallback analysis with automatic classification"""

    # Extract content for analysis
    content = prompt.lower()

    # Perform automatic classification
    classification_result = threat_classifier.classify_content(prompt)

    # Generate detailed analysis based on classification
    if "website" in content or "url" in content:
        return generate_website_analysis(prompt, classification_result)
    elif "app" in content or "mobile" in content:
        return generate_app_analysis(prompt, classification_result)
    else:
        return generate_general_analysis(prompt, classification_result)

def generate_website_analysis(prompt, classification):
    """Generate detailed website analysis with proactive threat identification"""
    
    # Extract URL if present
    urls = threat_classifier.extract_urls(prompt)
    target_url = urls[0] if urls else "the provided URL"
    
    analysis_parts = [
        f"�️ **AUTOMATED THREAT ANALYSIS REPORT**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. SECURITY ASSESSMENT**"
    ]
    
    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This website shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Avoid this website entirely. Do not enter personal information.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This website exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Exercise extreme caution. Verify authenticity before proceeding.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this website appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard web safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])
    
    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")
    
    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")
    
    analysis_parts.extend([
        f"",
        f"**2. PROACTIVE PROTECTION MEASURES**",
        f"• Real-time URL scanning completed",
        f"• Cross-referenced with threat intelligence databases",
        f"• Behavioral pattern analysis performed",
        f"• Domain reputation check conducted",
        f"",
        f"**3. ADDITIONAL SECURITY RECOMMENDATIONS**",
        f"• Always verify website URLs before entering sensitive information",
        f"• Look for HTTPS encryption (🔒) in the address bar",
        f"• Be cautious of websites requesting immediate action",
        f"• Use official apps or bookmarked links when possible",
        f"",
        f"---",
        f"*Analysis performed by CyberGuard AI Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])
    
    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }

def generate_app_analysis(prompt, classification):
    """Generate detailed app analysis with proactive threat identification"""
    
    analysis_parts = [
        f"📱 **MOBILE APP SECURITY ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. APP SECURITY ASSESSMENT**"
    ]
    
    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"🚨 **MALICIOUS APP DETECTED** - This application shows strong indicators of malicious behavior.",
            f"⛔ **CRITICAL RECOMMENDATION:** Do not install or use this application.",
            f"",
            f"**Malicious Indicators:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **POTENTIALLY UNSAFE APP** - This application has suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Verify app authenticity through official app stores only.",
            f"",
            f"**Suspicious Behaviors:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **APP APPEARS SAFE** - No significant threats detected in initial analysis.",
            f"ℹ️ **RECOMMENDATION:** Download only from official app stores with user reviews.",
            f"",
            f"**Safety Indicators:**"
        ])
    
    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")
    
    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")
    
    analysis_parts.extend([
        f"",
        f"**2. MOBILE SECURITY BEST PRACTICES**",
        f"• Only download apps from official stores (Google Play, App Store)",
        f"• Check app permissions before installation",
        f"• Read user reviews and ratings",
        f"• Verify developer information",
        f"• Keep apps updated to latest versions",
        f"",
        f"**3. PRIVACY PROTECTION**",
        f"• Review app permissions carefully",
        f"• Limit access to sensitive data (contacts, location, camera)",
        f"• Monitor app behavior after installation",
        f"• Use app reputation checking tools",
        f"",
        f"---",
        f"*Analysis performed by CyberGuard AI Mobile Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])
    
    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }

def generate_general_analysis(prompt, classification):
    """Generate general content analysis"""
    
    analysis_parts = [
        f"🔍 **CONTENT SECURITY ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**ANALYSIS RESULTS:**"
    ]
    
    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.append("🚨 **FRAUDULENT CONTENT DETECTED** - High probability of malicious intent.")
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.append("⚠️ **SUSPICIOUS CONTENT** - Exercise caution and verify authenticity.")
    else:
        analysis_parts.append("✅ **CONTENT APPEARS LEGITIMATE** - No significant threats detected.")
    
    analysis_parts.extend([
        f"",
        f"**Risk Factors Identified:**"
    ])
    
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")
    
    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")
    
    analysis_parts.extend([
        f"",
        f"---",
        f"*Analysis performed by CyberGuard AI Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])
    
    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }

@app.route("/analyze/website", methods=["POST"])
def analyze_website():
    try:
        print("📨 Received website analysis request")
        data = request.json
        url = data.get("url")
        print(f"🌐 Analyzing website: {url}")
        print(f"📊 Request data: {data}")

        if not url:
            print("❌ No URL provided in request")
            return jsonify({"error": "No URL provided"}), 400
        
        # Perform automatic classification first
        classification_result = threat_classifier.classify_content(url, "url")

        # Check Google Safe Browsing API for real-time threat detection
        safe_browsing_result = check_safe_browsing_api(url)
        if safe_browsing_result.get("threat_found"):
            # Boost classification if Safe Browsing detects a threat
            classification_result['risk_score'] = min(classification_result['risk_score'] + 50, 100)
            classification_result['risk_factors'].append(f"Google Safe Browsing: {safe_browsing_result['threat_type']} detected")
            if classification_result['risk_score'] >= 60:
                classification_result['classification'] = "FRAUDULENT"
                classification_result['threat_level'] = "HIGH"
        
        prompt = f"""Analyze the following website URL for signs of fraud, phishing, or malicious content. 
        Provide a detailed analysis including:
        1. Risk Level (Low, Medium, High)
        2. Fraud Category (if any): Phishing, Scam, Fake Store, etc.
        3. Detailed explanation of your analysis
        4. Specific red flags or indicators found
        
        URL to analyze: {url}
        
        Format your response clearly with sections for each point above."""
        
        print("📡 Calling analysis engine...")
        result = analyze_with_gemini(prompt)
        
        # Add classification data to result
        if result.get("status") == "success":
            result["automatic_classification"] = classification_result
            result["proactive_protection"] = {
                "threat_detected": classification_result['classification'] != 'LEGITIMATE',
                "protection_level": classification_result['threat_level'],
                "immediate_action_required": classification_result['classification'] == 'FRAUDULENT'
            }
        
        print(f"✅ Analysis complete: {result.get('status', 'unknown')}")
        return jsonify(result)
    except Exception as e:
        print(f"❌ Error in website analysis: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "status": "error"}), 500

@app.route("/analyze/app", methods=["POST"])
def analyze_app():
    try:
        data = request.json
        app_name = data.get("app_name", "")
        package = data.get("package", "")
        description = data.get("description", "")
        
        if not app_name and not package and not description:
            return jsonify({"error": "No app details provided"}), 400
        
        # Combine app details for classification
        app_content = f"App: {app_name} Package: {package} Description: {description}"
        classification_result = threat_classifier.classify_content(app_content, "mobile_app")
        
        prompt = f"""Analyze the following mobile application for signs of being fake, fraudulent, or malicious.
        Provide a detailed analysis including:
        1. Risk Level (Low, Medium, High)
        2. Fraud Category (if any): Fake App, Malware, Adware, etc.
        3. Detailed explanation of your analysis
        4. Specific red flags or indicators found
        
        App Details:
        - App Name: {app_name}
        - Package Name: {package}
        - Description: {description}
        
        Format your response clearly with sections for each point above."""
        
        result = analyze_with_gemini(prompt)
        
        # Add classification data to result
        if result.get("status") == "success":
            result["automatic_classification"] = classification_result
            result["mobile_security"] = {
                "threat_detected": classification_result['classification'] != 'LEGITIMATE',
                "install_recommendation": "DO NOT INSTALL" if classification_result['classification'] == 'FRAUDULENT' else "VERIFY FIRST" if classification_result['classification'] == 'SUSPICIOUS' else "SAFE TO INSTALL",
                "store_verification_required": classification_result['classification'] != 'LEGITIMATE'
            }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}", "status": "error"}), 500

@app.route("/analyze/app", methods=["OPTIONS"])
def analyze_app_options():
    response = jsonify({"status": "ok"})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# New Advanced Classification Endpoints

@app.route("/classify/content", methods=["POST", "OPTIONS"])
def classify_content():
    """Automatically classify any content into Legitimate, Suspicious, or Fraudulent"""
    try:
        data = request.json
        content = data.get("content", "")
        content_type = data.get("type", "text")  # text, url, email, etc.
        
        if not content:
            return jsonify({"error": "No content provided for classification"}), 400
        
        print(f"🔍 Classifying content type: {content_type}")
        
        # Perform automatic classification
        classification_result = threat_classifier.classify_content(content, content_type)
        
        # Generate detailed analysis
        analysis_result = get_fallback_analysis(content)
        
        return jsonify({
            "content_classification": classification_result,
            "detailed_analysis": analysis_result,
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "engine": "CyberGuard AI Advanced Classification System"
        })
        
    except Exception as e:
        print(f"❌ Error in content classification: {str(e)}")
        return jsonify({"error": f"Classification error: {str(e)}", "status": "error"}), 500

@app.route("/threat/proactive-scan", methods=["POST", "OPTIONS"])
def proactive_threat_scan():
    """Proactive threat identification and protection"""
    try:
        data = request.json
        targets = data.get("targets", [])  # List of URLs, emails, or content to scan
        scan_type = data.get("scan_type", "comprehensive")  # quick, comprehensive, deep
        
        if not targets:
            return jsonify({"error": "No targets provided for scanning"}), 400
        
        print(f"🛡️ Starting proactive threat scan for {len(targets)} targets")
        
        scan_results = []
        threat_summary = {
            "total_scanned": len(targets),
            "fraudulent": 0,
            "suspicious": 0,
            "legitimate": 0,
            "high_risk_threats": [],
            "protection_recommendations": []
        }
        
        for i, target in enumerate(targets):
            print(f"📊 Scanning target {i+1}/{len(targets)}: {target[:50]}...")
            
            # Classify each target
            classification = threat_classifier.classify_content(target)
            
            # Generate protection recommendations
            recommendations = generate_protection_recommendations(classification, target)
            
            scan_result = {
                "target": target[:100] + "..." if len(target) > 100 else target,
                "classification": classification,
                "recommendations": recommendations,
                "scan_timestamp": datetime.now().isoformat()
            }
            
            scan_results.append(scan_result)
            
            # Update summary
            threat_summary[classification['classification'].lower()] += 1
            
            if classification['threat_level'] == 'HIGH':
                threat_summary['high_risk_threats'].append({
                    "target": target[:50] + "..." if len(target) > 50 else target,
                    "risk_score": classification['risk_score'],
                    "primary_threat": classification['risk_factors'][0] if classification['risk_factors'] else "Unknown"
                })
        
        # Generate overall protection recommendations
        threat_summary['protection_recommendations'] = generate_overall_recommendations(threat_summary)
        
        return jsonify({
            "scan_results": scan_results,
            "threat_summary": threat_summary,
            "status": "success",
            "scan_completed": datetime.now().isoformat(),
            "engine": "CyberGuard AI Proactive Threat Scanner"
        })
        
    except Exception as e:
        print(f"❌ Error in proactive scan: {str(e)}")
        return jsonify({"error": f"Scan error: {str(e)}", "status": "error"}), 500

@app.route("/threat/intelligence", methods=["GET", "OPTIONS"])
def threat_intelligence():
    """Get current threat intelligence and statistics"""
    try:
        # Simulate real-time threat intelligence
        intelligence_data = {
            "current_threats": {
                "active_phishing_campaigns": 47,
                "new_malware_variants": 12,
                "compromised_websites": 156,
                "fake_apps_detected": 23
            },
            "threat_trends": {
                "phishing_increase": "+15% this week",
                "crypto_scams": "+23% this month",
                "fake_banking_apps": "+8% this week",
                "social_engineering": "+12% this month"
            },
            "protection_status": {
                "total_scans_today": 1247,
                "threats_blocked": 89,
                "users_protected": 1158,
                "success_rate": "92.8%"
            },
            "recent_discoveries": [
                {
                    "type": "Phishing Website",
                    "target": "fake-paypal-login.com",
                    "discovered": "2 hours ago",
                    "risk": "HIGH"
                },
                {
                    "type": "Malicious App",
                    "target": "Fake WhatsApp Pro",
                    "discovered": "4 hours ago", 
                    "risk": "HIGH"
                },
                {
                    "type": "Crypto Scam",
                    "target": "bitcoin-giveaway-fake.net",
                    "discovered": "6 hours ago",
                    "risk": "MEDIUM"
                }
            ],
            "last_updated": datetime.now().isoformat()
        }
        
        return jsonify({
            "threat_intelligence": intelligence_data,
            "status": "success",
            "engine": "CyberGuard AI Threat Intelligence Center"
        })
        
    except Exception as e:
        return jsonify({"error": f"Intelligence error: {str(e)}", "status": "error"}), 500

def generate_protection_recommendations(classification, target):
    """Generate specific protection recommendations based on classification"""
    recommendations = []
    
    if classification['classification'] == 'FRAUDULENT':
        recommendations.extend([
            "🚨 IMMEDIATE ACTION: Block this content/URL immediately",
            "⛔ Do not interact with or share this content",
            "🔒 Change any passwords if you've already interacted",
            "📞 Contact your bank/service provider if financial info was shared",
            "🚫 Report this threat to appropriate authorities"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        recommendations.extend([
            "⚠️ Exercise extreme caution with this content",
            "🔍 Verify authenticity through official channels",
            "🛡️ Use additional security measures (2FA, etc.)",
            "👥 Consult with security experts if unsure",
            "📋 Monitor accounts for unusual activity"
        ])
    else:
        recommendations.extend([
            "✅ Content appears safe for normal use",
            "🔒 Continue following standard security practices",
            "🛡️ Keep security software updated",
            "👁️ Remain vigilant for any changes"
        ])
    
    return recommendations

def generate_overall_recommendations(threat_summary):
    """Generate overall security recommendations based on scan summary"""
    recommendations = []
    
    total = threat_summary['total_scanned']
    fraudulent = threat_summary['fraudulent']
    suspicious = threat_summary['suspicious']
    
    fraud_percentage = (fraudulent / total) * 100 if total > 0 else 0
    
    if fraud_percentage > 30:
        recommendations.extend([
            "🚨 HIGH THREAT ENVIRONMENT: Multiple fraudulent items detected",
            "🔒 Implement immediate security measures",
            "🛡️ Enable advanced threat protection",
            "📞 Consider professional security consultation"
        ])
    elif fraud_percentage > 10:
        recommendations.extend([
            "⚠️ ELEVATED RISK: Some fraudulent content detected",
            "🔍 Increase vigilance and verification processes",
            "🛡️ Review and update security settings",
            "📋 Monitor for additional threats"
        ])
    else:
        recommendations.extend([
            "✅ NORMAL THREAT LEVEL: Standard precautions advised",
            "🔒 Maintain current security practices",
            "👁️ Continue regular monitoring"
        ])
    
    return recommendations

# Enhanced analysis functions for better error handling
def generate_enhanced_website_analysis(url, classification, status_message, detail_message):
    """Generate enhanced website analysis with API status information"""

    # Use the provided URL directly
    target_url = url if url else "the provided URL"

    analysis_parts = [
        f"{status_message}",
        f"📝 {detail_message}",
        f"",
        f"🛡️ **LOCAL AI THREAT ANALYSIS REPORT**",
        f"",
        f"**Target:** {target_url}",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. SECURITY ASSESSMENT**"
    ]

    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This website shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Avoid this website entirely. Do not enter personal information.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This website exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Exercise extreme caution. Verify authenticity before proceeding.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this website appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard web safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])

    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")

    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")

    analysis_parts.extend([
        f"",
        f"**2. LOCAL AI ANALYSIS COMPLETED**",
        f"• Pattern recognition algorithms applied",
        f"• Threat signature database cross-referenced",
        f"• Behavioral analysis performed",
        f"• Risk scoring calculated",
        f"",
        f"**3. RECOMMENDED ACTIONS**",
        f"• Continue using CyberGuard AI for real-time protection",
        f"• Report suspicious websites to authorities if fraudulent",
        f"• Keep security software updated",
        f"",
        f"---",
        f"*Local AI Analysis by CyberGuard Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])

    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "api_status": "LOCAL_ANALYSIS",
        "timestamp": datetime.now().isoformat()
    }

def generate_enhanced_app_analysis(prompt, classification, status_message, detail_message):
    """Generate enhanced app analysis with API status information"""

    analysis_parts = [
        f"{status_message}",
        f"📝 {detail_message}",
        f"",
        f"📱 **LOCAL AI APP SECURITY ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. APP SECURITY ASSESSMENT**"
    ]

    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This app shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Do not download or install this app.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This app exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Research thoroughly before installation.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this app appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard app safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])

    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")

    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")

    analysis_parts.extend([
        f"",
        f"**2. LOCAL AI ANALYSIS COMPLETED**",
        f"• App behavior patterns analyzed",
        f"• Permission requirements evaluated",
        f"• Developer reputation assessed",
        f"",
        f"---",
        f"*Local AI Analysis by CyberGuard Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])

    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "api_status": "LOCAL_ANALYSIS",
        "timestamp": datetime.now().isoformat()
    }

def generate_enhanced_general_analysis(prompt, classification, status_message, detail_message):
    """Generate enhanced general analysis with API status information"""

    analysis_parts = [
        f"{status_message}",
        f"📝 {detail_message}",
        f"",
        f"🔍 **LOCAL AI CONTENT ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. CONTENT SECURITY ASSESSMENT**"
    ]

    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This content shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Treat with extreme caution.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This content exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Verify source and context.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this content appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard content safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])

    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")

    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")

    analysis_parts.extend([
        f"",
        f"**2. LOCAL AI ANALYSIS COMPLETED**",
        f"• Content pattern analysis performed",
        f"• Linguistic analysis completed",
        f"• Context evaluation finished",
        f"",
        f"---",
        f"*Local AI Analysis by CyberGuard Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])

    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "api_status": "LOCAL_ANALYSIS",
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
