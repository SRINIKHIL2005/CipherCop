import time
import urllib.parse
import requests
import re

# Simple in-memory cache and rate limiter for Safe Browsing queries
_safe_browsing_cache = {}  # domain -> { 'result': {...}, 'ts': epoch }
_last_safe_browsing_call = 0

def rate_limited_safe_browsing(url, api_key, cache_ttl=3600, min_interval=0.5):
    """Rate-limited Safe Browsing wrapper.

    - Caches results per-domain for cache_ttl seconds.
    - Enforces a global min_interval between outgoing requests; if called
      too quickly will return a throttled response (non-blocking).
    - Returns a dict similar to check_safe_browsing_api: {threat_found, threat_type, ...}
    """
    global _last_safe_browsing_call
    now = time.time()
    domain = urllib.parse.urlparse(url).netloc.lower() if url else ''

    # Return cached result if fresh
    if domain in _safe_browsing_cache and (now - _safe_browsing_cache[domain]['ts'] < cache_ttl):
        return _safe_browsing_cache[domain]['result']

    # If API key not provided, short-circuit
    if not api_key:
        res = {"threat_found": False, "threat_type": None, "error": "api_key_missing"}
        _safe_browsing_cache[domain] = {'result': res, 'ts': now}
        return res

    # Enforce simple global rate limit
    if now - _last_safe_browsing_call < min_interval:
        # return a safe default and mark as throttled
        res = {"threat_found": False, "throttled": True, "threat_type": None, "error": "rate_limited"}
        _safe_browsing_cache[domain] = {'result': res, 'ts': now}
        return res

    # Build Safe Browsing request
    try:
        _last_safe_browsing_call = now
        payload = {
            "client": {"clientId": "ciphercop-security", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        # Use the public Safe Browsing endpoint
        resp = requests.post(f"https://safebrowsing.googleapis.com/v1/threatMatches:find?key={api_key}", json=payload, timeout=8)
        if resp.status_code == 200:
            j = resp.json()
            if 'matches' in j and len(j['matches']) > 0:
                match = j['matches'][0]
                out = {"threat_found": True, "threat_type": match.get('threatType'), "platform_type": match.get('platformType')}
                _safe_browsing_cache[domain] = {'result': out, 'ts': now}
                return out
            else:
                out = {"threat_found": False, "threat_type": None}
                _safe_browsing_cache[domain] = {'result': out, 'ts': now}
                return out
        else:
            out = {"threat_found": False, "threat_type": None, "error": f"api_status_{resp.status_code}"}
            _safe_browsing_cache[domain] = {'result': out, 'ts': now}
            return out
    except Exception as e:
        out = {"threat_found": False, "threat_type": None, "error": str(e)}
        _safe_browsing_cache[domain] = {'result': out, 'ts': now}
        return out


def domain_age_score(domain_age_days):
    """Score domain age risk: newer domains are more suspicious."""
    # If we couldn't determine domain age (network/WHOIS failed), treat as
    # neutral rather than penalizing popular/established domains. Previously
    # unknown age added a large suspicious boost which caused false positives
    # (e.g., google.com flagged when WHOIS lookup failed). Use 0 for unknown.
    if domain_age_days is None:
        return 0  # unknown age -> neutral (do not penalize on lookup failure)
    if domain_age_days < 30:
        return 50
    if domain_age_days < 180:
        return 25
    if domain_age_days < 365:
        return 10
    return 0


def html_features_score(html_features):
    """Score based on scraped HTML features (forms, scripts, iframes)."""
    score = 0
    try:
        if not html_features or isinstance(html_features, dict) and html_features.get('error'):
            # if we couldn't fetch the HTML, don't penalize too hard
            return 0

        form_count = int(html_features.get('form_count', 0)) if isinstance(html_features, dict) else 0
        script_count = int(html_features.get('script_count', 0)) if isinstance(html_features, dict) else 0
        iframe_count = int(html_features.get('iframe_count', 0)) if isinstance(html_features, dict) else 0
        suspicious_forms = int(html_features.get('suspicious_forms', 0)) if isinstance(html_features, dict) else 0

        if suspicious_forms > 0:
            score += 40
        if form_count > 3:
            score += 10
        if iframe_count > 2:
            score += 10
        if script_count > 80:
            score += 10
    except Exception:
        pass
    return min(score, 100)


def tld_risk_score(domain):
    if not domain:
        return 0
    domain = domain.lower()
    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club', '.online', '.site')
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return 25
    return 0


def compute_heuristic_score(domain, whois_features, html_features, classification_result=None, allowlist=None, blacklist=None):
    """Compute an overall heuristic score (0-100) combining domain age, html, tld, and heuristics."""
    score = 0
    factors = []

    d = domain.lower() if domain else ''
    if allowlist and d in allowlist:
        return {'score': 0, 'factors': ['allowlist']}
    if blacklist and d in blacklist:
        return {'score': 100, 'factors': ['blacklist']}

    # WHOIS / domain age
    domain_age = None
    if isinstance(whois_features, dict):
        domain_age = whois_features.get('domain_age')
    age_score = domain_age_score(domain_age)
    if age_score:
        score += age_score
        factors.append(f'domain_age_score:{age_score}')

    # HTML features
    html_score = html_features_score(html_features)
    if html_score:
        score += html_score
        factors.append(f'html_score:{html_score}')

    # TLD / domain pattern risk
    tld_score = tld_risk_score(domain)
    if tld_score:
        score += tld_score
        factors.append(f'tld_score:{tld_score}')

    # Include upstream heuristic classification if present
    try:
        if classification_result and isinstance(classification_result, dict):
            upstream = classification_result.get('risk_score') or 0
            # scale upstream to at most 40 points to avoid domination
            up = min(40, int(upstream * 0.4))
            if up:
                score += up
                factors.append(f'upstream_score:{up}')
    except Exception:
        pass

    final = min(100, int(score))
    return {'score': final, 'factors': factors}


def combine_scores(ml_proba, heuristic_score_dict, safe_browsing_result=None, ml_fallback=False):
    """Combine ML probability, heuristic score dict, and Safe Browsing result into final verdict and confidence.

    Returns: { 'verdict': 'LEGITIMATE'|'SUSPICIOUS'|'FRAUDULENT', 'confidence': float, 'combined_score': int, 'details': {...} }
    """
    ml_score = 0
    if ml_proba and isinstance(ml_proba, (list, tuple)):
        try:
            # ml_proba expected like [p0, p1]
            ml_score = float(ml_proba[1]) * 100
        except Exception:
            try:
                ml_score = float(max(ml_proba)) * 100
            except Exception:
                ml_score = 0

    heur_score = heuristic_score_dict.get('score') if isinstance(heuristic_score_dict, dict) else int(heuristic_score_dict or 0)

    # Safe Browsing overrides
    if safe_browsing_result and safe_browsing_result.get('threat_found'):
        combined = 95
        confidence = 98.0
        verdict = 'FRAUDULENT'
        details = {'reason': 'safe_browsing', 'safe_browsing': safe_browsing_result}
        return {'verdict': verdict, 'confidence': confidence, 'combined_score': combined, 'details': details}

    # Weighted average: prefer ML when available, but boost heuristics when ML weak.
    # If the ML features were created via a network-failure fallback (zero-vector)
    # the ML signal is less trustworthy; reduce its weight to avoid false positives.
    if ml_score > 0:
        ml_weight = 0.6
    else:
        ml_weight = 0.0

    # If fallback used for ML features, reduce ML weight to a conservative value
    if ml_fallback and ml_weight > 0:
        # reduce ML weight when fallback features were used (e.g., network/WHOIS failed)
        ml_weight = min(ml_weight, 0.2)

    heur_weight = 1.0 - ml_weight if ml_weight > 0 else 1.0

    combined_score = int(round(ml_weight * ml_score + heur_weight * heur_score))

    # Determine verdict thresholds
    if combined_score >= 70:
        verdict = 'FRAUDULENT'
    elif combined_score >= 40:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'LEGITIMATE'

    confidence = float(min(99.9, combined_score))
    details = {
        'ml_score': ml_score,
        'heuristic_score': heur_score,
        'heuristic_factors': heuristic_score_dict.get('factors', []) if isinstance(heuristic_score_dict, dict) else [],
        'safe_browsing': safe_browsing_result
    }
    return {'verdict': verdict, 'confidence': confidence, 'combined_score': combined_score, 'details': details}
