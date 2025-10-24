import validators
from dotenv import load_dotenv
import os
from urllib.parse import urlparse
import requests
import time
from database import create_database, get_brands_from_db
from scan_history import (create_scan_history_table, save_scan_result, get_scan_history)


import google.generativeai as genai



def extract_real_domain(url):
    parsed = urlparse(url)
    hostname = parsed.netloc
    parts = hostname.split('.')
    if len(parts) >= 2:
        real_domain = '.'.join(parts[-2:])
        return real_domain, hostname
    return hostname, hostname

load_dotenv()
create_database()
create_scan_history_table()
print(f"done")


if gemini_api_key := os.getenv('GEMINI_API_KEY'):
    model = None

    if gemini_api_key:
        genai.configure(api_key=gemini_api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        print('AI model loaded')
    else:
        print('Warning: No Gemini API key found, AI features disabled')

def get_link():
    url = input("Enter the URL: ")
    url = normalize_url(url)
    return url


def normalize_url(url):
    """Add http:// if protocol is missing"""
    url = url.strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    return url


def is_valid_url(url):
    if validators.url(url):
        return True
    else:
        return False

def check_suspicious_pattern(url):
    suspicious_keywords = ['secure', 'login', 'update', 'verify', 'account', 'confirm', 'banking', 'password']
    url_lower = url.lower()
    found_keywords = []

    for keywords in suspicious_keywords:
        if keywords in url_lower:
            found_keywords.append(keywords)

    if found_keywords:
        print(f"Warning: The URL contains suspicious keywords:")
        return True
    else:
        print(f"Warning: The URL does not contain suspicious keywords:")
        return False


api_key = os.getenv('GOOGLE_API_KEY')


def check_brand_impersonation(url):
    """Check if the URL contains brand names that could indicate impersonation."""

    # Get brands from database
    brands_data = get_brands_from_db()
    brand_keywords = [brand[0] for brand in brands_data]  # Just the names
    official_domains = [brand[1] for brand in brands_data]  # Just the domains

    real_domain, full_hostname = extract_real_domain(url)
    full_hostname = full_hostname.lower()
    real_domain = real_domain.lower()

    # Check if it's a legitimate domain
    if real_domain in official_domains:
        return {
            'impersonation': False,
            'legitimate': True,
            'real_domain': real_domain,
        }

    # Check for impersonation
    impersonation_detected = []
    for brand in brand_keywords:
        if brand in full_hostname and brand not in real_domain:
            impersonation_detected.append(brand)

    if impersonation_detected:
        return {
            'impersonation': True,
            'Legitimate': False,
            'brands': impersonation_detected,
            'Warning': f"⚠️ Impersonating {', '.join(impersonation_detected)}! Real domain is: {real_domain}"
        }

    return {
        'impersonation': False,
        'real_domain': real_domain,
    }

def expand_shortened_url(url):
    """Expands the shortened url like bit.ly"""
    shorteners = ['bit.ly', 'aka.ms', 'goo.gl', 'tinyurl.com', 'ow.ly',
                  't.co', 'shorturl.at', 'adf.ly', 'bl.ink', 'lnkd.in',
                  'rb.gy', 'cutt.ly', 'short.io']

    try:
        parsed = urlparse(url)
        is_shortened = any(shortener in parsed.netloc for shortener in shorteners)

        if is_shortened:
            print(f'⚠️ Shortened URL detected: {parsed.netloc}')
            print("Expanding...")

            response = requests.head(url, allow_redirects=True, timeout=10)
            expanded_url = response.url

            print(f"✓ Expanded URL: {expanded_url}")
            return {
                'is_shortened': True,
                'original_url': url,
                'expanded_url': expanded_url
            }
        else:
            return {
                'is_shortened': False,
                'original_url': url,
                'expanded_url': url
            }
    except requests.RequestException as e:
        return {
            'error': f'Could not expand URL: {str(e)}',
            'original_url': url,
            'expanded_url': url
        }


def check_virustotal(url):
    """Check the URL against VirusTotal API."""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')

    if not api_key:
        return {'error': 'no API key found for VirusTotal.'}

    headers = {'x-apikey': api_key}
    
    # Use URL encoding for better compatibility
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # First, try to get existing analysis
    check_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    check_response = requests.get(check_url, headers=headers)
    
    if check_response.status_code == 200:
        # URL already analyzed, get results directly
        data = check_response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'harmless': stats['harmless'],
            'undetected': stats['undetected'],
            'total_scans': sum(stats.values()),
            'threat_detected': stats['malicious'] > 0 or stats['suspicious'] > 0
        }
    
    # If not found, submit for analysis
    data = {'url': url}
    response = requests.post(
        'https://www.virustotal.com/api/v3/urls',
        headers=headers,
        data=data,
    )
    
    if response.status_code != 200:
        return {'error': f'VirusTotal API error: {response.status_code} - {response.text}'}

    result = response.json()
    analysis_id = result['data']['id']

    # Wait longer and poll for results
    max_attempts = 6
    for attempt in range(max_attempts):
        time.sleep(10)  # Increased from 5 to 10 seconds
        
        analysis_response = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=headers
        )
        
        if analysis_response.status_code != 200:
            if attempt == max_attempts - 1:
                return {'error': f'Could not get analysis results after {max_attempts} attempts'}
            continue
        
        analysis_data = analysis_response.json()
        status = analysis_data['data']['attributes']['status']
        
        if status == 'completed':
            stats = analysis_data['data']['attributes']['stats']
            return {
                'malicious': stats['malicious'],
                'suspicious': stats['suspicious'],
                'harmless': stats['harmless'],
                'undetected': stats['undetected'],
                'total_scans': sum(stats.values()),
                'threat_detected': stats['malicious'] > 0 or stats['suspicious'] > 0
            }
        
        print(f"Analysis in progress... (attempt {attempt + 1}/{max_attempts})")
    
    return {'error': 'Analysis timeout - try again later'}


def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API using Lookup API"""
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')

    if not api_key:
        return {'error': 'No Google Safe Browsing API key found'}

    # Encode URL
    import urllib.parse
    encoded_url = urllib.parse.quote(url, safe='')

    # Use v4 Lookup API
    api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'

    payload = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(api_url, json=payload)

        print(f"Debug - Status Code: {response.status_code}")
        print(f"Debug - Response: {response.text}")

        if response.status_code == 200:
            result = response.json()

            if 'matches' in result:
                threats = [match['threatType'] for match in result['matches']]
                return {
                    'threat_detected': True,
                    'threats': threats
                }
            else:
                return {
                    'threat_detected': False,
                    'threats': []
                }
        else:
            return {'error': f'API error: {response.status_code} - {response.text}'}

    except Exception as e:
        return {'error': f'Error: {str(e)}'}


def ai_predict_maliciousness(url, scan_results):
    """Use Gemini to predict maliciousness score based on scan results"""
    if not model:
        return {"score": 0, "explanation": "AI not available"}

    # Get historical data for context
    from scan_history import get_scan_history
    history = get_scan_history(20)

    
    prompt = f"""This is a cybersecurity AI that predicts website maliciousness scores.

Based on scan results it'll provide a maliciousness score from 0-100 and explanation.

SCAN RESULTS FOR: {url}
- Suspicious Keywords: {scan_results.get('suspicious_keywords', 'None')}
- Brand Impersonation: {scan_results.get('impersonation', False)}
- VirusTotal Malicious: {scan_results.get('vt_malicious', 0)}
- VirusTotal Suspicious: {scan_results.get('vt_suspicious', 0)}
- Google Safe Browsing Threat: {scan_results.get('gsb_threat', False)}
- URL Shortened: {scan_results.get('is_shortened', False)}
- Real Domain: {scan_results.get('real_domain', 'Unknown')}

Respond in this exact JSON format:
{{
    "score": <0-100>,
    "verdict": "<SAFE|SUSPICIOUS|DANGEROUS|CRITICAL>",
    "explanation": "<brief explanation>",
    "confidence": "<LOW|MEDIUM|HIGH>"
}}
"""

    try:
        response = model.generate_content(prompt)
        # Parse JSON response
        import json
        result = json.loads(response.text.strip().replace('```json', '').replace('```', ''))
        return result
    except Exception as e:
        # Fallback to rule-based scoring
        score = calculate_rule_based_score(scan_results)
        return {
            "score": score,
            "verdict": get_verdict(score),
            "explanation": "AI unavailable, using rule-based scoring",
            "confidence": "MEDIUM"
        }


def calculate_rule_based_score(scan_results):
    """Fallback rule-based scoring"""
    score = 0

    if scan_results.get('vt_malicious', 0) > 0:
        score += 50
    if scan_results.get('vt_suspicious', 0) > 0:
        score += 20
    if scan_results.get('gsb_threat', False):
        score += 30
    if scan_results.get('impersonation', False):
        score += 25
    if scan_results.get('suspicious_keywords', False):
        score += 10
    if scan_results.get('is_shortened', False):
        score += 5

    return min(score, 100)


def get_verdict(score):
    """Convert score to verdict"""
    if score < 20:
        return "SAFE"
    elif score < 50:
        return "SUSPICIOUS"
    elif score < 80:
        return "DANGEROUS"
    else:
        return "CRITICAL"


def chat_with_gemini(user_message, scan_results=None):
    """Chat with Gemini AI for URL security"""
    if not model:
        return "Gemini AI not available."

    context = "You are a cybersecurity assistant helping users check if URLs are safe.\n\n"

    if scan_results:
        context += f"Recent scan results:\n{scan_results}\n\n"

    context += f"User: {user_message}"

    try:
        response = model.generate_content(context)
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"





link = get_link()

# Expand shortened URLs first
expansion_result = expand_shortened_url(link)
if 'error' in expansion_result:
    print(f"Warning: {expansion_result['error']}")

# Use expanded URL for all checks
url_to_check = expansion_result.get('expanded_url', link)

if is_valid_url(url_to_check):
    print(f"\nThe URL '{url_to_check}' is valid.")
    check_suspicious_pattern(url_to_check)

    impersonation_result = check_brand_impersonation(url_to_check)
    if impersonation_result['impersonation']:
        print(impersonation_result['Warning'])
    else:
        print(f"✓ Real domain: {impersonation_result['real_domain']}")

    print("\nChecking with VirusTotal...")
    vt_result = check_virustotal(url_to_check)

    if 'error' in vt_result:
        print(f"VirusTotal Error: {vt_result['error']}")
    else:
        print(f"VirusTotal Results:")
        print(f"  Malicious: {vt_result['malicious']}")
        print(f"  Suspicious: {vt_result['suspicious']}")
        print(f"  Harmless: {vt_result['harmless']}")
        if vt_result['threat_detected']:
            print("  ⚠️ THREAT DETECTED!")
        else:
            print("  ✓ No threats detected")
    print("\nChecking with Google Safe Browsing...")
    gs_result = check_google_safe_browsing(url_to_check)
    if 'error' in gs_result:
        print(f"Google Safe Browsing Error: {gs_result['error']}")
    else:
        if gs_result['threat_detected']:
            print(f"⚠️ THREAT DETECTED by Google!")
            print(f"Threat types: {','.join(gs_result['threats'])}")
        else:
            print("✓ No threats detected by Google Safe Browsing")




    has_suspicious = check_suspicious_pattern(url_to_check)

    scan_data = {
    'url': url_to_check,
    'real_domain': impersonation_result.get('real_domain', ''),
    'has_suspicious_keywords': has_suspicious,
    'is_impersonation': impersonation_result.get('impersonation', False),
    'vt_malicious': vt_result.get('malicious', 0) if 'error' not in vt_result else 0,
    'vt_suspicious': vt_result.get('suspicious', 0) if 'error' not in vt_result else 0,
    'gsb_threat': gs_result.get('threat_detected', False) if 'error' not in gs_result else False,
    'is_shortened': expansion_result.get('is_shortened', False),
    'suspicious_keywords': 'Found' if has_suspicious else 'None',
    'impersonation': impersonation_result.get('impersonation', False)
}

    print("\n AI Analysis...")
    ai_result = ai_predict_maliciousness(url_to_check, scan_data)

    print(f"\n{'=' * 50}")
    print(f"{'AI PREDICTION'.center(50)}")
    print(f"{'=' * 50}")
    print(f"Maliciousness Score: {ai_result['score']}/100")
    print(f"Verdict: {ai_result['verdict']}")
    print(f"Confidence: {ai_result['confidence']}")
    print(f"Explanation: {ai_result['explanation']}")
    print(f"{'=' * 50}")

    scan_data['verdict'] = ai_result['verdict']

    save_scan_result(url_to_check, scan_data)



else:
    print(f"The URL '{url_to_check}' is not valid.")

