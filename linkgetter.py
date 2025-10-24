import validators
from dotenv import load_dotenv
import os
from urllib.parse import urlparse
import requests
import time
from database import create_database, get_brands_from_db
from scan_history import create_scan_history_table, save_scan_result, get_scan_history
import google.generativeai as genai
import base64
import json


def extract_real_domain(url):
    """Extract the actual domain from a URL"""
    parsed = urlparse(url)
    hostname = parsed.netloc
    parts = hostname.split('.')
    if len(parts) >= 2:
        real_domain = '.'.join(parts[-2:])
        return real_domain, hostname
    return hostname, hostname


# Initialize
load_dotenv()
create_database()
create_scan_history_table()
print("✓ Database initialized successfully\n")

# Setup Gemini AI
model = None
gemini_api_key = os.getenv('GEMINI_API_KEY')

if gemini_api_key:
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-2.0-flash-exp')
    print('✓ AI model loaded successfully')
else:
    print('⚠️  Warning: No Gemini API key found, AI features disabled')


def get_link():
    """Prompt user for URL input"""
    url = input("\n🔗 Enter the URL to scan: ")
    url = normalize_url(url)
    return url


def normalize_url(url):
    """Add http:// if protocol is missing"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def is_valid_url(url):
    """Validate URL format"""
    return validators.url(url)


def check_suspicious_pattern(url):
    """Check for suspicious keywords in URL"""
    suspicious_keywords = [
        'secure', 'login', 'update', 'verify', 'account', 
        'confirm', 'banking', 'password', 'signin', 'authenticate'
    ]
    url_lower = url.lower()
    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        print(f"⚠️  Suspicious keywords detected: {', '.join(found_keywords)}")
        return True
    else:
        print("✓ No suspicious keywords found")
        return False


def check_brand_impersonation(url):
    """Detect brand impersonation attempts"""
    brands_data = get_brands_from_db()
    brand_keywords = [brand[0] for brand in brands_data]
    official_domains = [brand[1] for brand in brands_data]

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
            'legitimate': False,
            'brands': impersonation_detected,
            'warning': f"⚠️  Impersonating {', '.join(impersonation_detected)}! Real domain is: {real_domain}"
        }

    return {
        'impersonation': False,
        'real_domain': real_domain,
    }


def expand_shortened_url(url):
    """Expand shortened URLs (bit.ly, tinyurl, etc.)"""
    shorteners = [
        'bit.ly', 'aka.ms', 'goo.gl', 'tinyurl.com', 'ow.ly',
        't.co', 'shorturl.at', 'adf.ly', 'bl.ink', 'lnkd.in',
        'rb.gy', 'cutt.ly', 'short.io'
    ]

    try:
        parsed = urlparse(url)
        is_shortened = any(shortener in parsed.netloc for shortener in shorteners)

        if is_shortened:
            print(f'🔗 Shortened URL detected: {parsed.netloc}')
            print("   Expanding to reveal destination...")

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
    """Scan URL with VirusTotal (70+ antivirus engines)"""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')

    if not api_key:
        return {'error': 'No VirusTotal API key found'}

    headers = {'x-apikey': api_key}
    
    # Use URL encoding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # Try to get existing analysis first
    check_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    check_response = requests.get(check_url, headers=headers)
    
    if check_response.status_code == 200:
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
    
    # Submit new scan if not found
    data = {'url': url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)
    
    if response.status_code != 200:
        return {'error': f'VirusTotal API error: {response.status_code}'}

    result = response.json()
    analysis_id = result['data']['id']

    # Poll for results
    max_attempts = 6
    for attempt in range(max_attempts):
        time.sleep(10)
        
        analysis_response = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=headers
        )
        
        if analysis_response.status_code != 200:
            if attempt == max_attempts - 1:
                return {'error': f'Could not retrieve analysis after {max_attempts} attempts'}
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
        
        print(f"   Analysis in progress... ({attempt + 1}/{max_attempts})")
    
    return {'error': 'Analysis timeout - please try again later'}


import requests



def check_google_safe_browsing(url):
    """Check URL with Google Safe Browsing API"""
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')

    if not api_key:
        return {'error': 'No Google Safe Browsing API key found'}

    api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'

    payload = {
        "client": {
            "clientId": "cybershield-bot",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=10)

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
            return {'error': f'API error: {response.status_code}'}

    except Exception as e:
        return {'error': f'Error: {str(e)}'}


def ai_predict_maliciousness(url, scan_results):
    """Use AI to predict threat level"""
    if not model:
        score = calculate_rule_based_score(scan_results)
        return {
            "score": score,
            "verdict": get_verdict(score),
            "explanation": "AI not available - using rule-based analysis",
            "confidence": "MEDIUM"
        }

    prompt = f"""You are a cybersecurity AI analyzing URL threats.

SCAN RESULTS FOR: {url}
- Suspicious Keywords: {scan_results.get('suspicious_keywords', 'None')}
- Brand Impersonation: {scan_results.get('impersonation', False)}
- VirusTotal Malicious: {scan_results.get('vt_malicious', 0)}
- VirusTotal Suspicious: {scan_results.get('vt_suspicious', 0)}
- Google Safe Browsing: {scan_results.get('gsb_threat', False)}
- URLhaus Detection: {scan_results.get('urlhaus_threat', False)}
- URL Shortened: {scan_results.get('is_shortened', False)}
- Real Domain: {scan_results.get('real_domain', 'Unknown')}

Provide a maliciousness score (0-100) and analysis in JSON format:
{{
    "score": <0-100>,
    "verdict": "<SAFE|SUSPICIOUS|DANGEROUS|CRITICAL>",
    "explanation": "<brief explanation>",
    "confidence": "<LOW|MEDIUM|HIGH>"
}}
"""

    try:
        response = model.generate_content(prompt)
        result = json.loads(response.text.strip().replace('```json', '').replace('```', ''))
        return result
    except Exception as e:
        score = calculate_rule_based_score(scan_results)
        return {
            "score": score,
            "verdict": get_verdict(score),
            "explanation": f"AI error: {str(e)} - using rule-based scoring",
            "confidence": "MEDIUM"
        }


def calculate_rule_based_score(scan_results):
    """Calculate threat score using rules"""
    score = 0

    if scan_results.get('vt_malicious', 0) > 0:
        score += 50
    if scan_results.get('vt_suspicious', 0) > 0:
        score += 20
    if scan_results.get('gsb_threat', False):
        score += 30
    if scan_results.get('urlhaus_threat', False):
        score += 25
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


# MAIN EXECUTION

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🛡️  CYBERSHIELD - URL THREAT DETECTOR".center(60))
    print("="*60)
    
    link = get_link()
    
    print("\n" + "-"*60)
    print("Starting comprehensive security scan...".center(60))
    print("-"*60 + "\n")

    # Expand shortened URLs
    expansion_result = expand_shortened_url(link)
    if 'error' in expansion_result:
        print(f"⚠️  {expansion_result['error']}\n")

    url_to_check = expansion_result.get('expanded_url', link)

    if not is_valid_url(url_to_check):
        print(f"\n❌ Invalid URL: '{url_to_check}'")
        print("Please check the URL format and try again.\n")
        exit(1)

    print(f"\n✓ URL validated: {url_to_check}\n")
    
    # Pattern checks
    print("━" * 60)
    print("PATTERN ANALYSIS")
    print("━" * 60)
    has_suspicious = check_suspicious_pattern(url_to_check)
    
    impersonation_result = check_brand_impersonation(url_to_check)
    if impersonation_result['impersonation']:
        print(impersonation_result['warning'])
    else:
        print(f"✓ Real domain verified: {impersonation_result['real_domain']}")

    # API checks
    print("\n" + "━" * 60)
    print("THREAT INTELLIGENCE SCAN")
    print("━" * 60)
    
    print("\n  Scanning with VirusTotal ...")
    vt_result = check_virustotal(url_to_check)
    if 'error' in vt_result:
        print(f"   ❌ {vt_result['error']}")
    else:
        print(f"   Malicious: {vt_result['malicious']}")
        print(f"   Suspicious: {vt_result['suspicious']}")
        print(f"   Harmless: {vt_result['harmless']}")
        if vt_result['threat_detected']:
            print("   🚨 THREAT DETECTED!")
        else:
            print("   ✓ Clean")

    print("\n🔐 Checking Google Safe Browsing...")
    gs_result = check_google_safe_browsing(url_to_check)
    if 'error' in gs_result:
        print(f"   ❌ {gs_result['error']}")
    else:
        if gs_result['threat_detected']:
            print(f"   🚨 THREAT DETECTED!")
            print(f"   Types: {', '.join(gs_result['threats'])}")
        else:
            print("   ✓ No threats detected")



    # Compile scan data
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

    # AI Analysis
    print("\n" + "━" * 60)
    print("🤖 AI ANALYSIS")
    print("━" * 60)
    
    ai_result = ai_predict_maliciousness(url_to_check, scan_data)

    # Display results
    print("\n" + "="*60)
    print("FINAL VERDICT".center(60))
    print("="*60)
    
    score = ai_result['score']
    verdict = ai_result['verdict']
    
    # Color-coded output
    verdict_emoji = {
        "SAFE": "✅",
        "SUSPICIOUS": "⚠️ ",
        "DANGEROUS": "🚨",
        "CRITICAL": "☠️ "
    }
    
    print(f"\n{verdict_emoji.get(verdict, '❓')} THREAT LEVEL: {verdict}")
    print(f"📊 Risk Score: {score}/100")
    print(f"🎯 Confidence: {ai_result['confidence']}")
    print(f"\n💡 Analysis: {ai_result['explanation']}")
    print("\n" + "="*60)

    # Save to database
    scan_data['verdict'] = ai_result['verdict']
    save_scan_result(url_to_check, scan_data)
    
    print("\n✓ Scan results saved to database")
   