import validators
from dotenv import load_dotenv
import os
from urllib.parse import urlparse
import requests
import time

def extract_real_domain(url):
    parsed = urlparse(url)
    hostname = parsed.netloc
    parts = hostname.split('.')
    if len(parts) >= 2:
        real_domain = '.'.join(parts[-2:])
        return real_domain, hostname
    return hostname, hostname

load_dotenv()

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
    brand_keywords = ['steam.com', 'facebook.com', 'youtube.com', 'google.com',
        'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'netflix.com', 'ebay.com', 'instagram.com', 'twitter.com',
        'linkedin.com', 'github.com', 'dropbox.com', 'yahoo.com'
    ]

    brand_keywords = [ 'steam', 'facebook', 'youtube', 'google', 'paypal',
        'amazon', 'microsoft', 'apple', 'netflix', 'ebay',
        'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'yahoo'
    ]
    real_domain, full_hostname = extract_real_domain(url)
    full_hostname = full_hostname.lower()
    real_domain = real_domain.lower()

    if real_domain.lower in brand_keywords:
        return{
            'impersonation': False,
            'legitimate': True,
            'domain': real_domain,
        }

    impersonation_detected = []
    for brand in brand_keywords:
        if brand in full_hostname.lower() and brand not in real_domain.lower():
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
        return{'error': 'no API key found for VirusTotal.'}

    headers = {'x-apikey': api_key}
    data = {'url': url}

    response = requests.post(
        'https://www.virustotal.com/api/v3/urls',
        headers=headers,
        data=data,
    )
    if response.status_code != 200:
        return{'error': f'VirusTotal API error: {response.status_code}'}

    result = response.json()
    analysis_id = result['data']['id']

    time.sleep(5)

    analysis_response = requests.get(
        f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
        headers = headers
    )
    if analysis_response.status_code != 200:
        return{'error': 'Could not get analysis results'}

    analysis_data = analysis_response.json()
    stats = analysis_data['data']['attributes']['stats']

    return {
        'malicious': stats['malicious'],
        'suspicious': stats['suspicious'],
        'harmless': stats['harmless'],
        'undetected': stats['undetected'],
        'total_scans': sum(stats.values()),
        'threat_detected': stats['malicious'] > 0 or stats['suspicious'] > 0
    }

# Main execution
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
else:
    print(f"The URL '{url_to_check}' is not valid.")

