import validators
from dotenv import load_dotenv
import os

load_dotenv()

def get_link():
    url = input("Enter the URL: ")
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
if api_key:
    print(f"API Key loaded: {api_key[:10]}...")
else:
    print("No API Key found in environment variables.")


link = get_link()
if is_valid_url(link):
    print(f"The URL '{link}' is valid.")
    check_suspicious_pattern(link)
else:
    print(f"The URL '{link}' is not valid.")

