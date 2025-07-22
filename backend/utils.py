import re
from urllib.parse import urlparse
import socket

def clean_url(url):
    """Clean and normalize URL"""
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return url

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return 'unknown'

def extract_features(url):
    """Extract features from URL for analysis"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        features = {
            'url_length': len(url),
            'has_https': url.lower().startswith('https://'),
            'subdomain_count': len(domain.split('.')) - 2 if domain else 0,
            'has_ip': is_ip_address(domain),
            'special_chars': count_special_chars(url),
            'path_depth': len([p for p in parsed.path.split('/') if p]),
            'query_params': len(parsed.query.split('&')) if parsed.query else 0
        }
        
        return features
    except Exception as e:
        # Return default features if parsing fails
        return {
            'url_length': len(url),
            'has_https': False,
            'subdomain_count': 0,
            'has_ip': False,
            'special_chars': 0,
            'path_depth': 0,
            'query_params': 0
        }

def is_ip_address(domain):
    """Check if domain is an IP address"""
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        # Check for IPv6
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            return True
        except socket.error:
            return False

def count_special_chars(url):
    """Count special characters in URL"""
    special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/~`')
    return sum(1 for char in url if char in special_chars)

def is_url_shortened(domain):
    """Check if URL uses a shortening service"""
    shorteners = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link',
        'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'
    ]
    return any(shortener in domain for shortener in shorteners)