import re
import json
from urllib.parse import urlparse
from utils import extract_domain, extract_features

class PhishingDetector:
    """
    Advanced phishing URL detection using machine learning-inspired features
    """
    
    def __init__(self):
        # Known phishing keywords and patterns
        self.phishing_keywords = [
            'secure', 'verify', 'update', 'confirm', 'suspended', 'expire',
            'login', 'signin', 'account', 'banking', 'paypal', 'amazon',
            'microsoft', 'google', 'apple', 'security', 'alert', 'urgent'
        ]
        
        # Common phishing TLDs and patterns
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.pw']
        
        # Trusted domains (whitelist)
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'facebook.com', 'twitter.com', 'github.com',
            'stackoverflow.com', 'reddit.com', 'wikipedia.org'
        }
    
    def predict(self, url):
        """
        Predict if a URL is phishing based on various features
        """
        try:
            features = extract_features(url)
            domain = extract_domain(url)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(url, domain, features)
            risk_factors = self._identify_risk_factors(url, domain, features)
            
            # Determine if phishing (threshold: 0.5)
            is_phishing = risk_score > 0.5
            
            return {
                'phishing': is_phishing,
                'confidence': risk_score if is_phishing else 1 - risk_score,
                'risk_factors': risk_factors
            }
            
        except Exception as e:
            # Default to safe if analysis fails
            return {
                'phishing': False,
                'confidence': 0.1,
                'risk_factors': [f'Analysis error: {str(e)}']
            }
    
    def _calculate_risk_score(self, url, domain, features):
        """Calculate overall risk score (0-1 scale)"""
        score = 0.0
        
        # Domain-based checks
        if domain in self.trusted_domains:
            return 0.1  # Very low risk for trusted domains
        
        # URL length (longer URLs are often suspicious)
        if features['url_length'] > 75:
            score += 0.2
        elif features['url_length'] > 50:
            score += 0.1
        
        # Special characters count
        if features['special_chars'] > 10:
            score += 0.3
        elif features['special_chars'] > 5:
            score += 0.15
        
        # Suspicious TLD
        for tld in self.suspicious_tlds:
            if url.lower().endswith(tld):
                score += 0.4
                break
        
        # Phishing keywords
        keyword_count = sum(1 for keyword in self.phishing_keywords 
                          if keyword in url.lower())
        score += min(keyword_count * 0.1, 0.4)
        
        # IP address instead of domain
        if features['has_ip']:
            score += 0.5
        
        # Subdomain count (many subdomains can be suspicious)
        if features['subdomain_count'] > 3:
            score += 0.3
        elif features['subdomain_count'] > 2:
            score += 0.2
        
        # HTTPS presence (lack of HTTPS is suspicious for login pages)
        if not features['has_https'] and any(kw in url.lower() 
                                           for kw in ['login', 'signin', 'account']):
            score += 0.2
        
        # URL shorteners (can hide malicious URLs)
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link']
        if any(shortener in domain for shortener in shorteners):
            score += 0.3
        
        # Domain spoofing attempts (similar to popular sites)
        if self._is_domain_spoofing(domain):
            score += 0.6
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _identify_risk_factors(self, url, domain, features):
        """Identify specific risk factors for the URL"""
        factors = []
        
        if features['url_length'] > 75:
            factors.append("Unusually long URL")
        
        if features['special_chars'] > 10:
            factors.append("High number of special characters")
        
        if features['has_ip']:
            factors.append("Uses IP address instead of domain name")
        
        if features['subdomain_count'] > 3:
            factors.append("Multiple subdomains detected")
        
        if not features['has_https']:
            factors.append("No HTTPS encryption")
        
        # Check for phishing keywords
        found_keywords = [kw for kw in self.phishing_keywords 
                         if kw in url.lower()]
        if found_keywords:
            factors.append(f"Contains suspicious keywords: {', '.join(found_keywords[:3])}")
        
        # Check for suspicious TLD
        for tld in self.suspicious_tlds:
            if url.lower().endswith(tld):
                factors.append(f"Uses suspicious TLD: {tld}")
                break
        
        if self._is_domain_spoofing(domain):
            factors.append("Possible domain spoofing attempt")
        
        return factors
    
    def _is_domain_spoofing(self, domain):
        """Check if domain might be spoofing a popular website"""
        # Common spoofing patterns
        spoofing_patterns = [
            'g00gle', 'goog1e', 'googIe',  # Google variations
            'amaz0n', 'amazom', 'ammazon',  # Amazon variations
            'paypaI', 'payp4l', 'paypaall',  # PayPal variations
            'microsft', 'micr0soft',       # Microsoft variations
            'app1e', 'appIe',              # Apple variations
        ]
        
        return any(pattern in domain.lower() for pattern in spoofing_patterns)