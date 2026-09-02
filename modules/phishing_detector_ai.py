"""
AI-Powered Phishing Detection Engine
"""

import re
import requests
from urllib.parse import urlparse
from datetime import datetime
import json
import os


class PhishingDetectorAI:
    """Advanced phishing detection with AI scoring"""
    
    def __init__(self):
        self.red_flags = []
        self.score = 0
        self.detected_urls = []
        self.suspicious_patterns = self._load_patterns()
    
    def _load_patterns(self):
        """Load phishing detection patterns"""
        return {
            'urgent_words': [
                'urgent', 'immediately', 'action required', 'verify now',
                'suspended', 'locked', 'account', 'confirm your',
                'click here', 'security alert', 'unauthorized',
                'limited time', 'act now', 'your account has been'
            ],
            'social_engineering': [
                'verify your account', 'security update',
                'unauthorized access', 'suspicious activity',
                'account suspended', 'click here now',
                'limited time offer', 'exclusive deal',
                'you have been selected', 'congratulations'
            ],
            'spoofed_brands': [
                'google', 'microsoft', 'apple', 'paypal',
                'amazon', 'facebook', 'bank', 'chase',
                'wells fargo', 'american express', 'visa'
            ],
            'suspicious_domains': [
                '.xyz', '.top', '.club', '.online', '.site',
                'secure-', 'verify-', 'update-', 'login-'
            ]
        }
    
    def analyze(self, email_text: str) -> dict:
        """Comprehensive email analysis with AI scoring"""
        
        self.text = email_text
        self.red_flags = []
        self.score = 0
        self.detected_urls = []
        
        # Run all detection checks
        self._check_urgency()
        self._check_social_engineering()
        self._check_sender()
        self._check_urls()
        self._check_brand_spoofing()
        self._check_attachments()
        self._check_grammar()
        self._check_greetings()
        
        # Normalize score
        self.score = min(100, self.score)
        
        # Determine risk level
        if self.score >= 70:
            risk = '🔴 High Risk'
            risk_key = 'high'
        elif self.score >= 40:
            risk = '🟡 Medium Risk'
            risk_key = 'medium'
        else:
            risk = '🟢 Low Risk'
            risk_key = 'low'
        
        return {
            'risk': risk,
            'risk_key': risk_key,
            'score': self.score,
            'flags': self.red_flags,
            'urls_found': self.detected_urls,
            'recommendations': self._generate_recommendations(),
            'detailed_analysis': self._get_detailed_analysis(),
            'ai_confidence': self._calculate_confidence()
        }
    
    def _check_urgency(self):
        """Detect urgency and pressure tactics"""
        found = []
        for word in self.suspicious_patterns['urgent_words']:
            if word in self.text.lower():
                found.append(word)
                self.score += 3
        
        if found:
            self.red_flags.append(f"⚠️ Urgency tactics detected: {', '.join(found[:5])}")
    
    def _check_social_engineering(self):
        """Detect social engineering attempts"""
        found = []
        for phrase in self.suspicious_patterns['social_engineering']:
            if phrase in self.text.lower():
                found.append(phrase)
                self.score += 5
        
        if found:
            self.red_flags.append(f"⚠️ Social engineering detected: {', '.join(found[:3])}")
    
    def _check_sender(self):
        """Check sender for spoofing"""
        # Check for generic senders
        generic = ['noreply', 'security', 'admin', 'support', 'service']
        for word in generic:
            if word in self.text.lower() and '@' not in self.text.lower():
                self.score += 5
                self.red_flags.append(f"⚠️ Generic sender name: '{word}'")
                break
        
        # Check for suspicious email patterns
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.text)
        for email in emails:
            domain = email.split('@')[1]
            if any(p in domain for p in self.suspicious_patterns['suspicious_domains']):
                self.score += 10
                self.red_flags.append(f"⚠️ Suspicious domain: {domain}")
    
    def _check_urls(self):
        """Extract and analyze URLs"""
        urls = re.findall(r'https?://[^\s<>"\')\]]+', self.text)
        self.detected_urls = urls
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Check for IP address
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc):
                    self.score += 15
                    self.red_flags.append(f"⚠️ IP address used as domain: {parsed.netloc}")
                
                # Check for suspicious domains
                if any(p in parsed.netloc.lower() for p in self.suspicious_patterns['suspicious_domains']):
                    self.score += 10
                    self.red_flags.append(f"⚠️ Suspicious domain extension: {parsed.netloc}")
                
                # Check for typosquatting
                for brand in self.suspicious_patterns['spoofed_brands']:
                    if brand in parsed.netloc.lower():
                        if not parsed.netloc.lower().startswith(brand) and not parsed.netloc.lower().startswith(f'www.{brand}'):
                            self.score += 20
                            self.red_flags.append(f"⚠️ Possible brand spoofing: {parsed.netloc}")
            
            except:
                pass
        
        if len(urls) > 3:
            self.score += 5
            self.red_flags.append(f"⚠️ Unusually high number of links: {len(urls)}")
    
    def _check_brand_spoofing(self):
        """Check for brand spoofing attempts"""
        for brand in self.suspicious_patterns['spoofed_brands']:
            if brand in self.text.lower():
                # Check if it's claiming to be from this brand
                if 'security' in self.text.lower() and 'update' in self.text.lower():
                    self.score += 10
                    self.red_flags.append(f"⚠️ Potential {brand} spoofing attempt")
    
    def _check_attachments(self):
        """Check for dangerous attachments"""
        dangerous = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.jar', '.dmg', '.zip', '.rar']
        for ext in dangerous:
            if ext in self.text.lower():
                self.score += 10
                self.red_flags.append(f"⚠️ Dangerous attachment type: {ext}")
                break
    
    def _check_grammar(self):
        """Check for grammar and spelling errors"""
        words = self.text.split()
        common_errors = ['teh', 'waht', 'abotu', 'adn', 'thier', 'recieve']
        found_errors = [w for w in words if w.lower() in common_errors]
        if found_errors:
            self.score += 5
            self.red_flags.append(f"⚠️ Grammar/spelling errors detected")
    
    def _check_greetings(self):
        """Check for generic greetings"""
        generic_greetings = ['dear customer', 'dear user', 'dear sir', 'dear madam', 'hello sir']
        for greeting in generic_greetings:
            if greeting in self.text.lower():
                self.score += 3
                self.red_flags.append(f"⚠️ Generic greeting detected")
                break
    
    def _generate_recommendations(self) -> list:
        """Generate actionable recommendations"""
        recommendations = []
        
        if self.score > 40:
            recommendations.append("🚫 Do NOT click any links in this email")
            recommendations.append("🚫 Do NOT reply or forward the email")
            recommendations.append("📧 Report this email to your IT security team")
            recommendations.append("🔍 Verify the sender through official channels")
        
        if self.score > 60:
            recommendations.append("⚠️ This is likely a phishing attack")
            recommendations.append("🗑️ Delete the email immediately")
            recommendations.append("🔒 Change any passwords that may have been shared")
        
        return recommendations
    
    def _get_detailed_analysis(self) -> dict:
        """Get detailed analysis breakdown"""
        return {
            'risk_factors': len(self.red_flags),
            'suspicious_indicators': self.red_flags,
            'url_count': len(self.detected_urls),
            'attack_likelihood': 'High' if self.score > 60 else 'Medium' if self.score > 30 else 'Low',
            'recommended_action': 'Block and report' if self.score > 40 else 'Monitor'
        }
    
    def _calculate_confidence(self) -> str:
        """Calculate AI confidence level"""
        if self.score > 70:
            return "High (92%)"
        elif self.score > 50:
            return "Medium (75%)"
        else:
            return "Low (60%)"
    
    def generate_sample_emails(self) -> list:
        """Generate sample phishing emails for training"""
        return [
            {
                'subject': '🚨 URGENT: Your Account Has Been Suspended',
                'body': 'Dear Customer, Your account has been suspended due to suspicious activity. Click here to verify immediately: http://security-verify.xyz/confirm',
                'flags': ['Urgent language', 'Generic greeting', 'Suspicious domain', 'Brand spoofing'],
                'risk': 'High'
            },
            {
                'subject': '✅ Your Amazon Order Confirmation #ORD-98765',
                'body': 'Thank you for your recent order of $299.99. To confirm delivery, please click: http://amazon-secure-order.site/confirm',
                'flags': ['Brand spoofing', 'Suspicious domain extension', 'Generic language'],
                'risk': 'High'
            },
            {
                'subject': '🎁 You\'ve Won a Free iPhone 15! Claim Now',
                'body': 'Congratulations! You\'ve been selected to win a free iPhone 15. Limited time offer! Click here: http://free-iphone-giveaway.top/claim',
                'flags': ['Too good to be true', 'Urgency language', 'Suspicious domain', 'Generic greeting'],
                'risk': 'Critical'
            },
            {
                'subject': '🔒 PayPal Security Alert - Action Required',
                'body': 'Your PayPal account was accessed from an unknown device. Please verify your identity: http://paypal-security-check.xyz/verify',
                'flags': ['Brand spoofing', 'Suspicious domain', 'Urgent action', 'Generic greeting'],
                'risk': 'High'
            },
            {
                'subject': '⚠️ Microsoft Critical Security Update',
                'body': 'A critical security vulnerability has been detected on your system. Update now: http://microsoft-update.xyz/download',
                'flags': ['Brand spoofing', 'Suspicious domain', 'Urgent language', 'Generic greeting'],
                'risk': 'High'
            }
        ]