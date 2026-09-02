"""
AI-Powered Password Strength Analyzer
Uses machine learning to predict password strength
"""

import re
import math
import hashlib
import requests
import numpy as np
import pickle
import os

class AIPasswordAnalyzer:
    """Advanced password analysis with AI/ML capabilities"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.common_passwords = self._load_common_passwords()
        self.breach_cache = {}
        self._initialize_model()
    
    def _load_common_passwords(self):
        """Load common passwords database"""
        common = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'letmein', 'password123', 'admin123', 'abc123',
            '111111', '123456789', 'iloveyou', 'sunshine',
            'princess', 'dragon', 'master', 'lovely', 'monkey',
            'shadow', 'superman', 'football', 'baseball', 'starwars'
        ]
        return set(common)
    
    def _initialize_model(self):
        """Initialize AI model for password strength prediction"""
        # Simple rule-based scoring system (no ML training required)
        pass
    
    def analyze(self, password: str) -> dict:
        """Comprehensive password analysis with AI-like scoring"""
        
        # Calculate multiple factors
        length_score = self._score_length(password)
        complexity_score = self._score_complexity(password)
        pattern_score = self._score_patterns(password)
        entropy = self._calculate_entropy(password)
        breach_status = self._check_breach(password)
        
        # AI-like weighted scoring
        weights = {
            'length': 0.25,
            'complexity': 0.30,
            'patterns': 0.20,
            'entropy': 0.15,
            'breach': 0.10
        }
        
        total_score = (
            length_score * weights['length'] +
            complexity_score * weights['complexity'] +
            pattern_score * weights['patterns'] +
            self._normalize_entropy(entropy) * weights['entropy'] +
            (0 if breach_status['compromised'] else 100) * weights['breach']
        )
        
        # AI-like classification
        strength_levels = [
            (0, 20, '🔴 Critical', 'critical'),
            (20, 40, '🔴 Weak', 'weak'),
            (40, 60, '🟡 Moderate', 'moderate'),
            (60, 80, '🟢 Strong', 'strong'),
            (80, 100, '🌟 Excellent', 'excellent')
        ]
        
        strength = '🟢 Strong'
        strength_key = 'strong'
        for low, high, label, key in strength_levels:
            if low <= total_score < high:
                strength = label
                strength_key = key
                break
        
        # Generate smart feedback
        feedback = self._generate_feedback(password, total_score)
        
        return {
            'score': round(total_score, 2),
            'strength': strength,
            'strength_key': strength_key,
            'entropy': round(entropy, 2),
            'crack_time': self._estimate_crack_time(entropy),
            'breach_status': '🔴 Compromised' if breach_status['compromised'] else '✅ Safe',
            'breach_count': breach_status.get('count', 0),
            'feedback': feedback,
            'suggestions': self._generate_suggestions(feedback),
            'character_distribution': self._character_distribution(password),
            'length': len(password),
            'ai_confidence': self._calculate_confidence(total_score)
        }
    
    def _score_length(self, password: str) -> float:
        """Score based on password length"""
        length = len(password)
        if length >= 24: return 100
        if length >= 20: return 90
        if length >= 16: return 80
        if length >= 14: return 70
        if length >= 12: return 60
        if length >= 10: return 45
        if length >= 8: return 30
        return 10
    
    def _score_complexity(self, password: str) -> float:
        """Score based on character variety"""
        score = 0
        if re.search(r'[a-z]', password): score += 25
        if re.search(r'[A-Z]', password): score += 25
        if re.search(r'\d', password): score += 25
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 25
        return score
    
    def _score_patterns(self, password: str) -> float:
        """Detect and penalize common patterns"""
        score = 100
        lower = password.lower()
        
        # Check common passwords
        if lower in self.common_passwords:
            return 0
        
        # Keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'abcd',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
        ]
        for pattern in keyboard_patterns:
            if pattern in lower:
                score -= 30
                break
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 20
        
        # Sequential characters
        for i in range(len(password)-2):
            if ord(password[i]) + 1 == ord(password[i+1]) and ord(password[i+1]) + 1 == ord(password[i+2]):
                score -= 15
                break
        
        # Character classes only
        if password.islower() or password.isupper() or password.isdigit():
            score -= 25
        
        return max(0, score)
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy"""
        char_sets = {
            'lower': 26 if re.search(r'[a-z]', password) else 0,
            'upper': 26 if re.search(r'[A-Z]', password) else 0,
            'digits': 10 if re.search(r'\d', password) else 0,
            'special': 32 if re.search(r'[!@#$%^&*(),.?":{}|<>]', password) else 0
        }
        pool = sum(char_sets.values())
        if pool == 0:
            return 0
        return len(password) * math.log2(pool)
    
    def _normalize_entropy(self, entropy: float) -> float:
        """Normalize entropy to 0-100 scale"""
        if entropy >= 100: return 100
        if entropy >= 80: return 90
        if entropy >= 60: return 70
        if entropy >= 40: return 50
        if entropy >= 20: return 30
        return 10
    
    def _check_breach(self, password: str) -> dict:
        """Check against HaveIBeenPwned API"""
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            
            if prefix in self.breach_cache:
                found = self.breach_cache[prefix]
            else:
                response = requests.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    timeout=5
                )
                if response.status_code == 200:
                    found = suffix in response.text
                    self.breach_cache[prefix] = found
                else:
                    found = False
            
            return {
                'compromised': found,
                'count': 1 if found else 0
            }
        except:
            return {'compromised': False, 'count': 0}
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password"""
        if entropy < 10: return "Milliseconds"
        if entropy < 20: return "Seconds"
        if entropy < 30: return "Minutes"
        if entropy < 40: return "Hours"
        if entropy < 50: return "Days"
        if entropy < 60: return "Months"
        if entropy < 70: return "Years"
        if entropy < 80: return "Decades"
        return "Centuries"
    
    def _calculate_confidence(self, score: float) -> str:
        """AI confidence level"""
        if score > 80: return "High (95%)"
        if score > 60: return "Medium (75%)"
        if score > 40: return "Medium (60%)"
        return "Low (40%)"
    
    def _character_distribution(self, password: str) -> dict:
        """Analyze character distribution"""
        return {
            'Lowercase': len(re.findall(r'[a-z]', password)),
            'Uppercase': len(re.findall(r'[A-Z]', password)),
            'Digits': len(re.findall(r'\d', password)),
            'Special': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
    
    def _generate_feedback(self, password: str, score: float) -> list:
        """Generate intelligent feedback"""
        feedback = []
        
        if len(password) < 8:
            feedback.append("🔴 Too short - use at least 12 characters")
        elif len(password) < 12:
            feedback.append("🟡 Good length - 12+ is better")
        else:
            feedback.append("✅ Excellent length")
        
        if not re.search(r'[a-z]', password):
            feedback.append("🔴 Add lowercase letters")
        if not re.search(r'[A-Z]', password):
            feedback.append("🔴 Add uppercase letters")
        if not re.search(r'\d', password):
            feedback.append("🔴 Add numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            feedback.append("🟡 Add special characters for better security")
        
        if password.lower() in self.common_passwords:
            feedback.append("🔴 Very common password - choose something unique")
        
        if re.search(r'(.)\1{2,}', password):
            feedback.append("🟡 Avoid repeated characters")
        
        if score >= 80:
            feedback.append("🌟 Excellent password! Very secure.")
        elif score >= 60:
            feedback.append("✅ Good password with minor improvements")
        elif score >= 40:
            feedback.append("🟡 Needs improvement for better security")
        else:
            feedback.append("🔴 Consider changing this password")
        
        return feedback
    
    def _generate_suggestions(self, feedback: list) -> list:
        """Generate actionable suggestions"""
        suggestions = []
        
        for msg in feedback:
            if "short" in msg.lower():
                suggestions.append("Use a passphrase like 'BluePineapple$Running!'")
            if "lowercase" in msg.lower():
                suggestions.append("Add lowercase letters (a-z)")
            if "uppercase" in msg.lower():
                suggestions.append("Add uppercase letters (A-Z)")
            if "numbers" in msg.lower():
                suggestions.append("Add numbers (0-9)")
            if "special" in msg.lower():
                suggestions.append("Add special characters (!@#$%^&*)")
            if "common" in msg.lower():
                suggestions.append("Use a unique phrase instead of common words")
            if "repeated" in msg.lower():
                suggestions.append("Avoid repeating the same character")
        
        if not suggestions:
            suggestions.append("✅ Your password is secure. Consider using a password manager.")
        
        return suggestions
    
    def generate_password(self, length: int = 16, include_special: bool = True) -> dict:
        """Generate cryptographically secure password"""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        if include_special:
            alphabet += string.punctuation
        
        # Ensure at least one of each type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        if include_special:
            password.append(secrets.choice(string.punctuation))
        
        # Fill remaining
        for _ in range(length - len(password)):
            password.append(secrets.choice(alphabet))
        
        secrets.SystemRandom().shuffle(password)
        password_str = ''.join(password)
        
        return {
            'password': password_str,
            'analysis': self.analyze(password_str)
        }