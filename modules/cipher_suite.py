"""
Advanced Caesar Cipher with AI-powered cracking
"""

import re
from collections import Counter

class CipherSuite:
    """Professional Caesar Cipher with brute force and analysis"""
    
    @staticmethod
    def encrypt(text: str, shift: int) -> dict:
        """Encrypt text using Caesar Cipher"""
        result = []
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) - 65 + shift) % 26 + 65))
            elif char.islower():
                result.append(chr((ord(char) - 97 + shift) % 26 + 97))
            else:
                result.append(char)
        return {
            'text': ''.join(result),
            'shift': shift,
            'method': 'Caesar Cipher Encryption'
        }
    
    @staticmethod
    def decrypt(text: str, shift: int) -> dict:
        """Decrypt text using Caesar Cipher"""
        return CipherSuite.encrypt(text, -shift)
    
    @staticmethod
    def brute_force(text: str) -> dict:
        """Try all 25 shifts with confidence scoring"""
        results = {}
        for shift in range(1, 26):
            decrypted = CipherSuite.encrypt(text, -shift)['text']
            confidence = CipherSuite._calculate_confidence(decrypted)
            results[shift] = {
                'text': decrypted,
                'confidence': confidence,
                'score': confidence
            }
        return results
    
    @staticmethod
    def _calculate_confidence(text: str) -> float:
        """Calculate how English-like the text is"""
        common_letters = 'etaoinshrdlcumwfgypbvkjxqz'
        
        # Letter frequency analysis
        freq = Counter(text.lower())
        total = sum(freq.values())
        
        score = 0
        for char in text.lower():
            if char.isalpha():
                if char in 'etaoinshrdlu':
                    score += 1
                try:
                    score += (26 - common_letters.index(char)) / 26
                except ValueError:
                    pass
        
        # Check for common words
        common_words = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i']
        text_lower = text.lower()
        for word in common_words:
            if word in text_lower:
                score += 2
        
        # Calculate percentage
        max_possible = len(text) * 1.5 if text else 1
        confidence = min(100, (score / max_possible) * 100)
        
        return round(confidence, 2)
    
    @staticmethod
    def analyze_cipher(text: str, shift: int, mode: str) -> dict:
        """Provide educational analysis of the cipher"""
        return {
            'algorithm': 'Caesar Cipher',
            'shift': shift,
            'mode': mode,
            'security_level': '🔴 Very Weak',
            'explanation': 'The Caesar cipher is a simple substitution cipher. It is not secure for modern use.',
            'history': 'Used by Julius Caesar for military communications.',
            'mathematics': f'Encryption: C = (P + {shift}) mod 26',
            'vulnerability': 'Vulnerable to brute force attacks. Only 25 possible shifts.'
        }

    @staticmethod
    def encrypt_advanced(text: str, shift: int, key: str = '') -> dict:
        """Advanced encryption with additional features"""
        encrypted = CipherSuite.encrypt(text, shift)
        return {
            'text': encrypted['text'],
            'shift': shift,
            'key': key if key else 'No key provided',
            'method': 'Caesar Cipher with Custom Key',
            'security': 'Educational purpose only'
        }