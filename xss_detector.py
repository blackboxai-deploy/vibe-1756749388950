#!/usr/bin/env python3
"""
XSS Attack Detection Engine
Simple pattern-based XSS detection for IoT devices
Bachelor's Final Year Project
"""

import re
import logging
import json
import urllib.parse
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xss_detection.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class XSSDetector:
    """Simple XSS detection engine with common attack patterns"""
    
    def __init__(self):
        self.detection_count = 0
        self.attack_log = []
        
        # Common XSS attack patterns
        self.xss_patterns = [
            # Script tags
            r'<script[^>]*>.*?</script>',
            r'<script[^>]*>',
            r'javascript:',
            
            # Event handlers
            r'on\w+\s*=',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            
            # Common XSS payloads
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'document\.cookie',
            r'document\.write',
            r'eval\s*\(',
            
            # HTML injection
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<img[^>]*onerror',
            r'<svg[^>]*onload',
            
            # URL-based attacks
            r'data:\s*text/html',
            r'vbscript:',
            r'livescript:',
            
            # Advanced patterns
            r'String\.fromCharCode',
            r'unescape\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
        ]
        
        # Compile patterns for better performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        
        logger.info("XSS Detector initialized with {} patterns".format(len(self.xss_patterns)))
    
    def detect_xss(self, content: str, source_ip: str = "", url: str = "") -> Dict:
        """
        Detect XSS attacks in given content
        
        Args:
            content: HTTP request/response content to analyze
            source_ip: Source IP address
            url: Requested URL
            
        Returns:
            Dictionary with detection results
        """
        if not content:
            return {"detected": False, "patterns": [], "risk_level": "low"}
        
        # URL decode the content
        try:
            decoded_content = urllib.parse.unquote_plus(content)
        except Exception:
            decoded_content = content
        
        detected_patterns = []
        
        # Check against all XSS patterns
        for i, pattern in enumerate(self.compiled_patterns):
            matches = pattern.findall(decoded_content)
            if matches:
                detected_patterns.append({
                    "pattern_id": i,
                    "pattern": self.xss_patterns[i],
                    "matches": matches[:5]  # Limit matches to prevent log spam
                })
        
        is_detected = len(detected_patterns) > 0
        
        if is_detected:
            self.detection_count += 1
            risk_level = self._calculate_risk_level(detected_patterns)
            
            # Log the detection
            attack_info = {
                "timestamp": datetime.now().isoformat(),
                "source_ip": source_ip,
                "url": url,
                "detected_patterns": detected_patterns,
                "risk_level": risk_level,
                "content_sample": decoded_content[:200]  # First 200 chars
            }
            
            self.attack_log.append(attack_info)
            self._log_attack(attack_info)
            
            return {
                "detected": True,
                "patterns": detected_patterns,
                "risk_level": risk_level,
                "attack_info": attack_info
            }
        
        return {"detected": False, "patterns": [], "risk_level": "low"}
    
    def _calculate_risk_level(self, patterns: List[Dict]) -> str:
        """Calculate risk level based on detected patterns"""
        high_risk_patterns = [0, 1, 2, 3, 4, 5, 6, 10, 11, 12]  # Script tags, event handlers, etc.
        medium_risk_patterns = [7, 8, 9, 13, 14, 15, 16]  # Common payloads
        
        pattern_ids = [p["pattern_id"] for p in patterns]
        
        if any(pid in high_risk_patterns for pid in pattern_ids):
            return "high"
        elif any(pid in medium_risk_patterns for pid in pattern_ids):
            return "medium"
        else:
            return "low"
    
    def _log_attack(self, attack_info: Dict):
        """Log detected XSS attack"""
        logger.warning(
            f"XSS ATTACK DETECTED! "
            f"Source: {attack_info['source_ip']} | "
            f"URL: {attack_info['url']} | "
            f"Risk: {attack_info['risk_level']} | "
            f"Patterns: {len(attack_info['detected_patterns'])}"
        )
    
    def analyze_http_request(self, method: str, url: str, headers: Dict, body: str, source_ip: str = "") -> Dict:
        """
        Analyze complete HTTP request for XSS attacks
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: HTTP headers dictionary
            body: Request body
            source_ip: Source IP address
            
        Returns:
            Detection results
        """
        results = []
        
        # Check URL parameters
        url_result = self.detect_xss(url, source_ip, url)
        if url_result["detected"]:
            url_result["location"] = "URL"
            results.append(url_result)
        
        # Check headers (especially User-Agent, Referer)
        for header_name, header_value in headers.items():
            if header_name.lower() in ['user-agent', 'referer', 'x-forwarded-for']:
                header_result = self.detect_xss(header_value, source_ip, url)
                if header_result["detected"]:
                    header_result["location"] = f"Header-{header_name}"
                    results.append(header_result)
        
        # Check request body
        if body:
            body_result = self.detect_xss(body, source_ip, url)
            if body_result["detected"]:
                body_result["location"] = "Body"
                results.append(body_result)
        
        return {
            "detected": len(results) > 0,
            "results": results,
            "total_detections": len(results)
        }
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        risk_levels = {"high": 0, "medium": 0, "low": 0}
        
        for attack in self.attack_log:
            risk_levels[attack["risk_level"]] += 1
        
        return {
            "total_detections": self.detection_count,
            "risk_levels": risk_levels,
            "recent_attacks": self.attack_log[-10:],  # Last 10 attacks
            "patterns_loaded": len(self.xss_patterns)
        }
    
    def save_log_to_file(self, filename: str = "xss_attacks.json"):
        """Save attack log to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.attack_log, f, indent=2)
            logger.info(f"Attack log saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save log: {e}")

# Test function
def test_xss_detector():
    """Test the XSS detector with sample payloads"""
    detector = XSSDetector()
    
    test_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "normal safe content",
        "document.cookie",
        "<iframe src='javascript:alert(1)'></iframe>",
        "onclick=alert('XSS')"
    ]
    
    print("Testing XSS Detector...")
    print("=" * 50)
    
    for payload in test_payloads:
        result = detector.detect_xss(payload, "127.0.0.1", "/test")
        print(f"Payload: {payload[:30]}")
        print(f"Detected: {result['detected']}")
        print(f"Risk Level: {result['risk_level']}")
        if result['detected']:
            print(f"Patterns: {len(result['patterns'])}")
        print("-" * 30)
    
    print(f"\nStatistics: {detector.get_statistics()}")

if __name__ == "__main__":
    test_xss_detector()