#!/usr/bin/env python3
"""
SafeScan AI Backend API Testing
Tests all backend endpoints for the cybersecurity analysis app
"""

import requests
import json
import sys
import time
from datetime import datetime

class SafeScanAPITester:
    def __init__(self, base_url="https://safescan-ai-4.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def test_root_endpoint(self):
        """Test API root endpoint"""
        try:
            response = requests.get(f"{self.api_url}/", timeout=10)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                data = response.json()
                details += f", Message: {data.get('message', 'No message')}"
            self.log_test("API Root Endpoint", success, details)
            return success
        except Exception as e:
            self.log_test("API Root Endpoint", False, str(e))
            return False

    def test_examples_endpoint(self):
        """Test examples endpoint"""
        try:
            response = requests.get(f"{self.api_url}/examples", timeout=10)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                examples = data.get('examples', [])
                details += f", Examples count: {len(examples)}"
                
                # Validate example structure
                required_types = ['log', 'code', 'email']
                found_types = [ex.get('type') for ex in examples]
                missing_types = [t for t in required_types if t not in found_types]
                
                if missing_types:
                    success = False
                    details += f", Missing types: {missing_types}"
                else:
                    details += f", All required types present: {found_types}"
                    
            self.log_test("Examples Endpoint", success, details)
            return success, response.json() if success else {}
        except Exception as e:
            self.log_test("Examples Endpoint", False, str(e))
            return False, {}

    def test_analyze_endpoint_validation(self):
        """Test analyze endpoint input validation"""
        test_cases = [
            {"text": "", "expected_status": 422, "description": "Empty input"},
            {"text": "short", "expected_status": 400, "description": "Too short input"},
            {"text": "This is a valid test input for security analysis that meets minimum length requirements.", 
             "expected_status": 200, "description": "Valid input"}
        ]
        
        all_passed = True
        for case in test_cases:
            try:
                response = requests.post(
                    f"{self.api_url}/analyze",
                    json={"text": case["text"]},
                    headers={"Content-Type": "application/json"},
                    timeout=30
                )
                
                success = response.status_code == case["expected_status"]
                details = f"{case['description']} - Status: {response.status_code}, Expected: {case['expected_status']}"
                
                if not success:
                    all_passed = False
                    
                self.log_test(f"Analyze Validation - {case['description']}", success, details)
                
                # If this is the valid case and it passed, save the result for history tests
                if case["expected_status"] == 200 and success:
                    self.sample_analysis = response.json()
                    
            except Exception as e:
                self.log_test(f"Analyze Validation - {case['description']}", False, str(e))
                all_passed = False
                
        return all_passed

    def test_analyze_endpoint_full(self):
        """Test full analyze endpoint with realistic input"""
        test_input = """
        2024-01-15 14:32:11 - WARNING - Failed login attempt for user 'admin' from IP 192.168.1.105
        2024-01-15 14:32:15 - WARNING - Failed login attempt for user 'admin' from IP 192.168.1.105
        2024-01-15 14:32:18 - WARNING - Failed login attempt for user 'admin' from IP 192.168.1.105
        2024-01-15 14:32:22 - CRITICAL - Account 'admin' locked after 3 failed attempts
        """
        
        try:
            print("🔍 Testing AI analysis (this may take 10-15 seconds)...")
            response = requests.post(
                f"{self.api_url}/analyze",
                json={"text": test_input.strip()},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                required_fields = ['id', 'risk', 'explanation', 'fixes', 'timestamp']
                missing_fields = [field for field in required_fields if field not in data]
                
                if missing_fields:
                    success = False
                    details += f", Missing fields: {missing_fields}"
                else:
                    details += f", Risk: {data.get('risk')}, Fixes count: {len(data.get('fixes', []))}"
                    # Validate risk level
                    if data.get('risk') not in ['Low', 'Medium', 'High']:
                        success = False
                        details += f", Invalid risk level: {data.get('risk')}"
                    
                    self.sample_analysis = data
            else:
                try:
                    error_data = response.json()
                    details += f", Error: {error_data.get('detail', 'Unknown error')}"
                except:
                    details += f", Raw response: {response.text[:100]}"
                    
            self.log_test("Full Analysis Test", success, details)
            return success
        except Exception as e:
            self.log_test("Full Analysis Test", False, str(e))
            return False

    def test_history_endpoints(self):
        """Test history-related endpoints"""
        # Test get history
        try:
            response = requests.get(f"{self.api_url}/history", timeout=10)
            success = response.status_code == 200
            details = f"Get History - Status: {response.status_code}"
            
            if success:
                history = response.json()
                details += f", History count: {len(history)}"
                
                # If we have history items, test individual operations
                if history and hasattr(self, 'sample_analysis'):
                    # Test delete individual item
                    analysis_id = self.sample_analysis.get('id')
                    if analysis_id:
                        delete_response = requests.delete(f"{self.api_url}/history/{analysis_id}", timeout=10)
                        delete_success = delete_response.status_code == 200
                        details += f", Delete item: {delete_response.status_code}"
                        
                        if not delete_success:
                            success = False
                            
            self.log_test("History Operations", success, details)
            return success
        except Exception as e:
            self.log_test("History Operations", False, str(e))
            return False

    def test_clear_history(self):
        """Test clear all history"""
        try:
            response = requests.delete(f"{self.api_url}/history", timeout=10)
            success = response.status_code == 200
            details = f"Clear History - Status: {response.status_code}"
            
            if success:
                # Verify history is actually cleared
                get_response = requests.get(f"{self.api_url}/history", timeout=10)
                if get_response.status_code == 200:
                    history = get_response.json()
                    if len(history) == 0:
                        details += ", History successfully cleared"
                    else:
                        success = False
                        details += f", History not cleared, still has {len(history)} items"
                        
            self.log_test("Clear History", success, details)
            return success
        except Exception as e:
            self.log_test("Clear History", False, str(e))
            return False

    def test_rate_limiting(self):
        """Test rate limiting (10 requests per minute)"""
        print("🔍 Testing rate limiting (this may take a moment)...")
        
        # Make multiple rapid requests
        rapid_requests = 0
        rate_limited = False
        
        for i in range(12):  # Try to exceed the 10/minute limit
            try:
                response = requests.post(
                    f"{self.api_url}/analyze",
                    json={"text": f"Test rate limiting request {i} - this is a test input for rate limiting validation."},
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                if response.status_code == 429:  # Rate limited
                    rate_limited = True
                    break
                elif response.status_code == 200:
                    rapid_requests += 1
                    
                time.sleep(0.1)  # Small delay between requests
                
            except Exception as e:
                break
                
        success = rate_limited or rapid_requests <= 10
        details = f"Rapid requests made: {rapid_requests}, Rate limited: {rate_limited}"
        
        self.log_test("Rate Limiting", success, details)
        return success

    def run_all_tests(self):
        """Run all backend tests"""
        print("🚀 Starting SafeScan AI Backend Tests")
        print("=" * 50)
        
        # Test basic connectivity
        if not self.test_root_endpoint():
            print("❌ Basic connectivity failed. Stopping tests.")
            return False
            
        # Test examples
        self.test_examples_endpoint()
        
        # Test analyze endpoint
        self.test_analyze_endpoint_validation()
        self.test_analyze_endpoint_full()
        
        # Test history
        self.test_history_endpoints()
        self.test_clear_history()
        
        # Test rate limiting
        self.test_rate_limiting()
        
        # Print summary
        print("\n" + "=" * 50)
        print(f"📊 Test Summary: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All backend tests PASSED!")
            return True
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests FAILED")
            return False

def main():
    """Main test execution"""
    tester = SafeScanAPITester()
    success = tester.run_all_tests()
    
    # Save detailed results
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump({
            "summary": {
                "total_tests": tester.tests_run,
                "passed_tests": tester.tests_passed,
                "success_rate": f"{(tester.tests_passed/tester.tests_run*100):.1f}%" if tester.tests_run > 0 else "0%",
                "timestamp": datetime.now().isoformat()
            },
            "detailed_results": tester.test_results
        }, f, indent=2)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())