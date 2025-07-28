#!/usr/bin/env python3
"""
Comprehensive Backend Testing for Earning Platform
Tests all critical backend components including authentication, wallet, M-Pesa, tasks, referrals, and notifications.
"""

import requests
import json
import time
import uuid
from datetime import datetime

# Configuration
BASE_URL = "https://f3a1880b-f45f-456a-9089-b54b7e9cc185.preview.emergentagent.com/api"
HEADERS = {"Content-Type": "application/json"}

class BackendTester:
    def __init__(self):
        self.base_url = BASE_URL
        self.headers = HEADERS.copy()
        self.test_results = []
        self.auth_token = None
        self.user_data = None
        self.referrer_token = None
        self.referrer_data = None
        
    def log_result(self, test_name, success, message, details=None):
        """Log test result"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method, endpoint, data=None, auth_required=False):
        """Make HTTP request with error handling"""
        url = f"{self.base_url}{endpoint}"
        headers = self.headers.copy()
        
        if auth_required and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=30)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=30)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=headers, json=data, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response
        except requests.exceptions.RequestException as e:
            return None, str(e)
    
    def test_user_registration(self):
        """Test user registration with referral code"""
        print("\n=== Testing User Registration ===")
        
        # First create a referrer user
        referrer_data = {
            "email": f"referrer_{uuid.uuid4().hex[:8]}@example.com",
            "password": "SecurePass123!",
            "full_name": "John Referrer",
            "phone": f"+254{uuid.uuid4().hex[:9]}"
        }
        
        response = self.make_request("POST", "/auth/register", referrer_data)
        if response and response.status_code == 200:
            referrer_result = response.json()
            self.referrer_token = referrer_result.get("token")
            self.referrer_data = referrer_result.get("user")
            referral_code = self.referrer_data.get("referral_code")
            
            self.log_result("Referrer Registration", True, 
                          f"Referrer registered successfully with code: {referral_code}")
            
            # Now register main user with referral code
            user_data = {
                "email": f"testuser_{uuid.uuid4().hex[:8]}@example.com",
                "password": "SecurePass123!",
                "full_name": "Jane Doe",
                "phone": f"+254{uuid.uuid4().hex[:9]}",
                "referral_code": referral_code
            }
            
            response = self.make_request("POST", "/auth/register", user_data)
            if response and response.status_code == 200:
                result = response.json()
                self.auth_token = result.get("token")
                self.user_data = result.get("user")
                
                # Verify response structure
                required_fields = ["token", "user", "success", "message"]
                missing_fields = [field for field in required_fields if field not in result]
                
                if missing_fields:
                    self.log_result("User Registration", False, 
                                  f"Missing fields in response: {missing_fields}", result)
                else:
                    self.log_result("User Registration", True, 
                                  f"User registered successfully with referral", 
                                  {"user_id": self.user_data.get("user_id"), 
                                   "referral_code": self.user_data.get("referral_code")})
            else:
                error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
                self.log_result("User Registration", False, f"Registration failed: {error_msg}")
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Referrer Registration", False, f"Referrer registration failed: {error_msg}")
    
    def test_user_login(self):
        """Test user login and JWT token validation"""
        print("\n=== Testing User Login ===")
        
        if not self.user_data:
            self.log_result("User Login", False, "No user data available for login test")
            return
        
        login_data = {
            "email": self.user_data["email"],
            "password": "SecurePass123!"
        }
        
        response = self.make_request("POST", "/auth/login", login_data)
        if response and response.status_code == 200:
            result = response.json()
            token = result.get("token")
            
            if token:
                self.auth_token = token  # Update token
                self.log_result("User Login", True, "Login successful, JWT token received")
                
                # Test JWT token validation by making authenticated request
                self.test_jwt_validation()
            else:
                self.log_result("User Login", False, "No token in login response", result)
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("User Login", False, f"Login failed: {error_msg}")
    
    def test_jwt_validation(self):
        """Test JWT token validation"""
        print("\n=== Testing JWT Token Validation ===")
        
        if not self.auth_token:
            self.log_result("JWT Validation", False, "No auth token available")
            return
        
        response = self.make_request("GET", "/dashboard/stats", auth_required=True)
        if response and response.status_code == 200:
            self.log_result("JWT Validation", True, "JWT token validated successfully")
        elif response and response.status_code == 401:
            self.log_result("JWT Validation", False, "JWT token validation failed - Unauthorized")
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("JWT Validation", False, f"JWT validation error: {error_msg}")
    
    def test_dashboard_stats(self):
        """Test dashboard statistics retrieval"""
        print("\n=== Testing Dashboard Statistics ===")
        
        response = self.make_request("GET", "/dashboard/stats", auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            
            # Check required fields
            required_fields = ["success", "user", "recent_transactions", "referral_stats", "notifications"]
            missing_fields = [field for field in required_fields if field not in result]
            
            if missing_fields:
                self.log_result("Dashboard Stats", False, 
                              f"Missing fields: {missing_fields}", result)
            else:
                user_info = result["user"]
                self.log_result("Dashboard Stats", True, 
                              f"Dashboard stats retrieved successfully", 
                              {"balance": user_info.get("wallet_balance"), 
                               "activated": user_info.get("is_activated")})
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Dashboard Stats", False, f"Dashboard stats failed: {error_msg}")
    
    def test_mpesa_deposit(self):
        """Test M-Pesa deposit initiation and simulation"""
        print("\n=== Testing M-Pesa Deposit System ===")
        
        # Test deposit initiation
        deposit_data = {
            "amount": 500.0,
            "phone": "+254712345678"
        }
        
        response = self.make_request("POST", "/payments/deposit", deposit_data, auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            transaction_id = result.get("transaction_id")
            
            if transaction_id:
                self.log_result("M-Pesa Deposit Initiation", True, 
                              f"Deposit initiated successfully", 
                              {"transaction_id": transaction_id, "amount": deposit_data["amount"]})
                
                # Test deposit simulation
                self.test_deposit_simulation(transaction_id)
            else:
                self.log_result("M-Pesa Deposit Initiation", False, 
                              "No transaction ID in response", result)
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("M-Pesa Deposit Initiation", False, f"Deposit initiation failed: {error_msg}")
    
    def test_deposit_simulation(self, transaction_id):
        """Test deposit simulation for testing purposes"""
        print("\n=== Testing Deposit Simulation ===")
        
        # Wait a moment before simulating
        time.sleep(1)
        
        response = self.make_request("POST", f"/payments/simulate-deposit-success?transaction_id={transaction_id}", 
                                   auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            new_balance = result.get("new_balance")
            is_activated = result.get("is_activated")
            
            self.log_result("Deposit Simulation", True, 
                          f"Deposit simulation successful", 
                          {"new_balance": new_balance, "activated": is_activated})
            
            # Update user activation status for subsequent tests
            if self.user_data:
                self.user_data["is_activated"] = is_activated
                self.user_data["wallet_balance"] = new_balance
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Deposit Simulation", False, f"Deposit simulation failed: {error_msg}")
    
    def test_task_system(self):
        """Test task retrieval and completion"""
        print("\n=== Testing Task System ===")
        
        # Test getting available tasks
        response = self.make_request("GET", "/tasks/available", auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            tasks = result.get("tasks", [])
            
            if tasks:
                self.log_result("Task Retrieval", True, 
                              f"Retrieved {len(tasks)} available tasks")
                
                # Test task completion with first task
                self.test_task_completion(tasks[0])
            else:
                self.log_result("Task Retrieval", False, "No tasks available")
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Task Retrieval", False, f"Task retrieval failed: {error_msg}")
    
    def test_task_completion(self, task):
        """Test completing a specific task"""
        print("\n=== Testing Task Completion ===")
        
        completion_data = {
            "task_id": task["task_id"],
            "completion_data": {
                "completed_at": datetime.now().isoformat(),
                "user_response": "Task completed successfully"
            }
        }
        
        response = self.make_request("POST", "/tasks/complete", completion_data, auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            reward = result.get("reward")
            
            self.log_result("Task Completion", True, 
                          f"Task completed successfully", 
                          {"task_title": task["title"], "reward": reward})
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Task Completion", False, f"Task completion failed: {error_msg}")
    
    def test_referral_system(self):
        """Test referral system functionality"""
        print("\n=== Testing Referral System ===")
        
        response = self.make_request("GET", "/referrals/stats", auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            stats = result.get("stats", {})
            
            required_fields = ["total_referrals", "referral_code", "referrals"]
            missing_fields = [field for field in required_fields if field not in stats]
            
            if missing_fields:
                self.log_result("Referral System", False, 
                              f"Missing fields in referral stats: {missing_fields}", stats)
            else:
                self.log_result("Referral System", True, 
                              f"Referral stats retrieved successfully", 
                              {"total_referrals": stats["total_referrals"], 
                               "referral_code": stats["referral_code"]})
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Referral System", False, f"Referral system test failed: {error_msg}")
    
    def test_wallet_system(self):
        """Test wallet balance and transaction tracking"""
        print("\n=== Testing Wallet System ===")
        
        # Get current dashboard to check wallet balance
        response = self.make_request("GET", "/dashboard/stats", auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            user_info = result.get("user", {})
            
            wallet_fields = ["wallet_balance", "total_earned", "total_withdrawn"]
            missing_fields = [field for field in wallet_fields if field not in user_info]
            
            if missing_fields:
                self.log_result("Wallet System", False, 
                              f"Missing wallet fields: {missing_fields}", user_info)
            else:
                self.log_result("Wallet System", True, 
                              f"Wallet system working correctly", 
                              {"balance": user_info["wallet_balance"], 
                               "earned": user_info["total_earned"]})
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Wallet System", False, f"Wallet system test failed: {error_msg}")
    
    def test_withdrawal_system(self):
        """Test withdrawal functionality"""
        print("\n=== Testing Withdrawal System ===")
        
        # Only test if user has sufficient balance and is activated
        if not self.user_data or not self.user_data.get("is_activated"):
            self.log_result("Withdrawal System", False, "User not activated for withdrawal test")
            return
        
        if self.user_data.get("wallet_balance", 0) < 100:
            self.log_result("Withdrawal System", False, "Insufficient balance for withdrawal test")
            return
        
        withdrawal_data = {
            "amount": 100.0,
            "phone": "+254712345678",
            "reason": "Test withdrawal"
        }
        
        response = self.make_request("POST", "/payments/withdraw", withdrawal_data, auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            transaction_id = result.get("transaction_id")
            
            if transaction_id:
                self.log_result("Withdrawal System", True, 
                              f"Withdrawal request submitted successfully", 
                              {"transaction_id": transaction_id, "amount": withdrawal_data["amount"]})
            else:
                self.log_result("Withdrawal System", False, 
                              "No transaction ID in withdrawal response", result)
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Withdrawal System", False, f"Withdrawal failed: {error_msg}")
    
    def test_notification_system(self):
        """Test notification creation and retrieval"""
        print("\n=== Testing Notification System ===")
        
        # Test getting notifications
        response = self.make_request("GET", "/notifications", auth_required=True)
        if response and response.status_code == 200:
            result = response.json()
            notifications = result.get("notifications", [])
            
            self.log_result("Notification Retrieval", True, 
                          f"Retrieved {len(notifications)} notifications")
            
            # Test creating a notification (admin endpoint)
            self.test_notification_creation()
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Notification Retrieval", False, f"Notification retrieval failed: {error_msg}")
    
    def test_notification_creation(self):
        """Test notification creation"""
        print("\n=== Testing Notification Creation ===")
        
        notification_data = {
            "title": "Test Notification",
            "message": "This is a test notification from backend testing",
            "user_id": self.user_data.get("user_id") if self.user_data else None
        }
        
        response = self.make_request("POST", "/notifications/create", notification_data)
        if response and response.status_code == 200:
            self.log_result("Notification Creation", True, "Notification created successfully")
        else:
            error_msg = response.json().get("detail", "Unknown error") if response else "Request failed"
            self.log_result("Notification Creation", False, f"Notification creation failed: {error_msg}")
    
    def run_all_tests(self):
        """Run all backend tests in sequence"""
        print("🚀 Starting Comprehensive Backend Testing...")
        print(f"Backend URL: {self.base_url}")
        print("=" * 60)
        
        # Run tests in logical order
        self.test_user_registration()
        self.test_user_login()
        self.test_dashboard_stats()
        self.test_wallet_system()
        self.test_mpesa_deposit()
        self.test_task_system()
        self.test_referral_system()
        self.test_withdrawal_system()
        self.test_notification_system()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("🏁 BACKEND TESTING SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result["success"])
        failed = len(self.test_results) - passed
        
        print(f"Total Tests: {len(self.test_results)}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"Success Rate: {(passed/len(self.test_results)*100):.1f}%")
        
        if failed > 0:
            print("\n🔍 FAILED TESTS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  ❌ {result['test']}: {result['message']}")
        
        print("\n📊 DETAILED RESULTS:")
        for result in self.test_results:
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {result['test']}: {result['message']}")

if __name__ == "__main__":
    tester = BackendTester()
    tester.run_all_tests()