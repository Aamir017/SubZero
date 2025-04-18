import os
import time
import json
from datetime import datetime
from subdomain_enum import enumerate_subdomains
from dns_resolver import resolve_dns
from http_analyzer import analyze_http_response
from screenshot import capture_screenshot

class SubdomainTakeoverScanner:
    def __init__(self, domain):
        self.domain = domain
        self.results = []
        self.screenshot_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                          'static', 'screenshots')
        self.history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        'static', 'history.json')
        
        # Ensure screenshot directory exists
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    def run_scan(self):
        """Run the complete subdomain takeover scan process"""
        print(f"Starting scan for {self.domain}")
        
        # Step 1: Enumerate subdomains
        subdomains = enumerate_subdomains(self.domain)
        print(f"Found {len(subdomains)} subdomains")
        
        if not subdomains:
            print("No subdomains found. Adding some common subdomains for testing.")
            # Add some common subdomains for testing
            subdomains = [
                self.domain,
                f"www.{self.domain}",
                f"mail.{self.domain}",
                f"api.{self.domain}",
                f"blog.{self.domain}"
            ]
        
        # Step 2: Process each subdomain
        for subdomain in subdomains:
            # Process for vulnerability
            result = self._process_subdomain(subdomain)
            
            if result:
                # This is a vulnerable subdomain
                self.results.append(result)
            else:
                # Add non-vulnerable subdomain to results too
                dns_info = resolve_dns(subdomain)
                http_info = analyze_http_response(subdomain)
                
                # Capture screenshot for non-vulnerable domains too
                screenshot_path = None
                if http_info.get('status_code'):
                    try:
                        screenshot_filename = f"{subdomain.replace('.', '_')}.png"
                        screenshot_path = os.path.join('screenshots', screenshot_filename)
                        full_path = os.path.join(self.screenshot_dir, screenshot_filename)
                        success = capture_screenshot(subdomain, full_path)
                        if not success or not os.path.exists(full_path) or os.path.getsize(full_path) == 0:
                            print(f"Screenshot failed for {subdomain}")
                            screenshot_path = None
                    except Exception as e:
                        print(f"Error capturing screenshot for {subdomain}: {str(e)}")
                        screenshot_path = None
                
                self.results.append({
                    'subdomain': subdomain,
                    'cname': dns_info.get('cname', 'N/A'),
                    'status_code': http_info.get('status_code', 'N/A'),
                    'service': self._identify_service(dns_info.get('cname', '')),
                    'error_message': http_info.get('error_message', 'N/A'),
                    'screenshot': screenshot_path,
                    'vulnerable': False
                })
        
        print(f"Scan completed. Found {len(self.results)} subdomains, including potentially vulnerable ones")
        
        # Save scan to history
        self._save_to_history()
        
        return self.results
    
    def _process_subdomain(self, subdomain):
        """Process a single subdomain and check for takeover vulnerability"""
        print(f"Processing {subdomain}")
        
        # Step 1: DNS resolution
        dns_info = resolve_dns(subdomain)
        
        # Skip if no CNAME or if properly resolved
        if not dns_info.get('cname') or not dns_info.get('vulnerable_dns'):
            return None
        
        # Step 2: HTTP response analysis
        http_info = analyze_http_response(subdomain)
        
        # Step 3: Capture screenshot
        screenshot_path = None
        if http_info.get('status_code'):  # Only capture screenshot if we got an HTTP response
            try:
                screenshot_filename = f"{subdomain.replace('.', '_')}.png"
                screenshot_path = os.path.join('screenshots', screenshot_filename)
                full_path = os.path.join(self.screenshot_dir, screenshot_filename)
                success = capture_screenshot(subdomain, full_path)
                if not success or not os.path.exists(full_path) or os.path.getsize(full_path) == 0:
                    print(f"Screenshot failed for {subdomain}")
                    screenshot_path = None
            except Exception as e:
                print(f"Error capturing screenshot for {subdomain}: {str(e)}")
                screenshot_path = None
        
        # Determine vulnerability status
        is_vulnerable = self._check_vulnerability(dns_info, http_info)
        
        # Prepare result
        if is_vulnerable:
            return {
                'subdomain': subdomain,
                'cname': dns_info.get('cname', 'N/A'),
                'status_code': http_info.get('status_code', 'N/A'),
                'service': self._identify_service(dns_info.get('cname', '')),
                'error_message': http_info.get('error_message', 'N/A'),
                'screenshot': screenshot_path,
                'vulnerable': is_vulnerable
            }
        
        return None
    
    def _check_vulnerability(self, dns_info, http_info):
        """Determine if a subdomain is vulnerable to takeover"""
        # Check for common vulnerability indicators
        
        # DNS indicators
        if dns_info.get('vulnerable_dns'):
            # NXDOMAIN or dangling CNAME
            return True
        
        # HTTP indicators
        if http_info.get('status_code') in [404, 503]:
            # Common error status codes
            return True
        
        # Check for service-specific error messages
        error_patterns = [
            "NoSuchBucket", 
            "No such app",
            "There isn't a GitHub Pages site here",
            "The specified bucket does not exist",
            "Repository not found",
            "Heroku | No such app"
        ]
        
        if http_info.get('error_message'):
            for pattern in error_patterns:
                if pattern.lower() in http_info.get('error_message', '').lower():
                    return True
        
        return False
    
    def _identify_service(self, cname):
        """Identify the service based on CNAME"""
        # Ensure cname is a string to prevent 'NoneType' is not iterable error
        if cname is None:
            cname = ""
            
        service_patterns = {
            's3.amazonaws.com': 'AWS S3',
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'azurewebsites.net': 'Azure App Service',
            'cloudfront.net': 'AWS CloudFront',
            'netlify.app': 'Netlify',
            'shopify.com': 'Shopify',
            'zendesk.com': 'Zendesk',
            'statuspage.io': 'Statuspage',
            'fastly.net': 'Fastly'
        }
        
        for pattern, service in service_patterns.items():
            if pattern in cname:
                return service
        
        return 'Unknown'
    
    def _save_to_history(self):
        """Save scan results to history file"""
        try:
            # Create history entry
            history_entry = {
                'domain': self.domain,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'subdomains_count': len(self.results),
                'vulnerable_count': sum(1 for result in self.results if result.get('vulnerable')),
                'results': self.results
            }
            
            # Load existing history
            history = []
            if os.path.exists(self.history_file):
                try:
                    with open(self.history_file, 'r') as f:
                        history = json.load(f)
                except json.JSONDecodeError:
                    # If file is corrupted, start with empty history
                    history = []
            
            # Add new entry
            history.append(history_entry)
            
            # Save updated history
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
            print(f"Scan saved to history")
        except Exception as e:
            print(f"Error saving to history: {str(e)}")

def get_scan_history():
    """Get all scan history entries"""
    history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'static', 'history.json')
    
    if not os.path.exists(history_file):
        return []
    
    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
        return history
    except Exception as e:
        print(f"Error loading history: {str(e)}")
        return []