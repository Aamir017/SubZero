import subprocess
import os
import tempfile
import requests
import tldextract
import socket
import random
import string

def enumerate_subdomains(domain):
    """
    Enumerate subdomains using Subfinder and Amass
    Returns a list of discovered subdomains
    """
    subdomains = set()
    
    # Use Subfinder
    subfinder_results = _run_subfinder(domain)
    if subfinder_results:
        subdomains.update(subfinder_results)
    
    # Use Amass
    amass_results = _run_amass(domain)
    if amass_results:
        subdomains.update(amass_results)
    
    # If no results from tools, try alternative methods
    if not subdomains:
        print("No results from Subfinder or Amass, trying alternative methods...")
        
        # Try certificate transparency logs
        ct_results = _check_certificate_transparency(domain)
        if ct_results:
            subdomains.update(ct_results)
        
        # Try common subdomain guessing
        common_results = _guess_common_subdomains(domain)
        if common_results:
            subdomains.update(common_results)
    
    # Always add the main domain itself
    subdomains.add(domain)
    
    return list(subdomains)

def _run_subfinder(domain):
    """Run Subfinder and return results"""
    try:
        # Create a temporary file to store results
        with tempfile.NamedTemporaryFile(delete=False, mode='w+t') as tmp:
            tmp_filename = tmp.name
        
        # Run subfinder command
        cmd = f"subfinder -d {domain} -o {tmp_filename}"
        print(f"Running command: {cmd}")
        subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Read results
        results = []
        if os.path.exists(tmp_filename) and os.path.getsize(tmp_filename) > 0:
            with open(tmp_filename, 'r') as f:
                results = [line.strip() for line in f if line.strip()]
        
        # Clean up
        try:
            os.unlink(tmp_filename)
        except:
            pass
        
        print(f"Subfinder found {len(results)} subdomains")
        return results
    except Exception as e:
        print(f"Error running Subfinder: {e}")
        return []

def _run_amass(domain):
    """Run Amass and return results"""
    try:
        # Create a temporary file to store results
        with tempfile.NamedTemporaryFile(delete=False, mode='w+t') as tmp:
            tmp_filename = tmp.name
        
        # Run amass command with passive mode for faster results
        cmd = f"amass enum -passive -d {domain} -o {tmp_filename}"
        print(f"Running command: {cmd}")
        subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Read results
        results = []
        if os.path.exists(tmp_filename) and os.path.getsize(tmp_filename) > 0:
            with open(tmp_filename, 'r') as f:
                results = [line.strip() for line in f if line.strip()]
        
        # Clean up
        try:
            os.unlink(tmp_filename)
        except:
            pass
        
        print(f"Amass found {len(results)} subdomains")
        return results
    except Exception as e:
        print(f"Error running Amass: {e}")
        return []

def _check_certificate_transparency(domain):
    """Check certificate transparency logs for subdomains"""
    subdomains = set()
    try:
        # Use crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '').lower()
                # Split by newlines and filter valid subdomains
                for subdomain in name.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain.endswith(f'.{domain}') or subdomain == domain:
                        subdomains.add(subdomain)
        
        print(f"Certificate transparency found {len(subdomains)} subdomains")
    except Exception as e:
        print(f"Error checking certificate transparency: {e}")
    
    return list(subdomains)

def _guess_common_subdomains(domain):
    """Guess common subdomains"""
    common_prefixes = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
        'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'portal',
        'admin', 'cdn', 'shop', 'ftp', 'cloud', 'support', 'direct', 'cpanel',
        'webdisk', 'whm', 'autodiscover', 'autoconfig', 'm', 'mobile', 'app'
    ]
    
    subdomains = set()
    
    # Check if common subdomains resolve
    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            subdomains.add(subdomain)
        except:
            pass
    
    print(f"Common subdomain guessing found {len(subdomains)} subdomains")
    return list(subdomains)