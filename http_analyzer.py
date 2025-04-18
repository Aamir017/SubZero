import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

def analyze_http_response(subdomain):
    """
    Analyze HTTP response for a subdomain
    Returns a dictionary with HTTP information
    """
    result = {
        'status_code': None,
        'error_message': None,
        'page_title': None,
        'headers': {}
    }
    
    try:
        # Try HTTP and HTTPS
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                result['status_code'] = response.status_code
                result['headers'] = dict(response.headers)
                
                # Parse HTML content
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Get page title
                    title_tag = soup.find('title')
                    if title_tag:
                        result['page_title'] = title_tag.text.strip()
                    
                    # Extract potential error messages
                    error_messages = []
                    
                    # Look for common error containers
                    error_containers = soup.select('.error, .not-found, #error, #not-found')
                    for container in error_containers:
                        error_messages.append(container.text.strip())
                    
                    # Look for specific error keywords in the page
                    body_text = soup.body.text.lower() if soup.body else ''
                    error_keywords = [
                        'no such bucket', 
                        'not found', 
                        'doesn\'t exist',
                        'no such app',
                        'isn\'t a github pages site',
                        'the specified bucket does not exist',
                        'repository not found',
                        'heroku | no such app'
                    ]
                    
                    for keyword in error_keywords:
                        if keyword in body_text:
                            error_messages.append(f"Found error keyword: {keyword}")
                    
                    if error_messages:
                        result['error_message'] = ' | '.join(error_messages)
                
                # Successfully got a response, no need to try the other protocol
                break
                
            except RequestException:
                # Try the other protocol
                continue
    
    except Exception as e:
        result['error_message'] = str(e)
    
    return result