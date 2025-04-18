import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException, TimeoutException

def capture_screenshot(url, output_path):
    """
    Capture a screenshot of a website
    Returns True if successful, False otherwise
    """
    if not url.startswith('http'):
        url = f'http://{url}'
    
    print(f"Capturing screenshot of {url}")
    
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1280,800')
    options.add_argument('--ignore-certificate-errors')
    
    try:
        # Use webdriver_manager to handle driver installation
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        # Set page load timeout
        driver.set_page_load_timeout(20)
        
        try:
            driver.get(url)
            # Wait for page to load
            time.sleep(3)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Take screenshot
            driver.save_screenshot(output_path)
            
            # Verify screenshot was created and has content
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                print(f"Screenshot saved to {output_path}")
                return True
            else:
                print(f"Screenshot file is empty or not created: {output_path}")
                return False
                
        except TimeoutException:
            print(f"Timeout while loading {url}")
            # Try to capture what loaded before timeout
            try:
                driver.save_screenshot(output_path)
                return os.path.exists(output_path) and os.path.getsize(output_path) > 0
            except:
                return False
        except Exception as e:
            print(f"Error capturing screenshot: {str(e)}")
            return False
        finally:
            driver.quit()
    except Exception as e:
        print(f"Error initializing WebDriver: {str(e)}")
        return False