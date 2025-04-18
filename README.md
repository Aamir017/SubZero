
# SubZero

A professional security tool for identifying subdomain takeover vulnerabilities. This web application helps security professionals and organizations detect potential subdomain takeover vulnerabilities by scanning domains and analyzing their DNS configurations.


## 📋Features

 **Comprehensive Subdomain Scanning**: Discover subdomains associated with a target domain
- **Vulnerability Detection**: Automatically identify subdomains vulnerable to takeover
- **Service Identification**: Recognize the services associated with vulnerable subdomains (AWS S3, GitHub Pages, Heroku, etc.)
- **Detailed Reporting**: Get comprehensive reports with vulnerability status, CNAME records, and HTTP status codes
- **Remediation Guidance**: Receive specific remediation steps based on the identified service
- **History Tracking**: Access previous scan results for comparison and tracking
- **Export Functionality**: Export results in CSV format for further analysis
- **Responsive Design**: User-friendly interface that works on desktop and mobile devices


##  🚀 Getting Started


## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
## Installation

1. Clone the repository:
```
    git clone https://github.com/Aamir017/SubZero.git
    cd SubZero
```
2.  Create and activate a virtual environment (recommended):

```
    python -m venv venv
    venv\Scripts\activate
```

3.   Install the required dependencies:

```
    pip install -r requirements.txt
```

4.    Run the application:

```
    python app.py
```
5. Access the application in your web browser at 
```
http://localhost:5000
```

## 🔍 Usage

- Enter the target domain (e.g., example.com) in the input field on the homepage
- Click "Scan Domain" to initiate the scanning process
- View the results, which include:
- Summary statistics (total subdomains, vulnerable, secure)
- Detailed table of all discovered subdomains
- Vulnerability status for each subdomain
- CNAME records and associated services
- HTTP status codes and error messages
- Use the search functionality to filter results
- Click on "Details" to view more information about a specific subdomain
- Export results as CSV or print them for documentation



## 🛠️ Remediation

The application provides specific remediation steps for vulnerable subdomains based on the identified service:

- AWS S3 : Instructions for creating and configuring S3 buckets
- GitHub Pages : Steps to set up GitHub Pages correctly
- Heroku : Guidance on creating and deploying Heroku applications
- Generic : General recommendations for securing DNS configurations
##  🔒 Security Considerations

This tool is designed for legitimate security testing and assessment purposes. Always ensure you have proper authorization before scanning domains that you do not own.

## 

⚠️ Disclaimer : This tool is for educational and professional security assessment purposes only. The authors are not responsible for any misuse or damage caused by this tool.