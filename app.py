from flask import Flask, render_template, request, redirect, url_for, flash
from scanner import SubdomainTakeoverScanner, get_scan_history
import os

app = Flask(__name__, template_folder='docs', static_folder='docs/static')
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain', '').strip()
    
    if not domain:
        flash('Please enter a domain to scan', 'danger')
        return redirect(url_for('index'))
    
    # Remove http:// or https:// if present
    if domain.startswith('http://'):
        domain = domain[7:]
    elif domain.startswith('https://'):
        domain = domain[8:]
    
    # Remove trailing slash if present
    if domain.endswith('/'):
        domain = domain[:-1]
    
    # Create scanner and run scan
    scanner = SubdomainTakeoverScanner(domain)
    results = scanner.run_scan()
    
    return render_template('results.html', domain=domain, results=results)

@app.route('/history')
def history():
    scan_history = get_scan_history()
    return render_template('history.html', history=scan_history)

@app.route('/history/<int:index>')
def history_detail(index):
    scan_history = get_scan_history()
    
    if 0 <= index < len(scan_history):
        entry = scan_history[index]
        return render_template('results.html', 
                              domain=entry['domain'], 
                              results=entry['results'],
                              timestamp=entry['timestamp'],
                              from_history=True)
    else:
        flash('History entry not found', 'danger')
        return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(debug=True)