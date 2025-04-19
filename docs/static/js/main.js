document.addEventListener('DOMContentLoaded', function() {
    // Add loading indicator for scan form
    const scanForm = document.querySelector('form[action*="scan"]');
    if (scanForm) {
        scanForm.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
            submitBtn.disabled = true;
            
            // Add a loading overlay
            const overlay = document.createElement('div');
            overlay.className = 'loading-overlay';
            overlay.innerHTML = `
                <div class="spinner-border text-light" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-3 text-light">Scanning subdomains, please wait...</p>
            `;
            document.body.appendChild(overlay);
        });
    }
    
    // Enable tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Results page filtering
    const showAllBtn = document.getElementById('show-all');
    const showVulnerableBtn = document.getElementById('show-vulnerable');
    const showSecureBtn = document.getElementById('show-secure');
    const vulnerableRows = document.querySelectorAll('.vulnerable-row');
    const secureRows = document.querySelectorAll('.secure-row');
    
    if (showAllBtn && showVulnerableBtn && showSecureBtn) {
        showAllBtn.addEventListener('click', function() {
            vulnerableRows.forEach(row => row.style.display = '');
            secureRows.forEach(row => row.style.display = '');
            
            showAllBtn.classList.add('active');
            showVulnerableBtn.classList.remove('active');
            showSecureBtn.classList.remove('active');
        });
        
        showVulnerableBtn.addEventListener('click', function() {
            vulnerableRows.forEach(row => row.style.display = '');
            secureRows.forEach(row => row.style.display = 'none');
            
            showAllBtn.classList.remove('active');
            showVulnerableBtn.classList.add('active');
            showSecureBtn.classList.remove('active');
        });
        
        showSecureBtn.addEventListener('click', function() {
            vulnerableRows.forEach(row => row.style.display = 'none');
            secureRows.forEach(row => row.style.display = '');
            
            showAllBtn.classList.remove('active');
            showVulnerableBtn.classList.remove('active');
            showSecureBtn.classList.add('active');
        });
    }
    
    // Export to CSV functionality
    const exportCsvBtn = document.getElementById('export-csv');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', function() {
            const table = document.getElementById('results-table');
            if (!table) return;
            
            let csv = [];
            const rows = table.querySelectorAll('tr');
            
            for (let i = 0; i < rows.length; i++) {
                let row = [], cols = rows[i].querySelectorAll('td, th');
                
                for (let j = 0; j < cols.length; j++) {
                    // Get the text content, removing any special characters that might break the CSV
                    let text = cols[j].textContent.replace(/"/g, '""').trim();
                    row.push('"' + text + '"');
                }
                
                csv.push(row.join(','));
            }
            
            const csvString = csv.join('\n');
            const domain = document.querySelector('.domain-highlight').textContent;
            const filename = `subdomain_scan_${domain}_${new Date().toISOString().slice(0,10)}.csv`;
            
            const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            
            if (navigator.msSaveBlob) { // IE 10+
                navigator.msSaveBlob(blob, filename);
            } else {
                const url = URL.createObjectURL(blob);
                link.href = url;
                link.setAttribute('download', filename);
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        });
    }
    
    // Add animation to elements when they come into view
    const animateOnScroll = function() {
        const elements = document.querySelectorAll('.animate__animated:not(.animate__fadeIn)');
        elements.forEach(element => {
            const position = element.getBoundingClientRect();
            if (position.top < window.innerHeight) {
                element.classList.add('animate__fadeIn');
            }
        });
    };
    
    window.addEventListener('scroll', animateOnScroll);
    animateOnScroll(); // Run once on page load
});

// Add this to the CSS file
document.head.insertAdjacentHTML('beforeend', `
<style>
.loading-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.7);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    z-index: 9999;
}
</style>
`);