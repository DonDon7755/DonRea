// Dashboard.js - Dashboard functionality for ransomware detection framework

document.addEventListener('DOMContentLoaded', function() {
    // Initialize components
    initCharts();
    initAlertsTable();
    initScanForm();
    initTabs();
    initAlertRefresh();
});

// Initialize dashboard charts
function initCharts() {
    // Only initialize charts if the elements exist
    const threatStatsElement = document.getElementById('threatStats');
    const scanHistoryElement = document.getElementById('scanHistory');
    
    if (threatStatsElement) {
        // Threat statistics chart
        const threatStatsChart = new Chart(threatStatsElement.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk'],
                datasets: [{
                    data: [
                        threatStatsElement.getAttribute('data-low') || 0,
                        threatStatsElement.getAttribute('data-medium') || 0,
                        threatStatsElement.getAttribute('data-high') || 0
                    ],
                    backgroundColor: [
                        'rgba(40, 167, 69, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(220, 53, 69, 0.8)'
                    ],
                    borderColor: [
                        'rgba(40, 167, 69, 1)',
                        'rgba(255, 193, 7, 1)',
                        'rgba(220, 53, 69, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.7)',
                        titleColor: '#fff',
                        bodyColor: '#fff'
                    }
                }
            }
        });
    }
    
    if (scanHistoryElement) {
        // Scan history chart
        const scanHistoryData = JSON.parse(scanHistoryElement.getAttribute('data-history') || '[]');
        
        const labels = scanHistoryData.map(item => item.date);
        const scannedFiles = scanHistoryData.map(item => item.scanned);
        const detectedThreats = scanHistoryData.map(item => item.detected);
        
        const scanHistoryChart = new Chart(scanHistoryElement.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Scanned Files',
                        data: scannedFiles,
                        borderColor: 'rgba(13, 110, 253, 1)',
                        backgroundColor: 'rgba(13, 110, 253, 0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Detected Threats',
                        data: detectedThreats,
                        borderColor: 'rgba(220, 53, 69, 1)',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.7)',
                        titleColor: '#fff',
                        bodyColor: '#fff'
                    }
                }
            }
        });
    }
}

// Initialize alerts table with DataTables
function initAlertsTable() {
    const alertsTable = document.getElementById('alertsTable');
    
    if (alertsTable) {
        $(alertsTable).DataTable({
            order: [[0, 'desc']],
            responsive: true,
            pageLength: 10,
            lengthMenu: [5, 10, 25, 50],
            dom: '<"d-flex justify-content-between align-items-center mb-3"<"d-flex align-items-center"l><"d-flex align-items-center"f>>t<"d-flex justify-content-between align-items-center mt-3"<"d-flex align-items-center"i><"d-flex align-items-center"p>>',
            language: {
                search: "_INPUT_",
                searchPlaceholder: "Search alerts...",
                lengthMenu: "_MENU_ per page",
                info: "Showing _START_ to _END_ of _TOTAL_ alerts",
                infoEmpty: "No alerts found",
                paginate: {
                    first: '<i class="fas fa-angle-double-left"></i>',
                    last: '<i class="fas fa-angle-double-right"></i>',
                    previous: '<i class="fas fa-angle-left"></i>',
                    next: '<i class="fas fa-angle-right"></i>'
                }
            }
        });
    }
}

// Initialize scan form
function initScanForm() {
    const scanForm = document.getElementById('scanForm');
    
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            const scanPath = document.getElementById('scanPath').value;
            
            if (!scanPath) {
                e.preventDefault();
                alert('Please enter a path to scan');
                return false;
            }
            
            // Show loading indicator
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanBtn').innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Scanning...';
        });
    }
}

// Initialize dashboard tabs
function initTabs() {
    const tabLinks = document.querySelectorAll('.nav-link');
    
    if (tabLinks.length > 0) {
        tabLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Remove active class from all tabs
                tabLinks.forEach(tab => tab.classList.remove('active'));
                
                // Add active class to clicked tab
                this.classList.add('active');
                
                // Show corresponding tab content
                const tabId = this.getAttribute('href').substring(1);
                document.querySelectorAll('.tab-pane').forEach(pane => {
                    pane.classList.remove('show', 'active');
                });
                document.getElementById(tabId).classList.add('show', 'active');
            });
        });
    }
}

// Setup auto-refresh for alerts
function initAlertRefresh() {
    // Auto-refresh alerts every 60 seconds
    const alertsContainer = document.getElementById('alertsContainer');
    
    if (alertsContainer) {
        setInterval(function() {
            fetch('/dashboard?partial=alerts')
                .then(response => response.text())
                .then(html => {
                    alertsContainer.innerHTML = html;
                })
                .catch(error => {
                    console.error('Error refreshing alerts:', error);
                });
        }, 60000);
    }
}

// Acknowledge an alert
function acknowledgeAlert(alertId) {
    fetch(`/acknowledge_alert/${alertId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update UI to show alert is acknowledged
            const alertRow = document.querySelector(`tr[data-alert-id="${alertId}"]`);
            if (alertRow) {
                alertRow.querySelector('.alert-status').innerHTML = '<span class="badge bg-success">Acknowledged</span>';
                alertRow.querySelector('.alert-actions').innerHTML = '<i class="fas fa-check-circle text-success"></i> Processed';
            }
        } else {
            alert('Failed to acknowledge alert');
        }
    })
    .catch(error => {
        console.error('Error acknowledging alert:', error);
        alert('An error occurred while acknowledging the alert');
    });
}

// Toggle monitoring status
function toggleMonitoring() {
    const toggleBtn = document.getElementById('monitoringToggle');
    
    if (toggleBtn) {
        toggleBtn.disabled = true;
        toggleBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Processing...';
        
        fetch('/toggle_monitoring', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update UI based on new monitoring status
                const newStatus = data.monitoring_enabled;
                const statusElement = document.getElementById('monitoringStatus');
                
                if (newStatus) {
                    statusElement.innerHTML = '<span class="badge bg-success">Enabled</span>';
                    toggleBtn.innerHTML = 'Disable Monitoring';
                    toggleBtn.classList.replace('btn-success', 'btn-danger');
                } else {
                    statusElement.innerHTML = '<span class="badge bg-danger">Disabled</span>';
                    toggleBtn.innerHTML = 'Enable Monitoring';
                    toggleBtn.classList.replace('btn-danger', 'btn-success');
                }
            } else {
                alert('Failed to toggle monitoring status');
                toggleBtn.innerHTML = toggleBtn.classList.contains('btn-success') ? 'Enable Monitoring' : 'Disable Monitoring';
            }
            
            toggleBtn.disabled = false;
        })
        .catch(error => {
            console.error('Error toggling monitoring status:', error);
            alert('An error occurred while toggling monitoring status');
            toggleBtn.disabled = false;
            toggleBtn.innerHTML = toggleBtn.classList.contains('btn-success') ? 'Enable Monitoring' : 'Disable Monitoring';
        });
    }
}
