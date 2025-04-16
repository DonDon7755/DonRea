// Admin.js - Admin functionality for ransomware detection framework

document.addEventListener('DOMContentLoaded', function() {
    // Initialize components
    initSettingsForm();
    initLogsTable();
    initQuarantineTable();
    initDetectionResultsTable();
    initSystemStats();
});

// Initialize settings form
function initSettingsForm() {
    const settingsForm = document.getElementById('settingsForm');
    
    if (settingsForm) {
        settingsForm.addEventListener('submit', function(e) {
            // Show loading indicator
            document.getElementById('saveSettingsBtn').disabled = true;
            document.getElementById('saveSettingsBtn').innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Saving...';
        });
    }
}

// Initialize logs table with DataTables
function initLogsTable() {
    const logsTable = document.getElementById('logsTable');
    
    if (logsTable) {
        $(logsTable).DataTable({
            order: [[0, 'desc']],
            responsive: true,
            pageLength: 15,
            lengthMenu: [15, 30, 50, 100],
            dom: '<"d-flex justify-content-between align-items-center mb-3"<"d-flex align-items-center"l><"d-flex align-items-center"f>>t<"d-flex justify-content-between align-items-center mt-3"<"d-flex align-items-center"i><"d-flex align-items-center"p>>',
            language: {
                search: "_INPUT_",
                searchPlaceholder: "Search logs...",
                lengthMenu: "_MENU_ per page",
                info: "Showing _START_ to _END_ of _TOTAL_ logs",
                infoEmpty: "No logs found",
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

// Initialize quarantine table with DataTables
function initQuarantineTable() {
    const quarantineTable = document.getElementById('quarantineTable');
    
    if (quarantineTable) {
        $(quarantineTable).DataTable({
            order: [[0, 'desc']],
            responsive: true,
            pageLength: 10,
            lengthMenu: [10, 25, 50, 100],
            dom: '<"d-flex justify-content-between align-items-center mb-3"<"d-flex align-items-center"l><"d-flex align-items-center"f>>t<"d-flex justify-content-between align-items-center mt-3"<"d-flex align-items-center"i><"d-flex align-items-center"p>>',
            language: {
                search: "_INPUT_",
                searchPlaceholder: "Search quarantined files...",
                lengthMenu: "_MENU_ per page",
                info: "Showing _START_ to _END_ of _TOTAL_ files",
                infoEmpty: "No quarantined files found",
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

// Initialize detection results table with DataTables
function initDetectionResultsTable() {
    const resultsTable = document.getElementById('detectionResultsTable');
    
    if (resultsTable) {
        $(resultsTable).DataTable({
            order: [[0, 'desc']],
            responsive: true,
            pageLength: 10,
            lengthMenu: [10, 25, 50, 100],
            dom: '<"d-flex justify-content-between align-items-center mb-3"<"d-flex align-items-center"l><"d-flex align-items-center"f>>t<"d-flex justify-content-between align-items-center mt-3"<"d-flex align-items-center"i><"d-flex align-items-center"p>>',
            language: {
                search: "_INPUT_",
                searchPlaceholder: "Search detection results...",
                lengthMenu: "_MENU_ per page",
                info: "Showing _START_ to _END_ of _TOTAL_ results",
                infoEmpty: "No detection results found",
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

// Initialize system statistics
function initSystemStats() {
    const systemStatsElement = document.getElementById('systemStats');
    
    if (systemStatsElement) {
        const systemStatsData = JSON.parse(systemStatsElement.getAttribute('data-stats') || '[]');
        
        const labels = systemStatsData.map(item => item.date);
        const cpuUsage = systemStatsData.map(item => item.cpu);
        const memoryUsage = systemStatsData.map(item => item.memory);
        
        const systemStatsChart = new Chart(systemStatsElement.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'CPU Usage (%)',
                        data: cpuUsage,
                        borderColor: 'rgba(13, 110, 253, 1)',
                        backgroundColor: 'rgba(13, 110, 253, 0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Memory Usage (%)',
                        data: memoryUsage,
                        borderColor: 'rgba(40, 167, 69, 1)',
                        backgroundColor: 'rgba(40, 167, 69, 0.1)',
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
                        max: 100,
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

// Restore file from quarantine
function restoreFile(itemId) {
    if (!confirm('Are you sure you want to restore this file? This may reintroduce potentially malicious content.')) {
        return;
    }
    
    const btn = document.querySelector(`button[data-restore-id="${itemId}"]`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    }
    
    fetch(`/restore_file/${itemId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove item from table
            const row = document.querySelector(`tr[data-item-id="${itemId}"]`);
            if (row) {
                row.remove();
            } else {
                // Reload the page if we can't find the row to remove
                window.location.reload();
            }
        } else {
            alert('Failed to restore file: ' + (data.message || 'Unknown error'));
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = 'Restore';
            }
        }
    })
    .catch(error => {
        console.error('Error restoring file:', error);
        alert('An error occurred while restoring the file');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = 'Restore';
        }
    });
}

// Delete file from quarantine
function deleteFile(itemId) {
    if (!confirm('Are you sure you want to permanently delete this file? This action cannot be undone.')) {
        return;
    }
    
    const btn = document.querySelector(`button[data-delete-id="${itemId}"]`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    }
    
    fetch(`/delete_file/${itemId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove item from table
            const row = document.querySelector(`tr[data-item-id="${itemId}"]`);
            if (row) {
                row.remove();
            } else {
                // Reload the page if we can't find the row to remove
                window.location.reload();
            }
        } else {
            alert('Failed to delete file: ' + (data.message || 'Unknown error'));
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = 'Delete';
            }
        }
    })
    .catch(error => {
        console.error('Error deleting file:', error);
        alert('An error occurred while deleting the file');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = 'Delete';
        }
    });
}

// Quarantine a file based on detection result
function quarantineFile(resultId) {
    const btn = document.querySelector(`button[data-quarantine-id="${resultId}"]`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    }
    
    fetch(`/quarantine_file/${resultId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update UI to show file is quarantined
            const row = document.querySelector(`tr[data-result-id="${resultId}"]`);
            if (row) {
                row.querySelector('.result-status').innerHTML = '<span class="badge bg-warning">Quarantined</span>';
                btn.outerHTML = '<span class="text-muted">Quarantined</span>';
            } else {
                // Reload the page if we can't find the row to update
                window.location.reload();
            }
        } else {
            alert('Failed to quarantine file: ' + (data.message || 'Unknown error'));
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = 'Quarantine';
            }
        }
    })
    .catch(error => {
        console.error('Error quarantining file:', error);
        alert('An error occurred while quarantining the file');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = 'Quarantine';
        }
    });
}
