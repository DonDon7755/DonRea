"""
Process monitoring system for Ransomware Detection & Mitigation Framework.
Monitors running processes for suspicious activity.
"""

import os
import time
import logging
import threading
from datetime import datetime

# Try to import psutil for process monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Get logger
logger = logging.getLogger(__name__)

# Global variables
monitor_active = False
monitor_thread = None
db_instance = None
detection_engine = None

# Suspicious process characteristics
SUSPICIOUS_PROCESS_NAMES = [
    "cryptor", "crypt", "ransom", "wcry", "wanna", 
    "lock", "encryptor", "decrypt", "locker"
]

# Monitoring interval in seconds
MONITORING_INTERVAL = 10


def initialize(database_instance, engine_instance):
    """Initialize the process monitoring system."""
    global db_instance, detection_engine
    
    db_instance = database_instance
    detection_engine = engine_instance
    
    logger.info("Process monitoring system initialized")
    
    return True


def monitor_processes(user_id=None):
    """Monitor running processes for suspicious activity."""
    if not HAS_PSUTIL:
        logger.warning("psutil module not available. Process monitoring disabled.")
        if db_instance:
            db_instance.add_log("Process monitoring disabled - psutil module not available", "WARNING", user_id)
        return []
    
    try:
        suspicious_processes = []
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
            try:
                # Get process info
                proc_info = proc.info
                pid = proc_info['pid']
                name = proc_info['name'].lower() if proc_info['name'] else ""
                cmdline = " ".join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ""
                
                # Skip system processes
                if name in ["system", "svchost.exe", "smss.exe", "csrss.exe", "services.exe", "lsass.exe"]:
                    continue
                
                # Check for suspicious process names
                if any(suspicious in name for suspicious in SUSPICIOUS_PROCESS_NAMES) or \
                   any(suspicious in cmdline for suspicious in SUSPICIOUS_PROCESS_NAMES):
                    
                    # Get more details
                    try:
                        exe_path = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = "Unknown"
                    
                    # Log suspicious process
                    logger.warning(f"Suspicious process detected: {name} (PID: {pid})")
                    if db_instance:
                        db_instance.add_log(f"Suspicious process detected: {name} (PID: {pid})", "WARNING", user_id)
                        db_instance.add_alert(
                            f"Suspicious process detected: {name} (PID: {pid})",
                            "WARNING",
                            process_name=name,
                            user_id=user_id
                        )
                    
                    # Add to list
                    suspicious_processes.append({
                        'pid': pid,
                        'name': name,
                        'cmdline': cmdline,
                        'path': exe_path,
                        'username': proc_info['username'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
                    # Analyze executable if available
                    if exe_path != "Unknown" and os.path.exists(exe_path):
                        logger.info(f"Analyzing suspicious process executable: {exe_path}")
                        if detection_engine:
                            detection_engine.detect_file(exe_path, user_id)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return suspicious_processes
        
    except Exception as e:
        logger.error(f"Error monitoring processes: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error monitoring processes: {str(e)}", "ERROR", user_id)
        return []


def start_monitoring(user_id=None):
    """Start process monitoring."""
    global monitor_active, monitor_thread
    
    if not HAS_PSUTIL:
        logger.warning("psutil module not available. Process monitoring disabled.")
        if db_instance:
            db_instance.add_log("Process monitoring disabled - psutil module not available", "WARNING", user_id)
        return False
    
    if monitor_active:
        logger.info("Process monitoring already active")
        return True
    
    try:
        monitor_active = True
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=_monitoring_worker, args=(user_id,), daemon=True)
        monitor_thread.start()
        
        logger.info("Process monitoring started")
        if db_instance:
            db_instance.add_log("Process monitoring started", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error starting process monitoring: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error starting process monitoring: {str(e)}", "ERROR", user_id)
        monitor_active = False
        return False


def stop_monitoring(user_id=None):
    """Stop process monitoring."""
    global monitor_active
    
    if not monitor_active:
        logger.info("Process monitoring already inactive")
        return True
    
    try:
        monitor_active = False
        
        logger.info("Process monitoring stopped")
        if db_instance:
            db_instance.add_log("Process monitoring stopped", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error stopping process monitoring: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error stopping process monitoring: {str(e)}", "ERROR", user_id)
        return False


def _monitoring_worker(user_id=None):
    """Worker thread for continuous process monitoring."""
    global monitor_active
    
    interval = MONITORING_INTERVAL
    
    try:
        # Get interval from settings if available
        if db_instance:
            setting = db_instance.get_setting('process_monitoring_interval', str(interval))
            try:
                interval = int(setting)
            except (ValueError, TypeError):
                interval = MONITORING_INTERVAL
        
        while monitor_active:
            # Monitor processes
            monitor_processes(user_id)
            
            # Sleep until next check
            time.sleep(interval)
            
    except Exception as e:
        logger.error(f"Error in process monitoring worker: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error in process monitoring worker: {str(e)}", "ERROR", user_id)
        monitor_active = False


def monitor_process_creation(interval=3600, user_id=None):
    """Monitor for newly created processes at regular intervals."""
    if not HAS_PSUTIL:
        logger.warning("psutil module not available. Process creation monitoring disabled.")
        return
    
    def process_creation_worker():
        try:
            # Previous process list
            previous_processes = set(p.pid for p in psutil.process_iter())
            
            while True:
                # Sleep for the interval
                time.sleep(interval)
                
                # Current process list
                current_processes = set(p.pid for p in psutil.process_iter())
                
                # New processes
                new_processes = current_processes - previous_processes
                
                # Check new processes
                for pid in new_processes:
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name().lower()
                        
                        # Check if suspicious
                        if any(suspicious in name for suspicious in SUSPICIOUS_PROCESS_NAMES):
                            logger.warning(f"Suspicious new process detected: {name} (PID: {pid})")
                            if db_instance:
                                db_instance.add_log(f"Suspicious new process detected: {name} (PID: {pid})", "WARNING", user_id)
                                db_instance.add_alert(
                                    f"Suspicious new process detected: {name} (PID: {pid})",
                                    "WARNING",
                                    process_name=name,
                                    user_id=user_id
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Update previous process list
                previous_processes = current_processes
                
        except Exception as e:
            logger.error(f"Error monitoring process creation: {str(e)}")
            if db_instance:
                db_instance.add_log(f"Error monitoring process creation: {str(e)}", "ERROR", user_id)
    
    # Start thread
    thread = threading.Thread(target=process_creation_worker, daemon=True)
    thread.start()
    
    logger.info("Process creation monitoring started")
    if db_instance:
        db_instance.add_log("Process creation monitoring started", "INFO", user_id)
    
    return thread