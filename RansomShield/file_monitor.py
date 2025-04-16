"""
File monitoring system for Ransomware Detection & Mitigation Framework.
Monitors the file system for suspicious changes.
"""

import os
import time
import logging
import threading
from datetime import datetime

# Try to import watchdog for file system monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

# Get logger
logger = logging.getLogger(__name__)

# Global variables
monitor_active = False
observer = None
db_instance = None
detection_engine = None

# Directories to monitor (can be configured)
monitor_dirs = []
DEFAULT_MONITOR_DIRS = [os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads")]


class RansomwareFileHandler(FileSystemEventHandler):
    """Handles file system events for ransomware detection."""
    
    def __init__(self, user_id=None):
        self.user_id = user_id
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self._analyze_file(event.src_path, "created")
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            self._analyze_file(event.src_path, "modified")
    
    def _analyze_file(self, file_path, action):
        """Analyze a file for ransomware indicators."""
        global detection_engine, db_instance
        
        if not detection_engine or not db_instance:
            logger.error("Detection engine or database not initialized")
            return
        
        try:
            # Check if file matches monitored extensions
            from config import MONITOR_EXTENSIONS
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext not in MONITOR_EXTENSIONS:
                return
            
            # Log the event
            logger.info(f"File {action}: {file_path}")
            db_instance.add_log(f"File {action}: {file_path}", "INFO", self.user_id)
            
            # Analyze the file
            result = detection_engine.detect_file(file_path, self.user_id)
            
            if result and result["risk_level"] >= 0.7:  # High risk
                # File is high risk, alert the user
                db_instance.add_alert(
                    f"Suspicious file {action}: {file_path}",
                    "CRITICAL",
                    file_path=file_path,
                    user_id=self.user_id
                )
                
                # Check for auto-quarantine setting
                auto_quarantine = db_instance.get_setting('enable_auto_quarantine', 'False')
                if auto_quarantine and auto_quarantine.lower() == 'true':
                    import quarantine
                    quarantine.quarantine_file(file_path, self.user_id)
            
        except Exception as e:
            logger.error(f"Error analyzing {action} file {file_path}: {str(e)}")
            if db_instance:
                db_instance.add_log(f"Error analyzing {action} file {file_path}: {str(e)}", "ERROR", self.user_id)


def initialize(database_instance, engine_instance, dirs_to_monitor=None):
    """Initialize the file monitoring system."""
    global db_instance, detection_engine, monitor_dirs
    
    db_instance = database_instance
    detection_engine = engine_instance
    
    # Set directories to monitor
    if dirs_to_monitor:
        monitor_dirs = dirs_to_monitor
    else:
        monitor_dirs = DEFAULT_MONITOR_DIRS
    
    logger.info("File monitoring system initialized")
    
    return True


def start_monitoring(user_id=None):
    """Start file system monitoring."""
    global monitor_active, observer
    
    if not HAS_WATCHDOG:
        logger.warning("Watchdog module not available. File monitoring disabled.")
        if db_instance:
            db_instance.add_log("File monitoring disabled - Watchdog module not available", "WARNING", user_id)
        return False
    
    if monitor_active:
        logger.info("File monitoring already active")
        return True
    
    try:
        observer = Observer()
        event_handler = RansomwareFileHandler(user_id)
        
        # Set up monitoring for each directory
        for directory in monitor_dirs:
            if os.path.exists(directory):
                observer.schedule(event_handler, directory, recursive=True)
                logger.info(f"Monitoring directory: {directory}")
                if db_instance:
                    db_instance.add_log(f"Started monitoring directory: {directory}", "INFO", user_id)
            else:
                logger.warning(f"Directory not found: {directory}")
                if db_instance:
                    db_instance.add_log(f"Cannot monitor directory (not found): {directory}", "WARNING", user_id)
        
        # Start the observer
        observer.start()
        monitor_active = True
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=_monitoring_heartbeat, args=(user_id,), daemon=True)
        heartbeat_thread.start()
        
        logger.info("File monitoring started")
        if db_instance:
            db_instance.add_log("File monitoring started", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error starting file monitoring: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error starting file monitoring: {str(e)}", "ERROR", user_id)
        return False


def stop_monitoring(user_id=None):
    """Stop file system monitoring."""
    global monitor_active, observer
    
    if not monitor_active:
        logger.info("File monitoring already inactive")
        return True
    
    try:
        if observer:
            observer.stop()
            observer.join()
            observer = None
        
        monitor_active = False
        
        logger.info("File monitoring stopped")
        if db_instance:
            db_instance.add_log("File monitoring stopped", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error stopping file monitoring: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error stopping file monitoring: {str(e)}", "ERROR", user_id)
        return False


def _monitoring_heartbeat(user_id=None):
    """Send heartbeat to ensure monitoring is still active."""
    global monitor_active
    
    interval = 3600  # 1 hour
    
    try:
        # Get interval from settings if available
        if db_instance:
            setting = db_instance.get_setting('monitoring_heartbeat_interval', str(interval))
            try:
                interval = int(setting)
            except (ValueError, TypeError):
                interval = 3600
        
        while monitor_active:
            logger.debug("File monitoring heartbeat")
            if db_instance:
                db_instance.add_log("File monitoring heartbeat", "DEBUG", user_id)
            
            # Sleep until next heartbeat
            time.sleep(interval)
            
    except Exception as e:
        logger.error(f"Error in monitoring heartbeat: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error in monitoring heartbeat: {str(e)}", "ERROR", user_id)


def add_directory(directory, user_id=None):
    """Add a directory to monitor."""
    global monitor_dirs, observer
    
    if not os.path.exists(directory):
        logger.warning(f"Directory not found: {directory}")
        if db_instance:
            db_instance.add_log(f"Cannot monitor directory (not found): {directory}", "WARNING", user_id)
        return False
    
    # Add to list of monitored directories
    if directory not in monitor_dirs:
        monitor_dirs.append(directory)
        
        # If monitoring is active, schedule the directory
        if monitor_active and observer:
            event_handler = RansomwareFileHandler(user_id)
            observer.schedule(event_handler, directory, recursive=True)
        
        logger.info(f"Added directory to monitoring: {directory}")
        if db_instance:
            db_instance.add_log(f"Added directory to monitoring: {directory}", "INFO", user_id)
        
        return True
    
    return False


def remove_directory(directory, user_id=None):
    """Remove a directory from monitoring."""
    global monitor_dirs
    
    if directory in monitor_dirs:
        monitor_dirs.remove(directory)
        
        # If monitoring is active, we need to restart it to apply changes
        if monitor_active:
            stop_monitoring(user_id)
            start_monitoring(user_id)
        
        logger.info(f"Removed directory from monitoring: {directory}")
        if db_instance:
            db_instance.add_log(f"Removed directory from monitoring: {directory}", "INFO", user_id)
        
        return True
    
    return False