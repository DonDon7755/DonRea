"""
Alert system for Ransomware Detection & Mitigation Framework.
Handles alert generation, processing, and notifications.
"""

import os
import time
import logging
import threading
import json
from datetime import datetime

# Get logger
logger = logging.getLogger(__name__)

# Global variables
alert_system_active = False
alert_thread = None
db_instance = None


def initialize(database_instance):
    """Initialize the alert system."""
    global db_instance
    
    db_instance = database_instance
    
    logger.info("Alert system initialized")
    
    return True


def start_alert_system(user_id=None):
    """Start the alert monitoring system."""
    global alert_system_active, alert_thread
    
    if alert_system_active:
        logger.info("Alert system already active")
        return True
    
    try:
        alert_system_active = True
        
        # Start alert monitoring thread
        alert_thread = threading.Thread(target=_alert_monitor, args=(user_id,), daemon=True)
        alert_thread.start()
        
        logger.info("Alert system started")
        if db_instance:
            db_instance.add_log("Alert system started", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error starting alert system: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error starting alert system: {str(e)}", "ERROR", user_id)
        alert_system_active = False
        return False


def stop_alert_system(user_id=None):
    """Stop the alert monitoring system."""
    global alert_system_active
    
    if not alert_system_active:
        logger.info("Alert system already inactive")
        return True
    
    try:
        alert_system_active = False
        
        logger.info("Alert system stopped")
        if db_instance:
            db_instance.add_log("Alert system stopped", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error stopping alert system: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error stopping alert system: {str(e)}", "ERROR", user_id)
        return False


def _alert_monitor(user_id=None):
    """Monitor for new alerts and send them to users."""
    global alert_system_active
    
    # Interval in seconds between alert checks
    interval = 60
    
    # Time of last check
    last_check_time = datetime.now()
    
    try:
        # Get interval from settings if available
        if db_instance:
            setting = db_instance.get_setting('alert_check_interval', str(interval))
            try:
                interval = int(setting)
            except (ValueError, TypeError):
                interval = 60
        
        while alert_system_active:
            try:
                # Current time
                current_time = datetime.now()
                
                # Get new alerts since last check
                if db_instance:
                    # Convert datetime to string for SQLite comparison
                    last_check_str = last_check_time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Get unacknowledged alerts
                    alerts = db_instance.get_alerts(acknowledged=False)
                    
                    # Process each alert
                    for alert in alerts:
                        _process_alert(alert, user_id)
                
                # Update last check time
                last_check_time = current_time
                
                # Sleep until next check
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in alert monitor cycle: {str(e)}")
                if db_instance:
                    db_instance.add_log(f"Error in alert monitor cycle: {str(e)}", "ERROR", user_id)
                time.sleep(interval)
                
    except Exception as e:
        logger.error(f"Error in alert monitor: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error in alert monitor: {str(e)}", "ERROR", user_id)
        alert_system_active = False


def _process_alert(alert, user_id=None):
    """Process a single alert."""
    try:
        # Log alert processing
        logger.info(f"Processing alert ID {alert['id']}: {alert['message']} (Severity: {alert['severity']})")
        
        # In a real implementation, you would:
        # 1. Send notification to the UI
        # 2. Send email/SMS notifications if configured
        # 3. Trigger automated response actions
        
        # For this demo, we'll just log the alert
        if db_instance:
            db_instance.add_log(
                f"Alert processed - ID {alert['id']}: {alert['message']} (Severity: {alert['severity']})",
                "INFO",
                user_id
            )
        
        # Handle critical alerts with automated responses
        if alert['severity'] == "CRITICAL":
            # Example: quarantine file if this is a file-related alert
            if alert['file_path'] and os.path.exists(alert['file_path']):
                logger.info(f"Critical alert detected for file: {alert['file_path']}")
                
                # Check auto-quarantine setting
                if db_instance:
                    auto_quarantine = db_instance.get_setting('enable_auto_quarantine', 'False')
                    if auto_quarantine and auto_quarantine.lower() == 'true':
                        import quarantine
                        quarantine.quarantine_file(alert['file_path'], user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error processing alert {alert['id']}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error processing alert {alert['id']}: {str(e)}", "ERROR", user_id)
        return False


def send_alert(message, severity, file_path=None, process_name=None, user_id=None, detection_result_id=None):
    """Send a manual alert."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return None
        
        # Validate severity
        valid_severities = ["INFO", "WARNING", "CRITICAL"]
        if severity not in valid_severities:
            severity = "INFO"
        
        # Add alert to database
        alert_id = db_instance.add_alert(
            message,
            severity,
            file_path=file_path,
            process_name=process_name,
            user_id=user_id,
            detection_result_id=detection_result_id
        )
        
        # Log alert creation
        logger.info(f"Alert created - ID {alert_id}: {message} (Severity: {severity})")
        db_instance.add_log(
            f"Alert created - ID {alert_id}: {message} (Severity: {severity})",
            "INFO",
            user_id
        )
        
        return alert_id
        
    except Exception as e:
        logger.error(f"Error sending alert: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error sending alert: {str(e)}", "ERROR", user_id)
        return None


def acknowledge_alert(alert_id, user_id=None):
    """Mark an alert as acknowledged."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return False
        
        # Acknowledge alert in database
        success = db_instance.acknowledge_alert(alert_id, user_id)
        
        if success:
            logger.info(f"Alert ID {alert_id} acknowledged by user {user_id}")
        else:
            logger.warning(f"Failed to acknowledge alert ID {alert_id}")
        
        return success
        
    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error acknowledging alert {alert_id}: {str(e)}", "ERROR", user_id)
        return False


def get_active_alerts(limit=10, user_id=None):
    """Get active (unacknowledged) alerts."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return []
        
        # Get unacknowledged alerts from database
        alerts = db_instance.get_alerts(limit=limit, acknowledged=False)
        
        return alerts
        
    except Exception as e:
        logger.error(f"Error getting active alerts: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error getting active alerts: {str(e)}", "ERROR", user_id)
        return []


def get_alert_history(limit=50, user_id=None):
    """Get alert history (all alerts)."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return []
        
        # Get all alerts from database
        alerts = db_instance.get_alerts(limit=limit)
        
        return alerts
        
    except Exception as e:
        logger.error(f"Error getting alert history: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error getting alert history: {str(e)}", "ERROR", user_id)
        return []


# Optional: Add notification methods for different channels

def send_email_notification(alert, email_address):
    """Send an email notification for an alert."""
    logger.info(f"Email notification would be sent to {email_address} for alert {alert['id']}")
    # In a real implementation, you would use smtplib or an email service API
    return True


def send_desktop_notification(alert):
    """Send a desktop notification for an alert."""
    logger.info(f"Desktop notification would be shown for alert {alert['id']}")
    # In a real implementation, you would use platform-specific notification APIs
    return True