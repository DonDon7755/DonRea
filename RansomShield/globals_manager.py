"""
Global variables manager for Ransomware Detection & Mitigation Framework.
Centralizes access to global state to avoid circular import issues.
"""

# Global variables
cnn_model = None
lstm_model = None
CNN_THRESHOLD = 0.7  # Default value
LSTM_THRESHOLD = 0.6  # Default value
file_monitoring_active = False
process_monitoring_active = False
monitor_thread = None
quarantine_dir = "quarantine"
current_user = None  # Store current logged in user

def get_current_user():
    """Get the current user safely."""
    return current_user

def set_current_user(user):
    """Set the current user."""
    global current_user
    current_user = user

def get_current_user_id():
    """Get the current user ID safely."""
    if current_user and 'id' in current_user:
        return current_user['id']
    return None

def is_admin():
    """Check if current user is admin."""
    if current_user and 'is_admin' in current_user:
        return current_user['is_admin']
    return False

def get_username():
    """Get the current username safely."""
    if current_user and 'username' in current_user:
        return current_user['username']
    return 'Guest'

def reset_user():
    """Reset the current user to None."""
    global current_user
    current_user = None

def set_monitoring_active(file_active=None, process_active=None):
    """Set monitoring status."""
    global file_monitoring_active, process_monitoring_active
    
    if file_active is not None:
        file_monitoring_active = file_active
    
    if process_active is not None:
        process_monitoring_active = process_active

def get_file_monitoring_active():
    """Get file monitoring status."""
    return file_monitoring_active

def get_process_monitoring_active():
    """Get process monitoring status."""
    return process_monitoring_active

def set_model_thresholds(cnn=None, lstm=None):
    """Set model thresholds."""
    global CNN_THRESHOLD, LSTM_THRESHOLD
    
    if cnn is not None:
        CNN_THRESHOLD = cnn
    
    if lstm is not None:
        LSTM_THRESHOLD = lstm

def get_cnn_threshold():
    """Get CNN threshold."""
    return CNN_THRESHOLD

def get_lstm_threshold():
    """Get LSTM threshold."""
    return LSTM_THRESHOLD

def set_quarantine_directory(directory):
    """Set quarantine directory."""
    global quarantine_dir
    quarantine_dir = directory

def get_quarantine_directory():
    """Get quarantine directory."""
    return quarantine_dir