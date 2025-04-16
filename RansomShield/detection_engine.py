"""
Detection Engine for Ransomware Detection & Mitigation Framework.
Handles the loading of ML models and file analysis functionality.
"""
import os
import json
import logging
import hashlib
import math
import threading
import time
from datetime import datetime
import globals_manager

# Import these conditionally as they may not be available in all environments
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    # Simple log2 replacement if numpy is not available
    def log2(x):
        return math.log(x, 2) if x > 0 else 0

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

# Get logger
logger = logging.getLogger(__name__)

# Global variables
cnn_model = None
lstm_model = None
# Thresholds now managed by globals_manager

# Alert levels from config (imported here to avoid circular dependencies)
ALERT_LEVELS = {
    "LOW": 0.3,
    "MEDIUM": 0.5,
    "HIGH": 0.7
}

# Maximum file size to scan (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

# Database instance (will be set during initialization)
db_instance = None

def initialize(database_instance, cnn_threshold=0.7, lstm_threshold=0.6):
    """Initialize the detection engine with configuration."""
    global db_instance
    db_instance = database_instance
    
    # Set thresholds in globals_manager
    globals_manager.set_model_thresholds(cnn=cnn_threshold, lstm=lstm_threshold)
    
    # Load models
    load_models()
    logger.info("Detection engine initialized")
    
    return True

def load_models():
    """Load the pre-trained CNN and LSTM models"""
    global cnn_model, lstm_model
    
    if not HAS_TENSORFLOW:
        logger.warning("TensorFlow not available. Models will not be loaded.")
        return False
    
    try:
        # Path to model files (adjust as needed)
        cnn_model_path = os.path.join("models", "cnn_model.h5")
        lstm_model_path = os.path.join("models", "lstm_model.h5")
        
        # Check if model files exist
        if os.path.exists(cnn_model_path) and os.path.exists(lstm_model_path):
            # Load models
            cnn_model = tf.keras.models.load_model(cnn_model_path)
            lstm_model = tf.keras.models.load_model(lstm_model_path)
            logger.info("ML models loaded successfully")
            return True
        else:
            logger.warning("Model files not found. Using simulated predictions.")
            return False
            
    except Exception as e:
        logger.error(f"Error loading models: {str(e)}")
        return False

def extract_file_features(file_path):
    """Extract features from a file for model input"""
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        # Get file size for basic filtering
        file_size = os.path.getsize(file_path)
        
        # Skip files that are too large
        if file_size > MAX_FILE_SIZE:
            logger.info(f"File too large to scan: {file_path} ({file_size} bytes)")
            return None
        
        # Calculate entropy
        entropy = calculate_entropy(file_path)
        
        # Default features if no PE analysis is possible
        features = {
            # PE header features
            'DebugSize': 0,
            'DebugRVA': 0,
            'MajorImageVersion': 0,
            'MajorOSVersion': 0,
            'ExportRVA': 0,
            'ExportSize': 0,
            'IatVRA': 0,
            'MajorLinkerVersion': 0,
            'MinorLinkerVersion': 0,
            'NumberOfSections': 0,
            'SizeOfStackReserve': 0,
            'DllCharacteristics': 0,
            'ResourceSize': 0,
            # Basic file info
            'file_size': file_size,
            'entropy': entropy
        }
        
        # If it's a PE file and pefile module is available, extract PE-specific features
        if HAS_PEFILE and os.path.splitext(file_path)[1].lower() in ['.exe', '.dll', '.sys']:
            try:
                pe = pefile.PE(file_path)
                
                # Extract specific PE header features
                features.update({
                    'DebugSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'DebugRVA': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'MajorOSVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'ExportRVA': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'ExportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'IatVRA': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].VirtualAddress if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'NumberOfSections': len(pe.sections) if hasattr(pe, 'sections') else 0,
                    'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                    'ResourceSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size if hasattr(pe, 'OPTIONAL_HEADER') else 0,
                })
                
            except Exception as e:
                logger.warning(f"Error parsing PE file {file_path}: {str(e)}")
        
        return features
        
    except Exception as e:
        logger.error(f"Error extracting features from {file_path}: {str(e)}")
        return None

def calculate_entropy(file_path):
    """Calculate Shannon entropy of a file"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 1024)  # Read first 1MB for efficiency
            
        if not data:
            return 0
            
        entropy = 0
        byte_counts = {}
        file_size = len(data)
        
        # Count occurrences of each byte
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            probability = count / file_size
            if probability > 0:
                if HAS_NUMPY:
                    entropy -= probability * np.log2(probability)
                else:
                    entropy -= probability * log2(probability)
        
        return entropy
        
    except Exception as e:
        logger.error(f"Error calculating entropy for {file_path}: {str(e)}")
        return 0

def preprocess_features_for_cnn(features):
    """Prepare features for CNN model input"""
    if not HAS_NUMPY:
        logger.warning("NumPy not available. Using basic list for features.")
        # Return a basic list with the 13 specific features
        return [
            features['DebugSize'],
            features['DebugRVA'],
            features['MajorImageVersion'],
            features['MajorOSVersion'],
            features['ExportRVA'],
            features['ExportSize'],
            features['IatVRA'],
            features['MajorLinkerVersion'],
            features['MinorLinkerVersion'],
            features['NumberOfSections'],
            features['SizeOfStackReserve'],
            features['DllCharacteristics'],
            features['ResourceSize']
        ]
    
    # Create numpy array with the 13 features
    feature_array = np.array([
        features['DebugSize'],
        features['DebugRVA'],
        features['MajorImageVersion'],
        features['MajorOSVersion'],
        features['ExportRVA'],
        features['ExportSize'],
        features['IatVRA'],
        features['MajorLinkerVersion'],
        features['MinorLinkerVersion'],
        features['NumberOfSections'],
        features['SizeOfStackReserve'],
        features['DllCharacteristics'],
        features['ResourceSize']
    ])
    
    # Normalize features
    feature_array = feature_array.reshape(1, -1)
    
    return feature_array

def preprocess_features_for_lstm(features):
    """Prepare features for LSTM model input"""
    if not HAS_NUMPY:
        # Same as CNN for simplicity in this demo
        return preprocess_features_for_cnn(features)
    
    # For LSTM models, we might need a different shape
    # This would depend on your specific LSTM model's requirements
    feature_array = np.array([
        features['DebugSize'],
        features['DebugRVA'],
        features['MajorImageVersion'],
        features['MajorOSVersion'],
        features['ExportRVA'],
        features['ExportSize'],
        features['IatVRA'],
        features['MajorLinkerVersion'],
        features['MinorLinkerVersion'],
        features['NumberOfSections'],
        features['SizeOfStackReserve'],
        features['DllCharacteristics'],
        features['ResourceSize']
    ])
    
    # Reshape for LSTM input (assuming time steps of 1 and 13 features)
    feature_array = feature_array.reshape(1, 1, 13)
    
    return feature_array

def detect_file(file_path, user_id=None):
    """Analyze a file using CNN and LSTM models"""
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        # Calculate file hash and size
        file_hash = calculate_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        # Extract features
        features = extract_file_features(file_path)
        if not features:
            logger.warning(f"Unable to extract features from {file_path}")
            return None
        
        # Format features for model input
        cnn_input = preprocess_features_for_cnn(features)
        lstm_input = preprocess_features_for_lstm(features)
        
        # Get predictions from models (or simulate if models not loaded)
        if HAS_TENSORFLOW and cnn_model and lstm_model:
            # Use actual models
            cnn_score = float(cnn_model.predict(cnn_input)[0][0])
            lstm_score = float(lstm_model.predict(lstm_input)[0][0])
        else:
            # Simulate predictions based on file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in ['.exe', '.dll']:
                import random
                cnn_score = min(1.0, max(0.0, 0.85 + random.uniform(-0.2, 0.2)))
                lstm_score = min(1.0, max(0.0, 0.78 + random.uniform(-0.2, 0.2)))
            elif file_ext in ['.bat', '.cmd', '.ps1']:
                import random
                cnn_score = min(1.0, max(0.0, 0.72 + random.uniform(-0.2, 0.2)))
                lstm_score = min(1.0, max(0.0, 0.68 + random.uniform(-0.2, 0.2)))
            else:
                import random
                cnn_score = min(1.0, max(0.0, 0.25 + random.uniform(-0.2, 0.2)))
                lstm_score = min(1.0, max(0.0, 0.35 + random.uniform(-0.2, 0.2)))
        
        # Combine scores (you may adjust the weights as needed)
        combined_score = 0.6 * cnn_score + 0.4 * lstm_score
        
        # Determine detection method
        if cnn_score >= globals_manager.get_cnn_threshold() and lstm_score >= globals_manager.get_lstm_threshold():
            detection_method = "Combined"
        elif cnn_score >= globals_manager.get_cnn_threshold():
            detection_method = "CNN"
        elif lstm_score >= globals_manager.get_lstm_threshold():
            detection_method = "LSTM"
        else:
            detection_method = "None" if combined_score < ALERT_LEVELS["LOW"] else "Heuristic"
        
        # Store result in database
        if db_instance:
            result_id = db_instance.add_detection_result(
                file_path, 
                file_hash, 
                file_size, 
                combined_score, 
                detection_method, 
                json.dumps(features)
            )
            
            # Generate alert if risk level is high enough
            if combined_score >= ALERT_LEVELS["LOW"]:
                severity = "INFO"
                if combined_score >= ALERT_LEVELS["HIGH"]:
                    severity = "CRITICAL"
                elif combined_score >= ALERT_LEVELS["MEDIUM"]:
                    severity = "WARNING"
                
                db_instance.add_alert(
                    f"Potential ransomware detected in file {file_path}",
                    severity,
                    file_path=file_path,
                    user_id=user_id,
                    detection_result_id=result_id
                )
                
                # Add log
                db_instance.add_log(
                    f"File {file_path} detected with risk level {combined_score:.2f}",
                    "WARNING" if combined_score >= ALERT_LEVELS["MEDIUM"] else "INFO",
                    user_id=user_id
                )
                
                # Check for auto-quarantine
                if combined_score >= ALERT_LEVELS["HIGH"]:
                    auto_quarantine = db_instance.get_setting('enable_auto_quarantine', 'False')
                    if auto_quarantine and auto_quarantine.lower() == 'true':
                        # Import here to avoid circular imports
                        import quarantine
                        quarantine.quarantine_file(file_path, user_id)
        
        # Return result
        return {
            "file_path": file_path,
            "file_hash": file_hash,
            "file_size": file_size,
            "risk_level": combined_score,
            "cnn_score": cnn_score,
            "lstm_score": lstm_score,
            "detection_method": detection_method,
            "features": features
        }
            
    except Exception as e:
        logger.error(f"Error detecting file {file_path}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error analyzing file {file_path}: {str(e)}", "ERROR", user_id)
        return None

def scan_directory(directory_path, user_id=None):
    """Scan a directory recursively for suspicious files"""
    from config import MONITOR_EXTENSIONS, IGNORE_PATHS
    
    try:
        logger.info(f"Starting scan on directory: {directory_path}")
        
        if db_instance:
            db_instance.add_log(f"Starting scan on directory: {directory_path}", "INFO", user_id)
        
        files_scanned = 0
        threats_found = 0
        results = []
        
        # Walk through the directory
        for root, _, files in os.walk(directory_path):
            # Skip ignored paths
            if any(ignored in root for ignored in IGNORE_PATHS):
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Only scan files with monitored extensions
                file_ext = os.path.splitext(file_path)[1].lower()
                if file_ext not in MONITOR_EXTENSIONS:
                    continue
                
                try:
                    # Analyze the file
                    result = detect_file(file_path, user_id)
                    
                    if result:
                        files_scanned += 1
                        results.append(result)
                        
                        if result["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
                            threats_found += 1
                            
                except Exception as e:
                    logger.error(f"Error scanning file {file_path}: {str(e)}")
        
        # Log scan completion
        if db_instance:
            db_instance.add_log(
                f"Scan completed on {directory_path}. Files scanned: {files_scanned}, Threats found: {threats_found}", 
                "INFO", 
                user_id
            )
        
        logger.info(f"Scan completed. Files scanned: {files_scanned}, Threats found: {threats_found}")
        
        return {
            "directory": directory_path,
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Error scanning directory {directory_path}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error scanning directory {directory_path}: {str(e)}", "ERROR", user_id)
        return None

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {str(e)}")
        return "error-calculating-hash"

def detect_process(process_id, user_id=None):
    """Analyze a process for suspicious behavior"""
    try:
        # This is a placeholder - in a real implementation, you would:
        # 1. Get the process executable path
        # 2. Check memory usage, network connections, etc.
        # 3. Run the executable through the file detection
        # 4. Monitor for suspicious behavior like encrypting files
        
        logger.info(f"Process detection not fully implemented. Process ID: {process_id}")
        
        if db_instance:
            db_instance.add_log(f"Process detection called on PID {process_id}", "INFO", user_id)
        
        return {
            "process_id": process_id,
            "risk_level": 0,
            "detection_method": "Not implemented"
        }
        
    except Exception as e:
        logger.error(f"Error detecting process {process_id}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error detecting process {process_id}: {str(e)}", "ERROR", user_id)
        return None

# Scheduled scan functionality
def start_scheduled_scanning(interval=3600):
    """Start scheduled scanning thread"""
    def scanning_worker():
        while True:
            try:
                # Get directories to scan from config/settings
                # For demo, we'll just scan the current directory
                scan_directory(".", None)
                
                # Sleep for the interval
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in scheduled scanning: {str(e)}")
                time.sleep(interval)
    
    # Start thread
    thread = threading.Thread(target=scanning_worker, daemon=True)
    thread.start()
    logger.info(f"Scheduled scanning started with interval of {interval} seconds")
    
    return thread