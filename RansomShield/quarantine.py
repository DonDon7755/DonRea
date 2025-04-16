"""
Quarantine system for Ransomware Detection & Mitigation Framework.
Handles isolation and management of suspicious files.
"""

import os
import shutil
import logging
import threading
import time
import json
from datetime import datetime, timedelta

# Get logger
logger = logging.getLogger(__name__)

# Global variables
db_instance = None
quarantine_dir = "quarantine"
backup_bin_dir = "backup_bin"  # Directory for backup bin (deleted files)
maintenance_active = False
maintenance_thread = None


def initialize(database_instance, quarantine_directory=None):
    """Initialize the quarantine system."""
    global db_instance, quarantine_dir, backup_bin_dir
    
    db_instance = database_instance
    
    if quarantine_directory:
        quarantine_dir = quarantine_directory
    
    # Create quarantine directory if it doesn't exist
    os.makedirs(quarantine_dir, exist_ok=True)
    
    # Create backup bin directory if it doesn't exist
    backup_path = os.path.join(os.path.dirname(quarantine_dir), backup_bin_dir)
    os.makedirs(backup_path, exist_ok=True)
    
    logger.info(f"Quarantine system initialized with directory: {quarantine_dir}")
    logger.info(f"Backup bin initialized with directory: {backup_path}")
    
    return True


def quarantine_file(file_path, user_id=None):
    """Move a file to quarantine."""
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            if db_instance:
                db_instance.add_log(f"Failed to quarantine file (not found): {file_path}", "ERROR", user_id)
            return False
        
        # Get file information
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Calculate file hash
        import hashlib
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        
        # Create quarantine filename using hash to ensure uniqueness
        quarantine_filename = f"{file_hash}_{file_name}"
        quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
        
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        
        # Copy file to quarantine (instead of moving to preserve evidence)
        shutil.copy2(file_path, quarantine_path)
        
        # Mark the original as hidden or rename it (optional)
        # In a real implementation, you might:
        # 1. Replace the original with a warning file
        # 2. Set file permissions to prevent execution
        # 3. Use platform-specific isolation techniques
        
        # For this demo, we'll just log that the file was quarantined
        logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
        
        # Add to database
        if db_instance:
            # Get risk level from detection result if available
            risk_level = 0.8  # Default high risk
            try:
                with db_instance.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT risk_level FROM detection_results WHERE file_path = ? ORDER BY timestamp DESC LIMIT 1",
                        (file_path,)
                    )
                    result = cursor.fetchone()
                    if result:
                        risk_level = result["risk_level"]
            except Exception as e:
                logger.error(f"Error getting risk level for {file_path}: {str(e)}")
            
            # Add quarantine item
            quarantine_id = db_instance.add_quarantine_item(
                file_path,
                quarantine_path,
                file_hash,
                file_size,
                risk_level,
                user_id
            )
            
            # Add log
            db_instance.add_log(f"File quarantined: {file_path}", "INFO", user_id)
            
            # Add alert
            db_instance.add_alert(
                f"File quarantined: {file_path}",
                "INFO",
                file_path=file_path,
                user_id=user_id
            )
        
        return True
        
    except Exception as e:
        logger.error(f"Error quarantining file {file_path}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error quarantining file {file_path}: {str(e)}", "ERROR", user_id)
        return False


def restore_file(quarantine_id, user_id=None):
    """Restore a file from quarantine."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return False
        
        # Get quarantine item details
        with db_instance.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (quarantine_id,))
            item = cursor.fetchone()
        
        if not item:
            logger.error(f"Quarantine item not found: {quarantine_id}")
            if db_instance:
                db_instance.add_log(f"Failed to restore file (quarantine item not found): {quarantine_id}", "ERROR", user_id)
            return False
        
        # Check if quarantine file exists
        quarantine_path = item["quarantine_path"]
        if not os.path.exists(quarantine_path):
            logger.error(f"Quarantined file not found: {quarantine_path}")
            if db_instance:
                db_instance.add_log(f"Failed to restore file (quarantined file not found): {quarantine_path}", "ERROR", user_id)
            return False
        
        # Get original path
        original_path = item["original_path"]
        
        # Check if original location is writable
        original_dir = os.path.dirname(original_path)
        if not os.path.exists(original_dir):
            try:
                os.makedirs(original_dir)
            except Exception as e:
                logger.error(f"Failed to create directory {original_dir}: {str(e)}")
                if db_instance:
                    db_instance.add_log(f"Failed to create directory for file restoration: {original_dir}", "ERROR", user_id)
                return False
        
        # Restore file to original location
        shutil.copy2(quarantine_path, original_path)
        
        # Remove from database
        db_instance.delete_quarantine_item(quarantine_id)
        
        # Add log
        db_instance.add_log(f"File restored from quarantine: {original_path}", "INFO", user_id)
        
        # Add alert
        db_instance.add_alert(
            f"File restored from quarantine: {original_path}",
            "INFO",
            file_path=original_path,
            user_id=user_id
        )
        
        logger.info(f"File restored: {quarantine_path} -> {original_path}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error restoring file {quarantine_id}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error restoring file {quarantine_id}: {str(e)}", "ERROR", user_id)
        return False


def delete_file(quarantine_id, user_id=None, permanent=False):
    """Delete a file from quarantine. By default, moves to backup bin unless permanent=True."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return False
        
        # Get quarantine item details
        with db_instance.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (quarantine_id,))
            item = cursor.fetchone()
        
        if not item:
            logger.error(f"Quarantine item not found: {quarantine_id}")
            if db_instance:
                db_instance.add_log(f"Failed to delete file (quarantine item not found): {quarantine_id}", "ERROR", user_id)
            return False
        
        # Check if quarantine file exists
        quarantine_path = item["quarantine_path"]
        if os.path.exists(quarantine_path):
            if permanent:
                # Permanently delete the file
                os.remove(quarantine_path)
                logger.info(f"File permanently deleted from quarantine: {quarantine_path}")
            else:
                # Move to backup bin instead of permanent deletion
                backup_path = os.path.join(os.path.dirname(quarantine_dir), backup_bin_dir)
                os.makedirs(backup_path, exist_ok=True)
                
                # Create backup filename with timestamp to prevent overwriting
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                file_name = os.path.basename(quarantine_path)
                backup_filename = f"{timestamp}_{file_name}"
                backup_file_path = os.path.join(backup_path, backup_filename)
                
                # Move file to backup bin
                shutil.move(quarantine_path, backup_file_path)
                
                # Store metadata about the backup
                metadata = {
                    "original_path": item["original_path"],
                    "quarantine_path": item["quarantine_path"],
                    "file_hash": item["file_hash"],
                    "file_size": item["file_size"],
                    "risk_level": item["risk_level"],
                    "timestamp": datetime.now().isoformat(),
                    "user_id": user_id
                }
                
                # Save metadata to a JSON file
                metadata_path = f"{backup_file_path}.json"
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                logger.info(f"File moved to backup bin: {quarantine_path} -> {backup_file_path}")
        else:
            logger.warning(f"Quarantined file not found: {quarantine_path}")
        
        # Remove from database
        db_instance.delete_quarantine_item(quarantine_id)
        
        # Add log
        if permanent:
            db_instance.add_log(f"File permanently deleted from quarantine: {item['original_path']}", "INFO", user_id)
        else:
            db_instance.add_log(f"File moved to backup bin: {item['original_path']}", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error deleting file {quarantine_id}: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error deleting file {quarantine_id}: {str(e)}", "ERROR", user_id)
        return False


def purge_quarantine(days=30, user_id=None):
    """Purge old files from quarantine."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return False
        
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d %H:%M:%S")
        
        # Get old quarantine items
        with db_instance.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE timestamp < ?", (cutoff_str,))
            items = cursor.fetchall()
        
        if not items:
            logger.info(f"No quarantine items older than {days} days")
            return True
        
        # Delete each item
        deleted_count = 0
        for item in items:
            try:
                # Delete file if it exists
                quarantine_path = item["quarantine_path"]
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                
                # Remove from database
                db_instance.delete_quarantine_item(item["id"])
                
                deleted_count += 1
                
            except Exception as e:
                logger.error(f"Error purging quarantine item {item['id']}: {str(e)}")
        
        # Add log
        if deleted_count > 0:
            db_instance.add_log(f"Purged {deleted_count} old items from quarantine", "INFO", user_id)
            logger.info(f"Purged {deleted_count} old items from quarantine")
        
        return True
        
    except Exception as e:
        logger.error(f"Error purging quarantine: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error purging quarantine: {str(e)}", "ERROR", user_id)
        return False


def start_quarantine_maintenance(user_id=None):
    """Start a thread that periodically purges old quarantined files."""
    global maintenance_active, maintenance_thread
    
    if maintenance_active:
        logger.info("Quarantine maintenance already active")
        return True
    
    def maintenance_worker():
        global maintenance_active
        
        try:
            # Default interval: 24 hours
            interval = 86400
            
            # Default purge threshold: 30 days
            days = 30
            
            # Get settings if available
            if db_instance:
                interval_setting = db_instance.get_setting('quarantine_maintenance_interval', str(interval))
                days_setting = db_instance.get_setting('quarantine_purge_days', str(days))
                
                try:
                    interval = int(interval_setting)
                except (ValueError, TypeError):
                    interval = 86400
                
                try:
                    days = int(days_setting)
                except (ValueError, TypeError):
                    days = 30
            
            logger.info(f"Quarantine maintenance started (interval: {interval}s, purge threshold: {days} days)")
            if db_instance:
                db_instance.add_log(f"Quarantine maintenance started", "INFO", user_id)
            
            while maintenance_active:
                # Purge old files
                purge_quarantine(days, user_id)
                
                # Sleep until next run
                time.sleep(interval)
                
        except Exception as e:
            logger.error(f"Error in quarantine maintenance: {str(e)}")
            if db_instance:
                db_instance.add_log(f"Error in quarantine maintenance: {str(e)}", "ERROR", user_id)
            maintenance_active = False
    
    # Start maintenance thread
    maintenance_active = True
    maintenance_thread = threading.Thread(target=maintenance_worker, daemon=True)
    maintenance_thread.start()
    
    return True


def stop_quarantine_maintenance(user_id=None):
    """Stop the quarantine maintenance thread."""
    global maintenance_active
    
    if not maintenance_active:
        logger.info("Quarantine maintenance already inactive")
        return True
    
    try:
        maintenance_active = False
        
        logger.info("Quarantine maintenance stopped")
        if db_instance:
            db_instance.add_log("Quarantine maintenance stopped", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error stopping quarantine maintenance: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error stopping quarantine maintenance: {str(e)}", "ERROR", user_id)
        return False


def get_quarantine_stats(user_id=None):
    """Get statistics about quarantined files."""
    try:
        if not db_instance:
            logger.error("Database not initialized")
            return None
        
        # Get all quarantine items
        quarantine_items = db_instance.get_quarantine_items()
        
        # Calculate stats
        total_items = len(quarantine_items)
        total_size = sum(item["file_size"] for item in quarantine_items)
        
        # Get oldest and newest items
        oldest_time = min([item["timestamp"] for item in quarantine_items]) if quarantine_items else None
        newest_time = max([item["timestamp"] for item in quarantine_items]) if quarantine_items else None
        
        # Risk level distribution
        high_risk = sum(1 for item in quarantine_items if item["risk_level"] >= 0.7)
        medium_risk = sum(1 for item in quarantine_items if 0.5 <= item["risk_level"] < 0.7)
        low_risk = sum(1 for item in quarantine_items if item["risk_level"] < 0.5)
        
        # Format timestamps
        if oldest_time:
            oldest_time = datetime.fromisoformat(oldest_time).strftime("%Y-%m-%d %H:%M:%S")
        
        if newest_time:
            newest_time = datetime.fromisoformat(newest_time).strftime("%Y-%m-%d %H:%M:%S")
        
        stats = {
            "total_items": total_items,
            "total_size": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "oldest_item": oldest_time,
            "newest_item": newest_time,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting quarantine stats: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error getting quarantine stats: {str(e)}", "ERROR", user_id)
        return None


def get_backup_bin_items(user_id=None):
    """List files in the backup bin."""
    try:
        # Ensure backup bin directory exists
        backup_path = os.path.join(os.path.dirname(quarantine_dir), backup_bin_dir)
        if not os.path.exists(backup_path):
            os.makedirs(backup_path, exist_ok=True)
            return []
        
        backup_items = []
        
        # List all files in backup bin
        for filename in os.listdir(backup_path):
            if filename.endswith(".json"):
                continue  # Skip metadata files
                
            # Look for corresponding metadata file
            metadata_path = os.path.join(backup_path, f"{filename}.json")
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        
                    # Create backup item record
                    file_path = os.path.join(backup_path, filename)
                    item = {
                        "filename": filename,
                        "path": file_path,
                        "metadata": metadata,
                        "size": os.path.getsize(file_path),
                        "timestamp": metadata.get("timestamp", "Unknown")
                    }
                    backup_items.append(item)
                except Exception as e:
                    logger.error(f"Error reading metadata for {filename}: {str(e)}")
            else:
                # No metadata file, create basic entry
                file_path = os.path.join(backup_path, filename)
                try:
                    item = {
                        "filename": filename,
                        "path": file_path,
                        "metadata": None,
                        "size": os.path.getsize(file_path),
                        "timestamp": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                    }
                    backup_items.append(item)
                except Exception as e:
                    logger.error(f"Error creating basic entry for {filename}: {str(e)}")
        
        # Sort by timestamp (newest first)
        backup_items.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return backup_items
        
    except Exception as e:
        logger.error(f"Error listing backup bin: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error listing backup bin: {str(e)}", "ERROR", user_id)
        return []


def restore_from_backup(backup_filename, user_id=None):
    """Restore a file from the backup bin to quarantine."""
    try:
        # Ensure backup bin directory exists
        backup_path = os.path.join(os.path.dirname(quarantine_dir), backup_bin_dir)
        if not os.path.exists(backup_path):
            logger.error("Backup bin directory does not exist")
            return False
        
        # Check if file exists in backup bin
        backup_file_path = os.path.join(backup_path, backup_filename)
        if not os.path.exists(backup_file_path):
            logger.error(f"File not found in backup bin: {backup_filename}")
            return False
        
        # Look for metadata file
        metadata_path = f"{backup_file_path}.json"
        metadata = None
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            except Exception as e:
                logger.error(f"Error reading metadata for {backup_filename}: {str(e)}")
        
        # If we have metadata, restore with original details
        if metadata and "quarantine_path" in metadata and "original_path" in metadata:
            # Restore to original quarantine path if possible
            quarantine_path = metadata["quarantine_path"]
            if os.path.exists(os.path.dirname(quarantine_path)):
                # Directory exists, restore directly
                shutil.copy2(backup_file_path, quarantine_path)
            else:
                # Create a new quarantine path
                os.makedirs(quarantine_dir, exist_ok=True)
                quarantine_path = os.path.join(quarantine_dir, os.path.basename(metadata["quarantine_path"]))
                shutil.copy2(backup_file_path, quarantine_path)
            
            # Add back to database
            if db_instance:
                db_instance.add_quarantine_item(
                    metadata["original_path"],
                    quarantine_path,
                    metadata["file_hash"] if "file_hash" in metadata else "unknown",
                    metadata["file_size"] if "file_size" in metadata else os.path.getsize(backup_file_path),
                    metadata["risk_level"] if "risk_level" in metadata else 0.5,
                    user_id
                )
            
            logger.info(f"File restored from backup bin to quarantine: {backup_file_path} -> {quarantine_path}")
            
            # Add log
            if db_instance:
                db_instance.add_log(f"File restored from backup bin to quarantine: {metadata['original_path']}", "INFO", user_id)
            
            # Optionally remove from backup bin
            try:
                os.remove(backup_file_path)
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
            except Exception as e:
                logger.warning(f"Failed to remove backup file after restore: {str(e)}")
            
            return True
        else:
            # No metadata, create new quarantine entry
            # Generate a filename
            file_name = os.path.basename(backup_file_path)
            quarantine_path = os.path.join(quarantine_dir, file_name)
            
            # Copy to quarantine
            os.makedirs(quarantine_dir, exist_ok=True)
            shutil.copy2(backup_file_path, quarantine_path)
            
            # Calculate file hash
            import hashlib
            hasher = hashlib.sha256()
            with open(quarantine_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            
            # Add to database
            if db_instance:
                db_instance.add_quarantine_item(
                    f"Restored from backup: {file_name}",
                    quarantine_path,
                    file_hash,
                    os.path.getsize(backup_file_path),
                    0.5,  # Default risk level (medium)
                    user_id
                )
            
            logger.info(f"File restored from backup bin to quarantine (no metadata): {backup_file_path} -> {quarantine_path}")
            
            # Add log
            if db_instance:
                db_instance.add_log(f"File restored from backup bin to quarantine: {file_name}", "INFO", user_id)
            
            # Optionally remove from backup bin
            try:
                os.remove(backup_file_path)
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
            except Exception as e:
                logger.warning(f"Failed to remove backup file after restore: {str(e)}")
            
            return True
        
    except Exception as e:
        logger.error(f"Error restoring from backup bin: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error restoring from backup bin: {str(e)}", "ERROR", user_id)
        return False


def permanently_delete_from_backup(backup_filename, user_id=None):
    """Permanently delete a file from the backup bin."""
    try:
        # Ensure backup bin directory exists
        backup_path = os.path.join(os.path.dirname(quarantine_dir), backup_bin_dir)
        if not os.path.exists(backup_path):
            logger.error("Backup bin directory does not exist")
            return False
        
        # Check if file exists in backup bin
        backup_file_path = os.path.join(backup_path, backup_filename)
        if not os.path.exists(backup_file_path):
            logger.error(f"File not found in backup bin: {backup_filename}")
            return False
        
        # Get metadata if available
        metadata_path = f"{backup_file_path}.json"
        original_path = backup_filename
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    if "original_path" in metadata:
                        original_path = metadata["original_path"]
            except Exception as e:
                logger.error(f"Error reading metadata for {backup_filename}: {str(e)}")
        
        # Delete the file
        os.remove(backup_file_path)
        
        # Delete metadata if it exists
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
        
        logger.info(f"File permanently deleted from backup bin: {backup_file_path}")
        
        # Add log
        if db_instance:
            db_instance.add_log(f"File permanently deleted from backup bin: {original_path}", "INFO", user_id)
        
        return True
        
    except Exception as e:
        logger.error(f"Error permanently deleting from backup bin: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Error permanently deleting from backup bin: {str(e)}", "ERROR", user_id)
        return False