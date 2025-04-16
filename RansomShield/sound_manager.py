"""
Sound management module for the Ransomware Detection Framework.
Handles playing alert sounds for different severity levels.
"""

import os
import sys
import logging

# Set up logging
logger = logging.getLogger(__name__)

# Try to import QSoundEffect, provide fallback if not available
qt_multimedia_available = False
try:
    from PyQt6.QtMultimedia import QSoundEffect
    from PyQt6.QtCore import QUrl
    qt_multimedia_available = True
except ImportError:
    logger.warning("PyQt6.QtMultimedia not available. Sound alerts will be disabled.")
    # Create dummy classes for compatibility
    class QSoundEffect:
        def setSource(self, _): pass
        def setVolume(self, _): pass
        def play(self): pass
    
    # Create a dummy QUrl class too
    class QUrl:
        @staticmethod
        def fromLocalFile(path):
            return path

# Sound file paths
SOUNDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "sounds")
SOUND_FILES = {
    "CRITICAL": os.path.join(SOUNDS_DIR, "alert_critical.wav"),
    "HIGH": os.path.join(SOUNDS_DIR, "alert_critical.wav"),
    "WARNING": os.path.join(SOUNDS_DIR, "alert_warning.wav"),
    "MEDIUM": os.path.join(SOUNDS_DIR, "alert_warning.wav"),
    "INFO": os.path.join(SOUNDS_DIR, "alert_info.wav"),
    "LOW": os.path.join(SOUNDS_DIR, "alert_info.wav"),
}

# Flag to determine if sound is enabled
sound_enabled = True

# Hold references to sound objects to prevent garbage collection
sound_effects = {}


def initialize():
    """Initialize the sound manager."""
    global sound_enabled
    
    # Check if Qt Multimedia is available
    if not qt_multimedia_available:
        logger.warning("Qt Multimedia not available. Sound alerts will be disabled.")
        sound_enabled = False
        return
    
    # Check if sounds directory exists
    if not os.path.exists(SOUNDS_DIR):
        try:
            os.makedirs(SOUNDS_DIR)
            logger.info(f"Created sounds directory: {SOUNDS_DIR}")
        except Exception as e:
            logger.error(f"Failed to create sounds directory: {str(e)}")
            sound_enabled = False
            return
    
    # Check if sound files exist
    missing_files = []
    for severity, file_path in SOUND_FILES.items():
        if not os.path.exists(file_path):
            missing_files.append((severity, file_path))
    
    if missing_files:
        logger.warning(f"Missing sound files: {missing_files}")
        
        # Create placeholder sound files if missing
        try:
            _create_placeholder_sound_files(missing_files)
        except Exception as e:
            logger.error(f"Failed to create placeholder sound files: {str(e)}")
            sound_enabled = False


def _create_placeholder_sound_files(missing_files):
    """Create basic placeholder sound files."""
    # This would typically generate very simple WAV files
    # In a real application, you'd include actual sound files
    logger.info("Sound files would be created here in a production environment")
    # We'll leave this empty for now as we'd need additional libraries to generate
    # real sound files (like scipy or wavio)


def play_alert_sound(severity):
    """Play an alert sound for the given severity.
    
    Args:
        severity (str): The severity level (CRITICAL, HIGH, WARNING, MEDIUM, INFO, LOW)
    """
    if not sound_enabled or not qt_multimedia_available:
        logger.debug(f"Sound alerts disabled or Qt Multimedia not available. Skipping alert sound for {severity}.")
        return
    
    # Normalize severity to handle case differences
    severity = severity.upper()
    
    # If severity not found, use INFO as default
    if severity not in SOUND_FILES:
        severity = "INFO"
    
    sound_file = SOUND_FILES[severity]
    
    try:
        # Create a QSoundEffect and play it
        effect = QSoundEffect()
        
        # Use QUrl safely (it should be available if qt_multimedia_available is True)
        if os.path.exists(sound_file):
            effect.setSource(QUrl.fromLocalFile(sound_file))
            effect.setVolume(0.75)  # 75% volume
            
            # Store reference to prevent garbage collection
            sound_effects[severity] = effect
            
            # Play the sound
            effect.play()
            logger.debug(f"Playing alert sound for {severity} severity")
        else:
            logger.warning(f"Sound file not found: {sound_file}")
    except Exception as e:
        logger.error(f"Failed to play alert sound: {str(e)}")


def set_sound_enabled(enabled):
    """Enable or disable sounds.
    
    Args:
        enabled (bool): Whether sound should be enabled
    """
    global sound_enabled
    sound_enabled = enabled
    logger.info(f"Sound alerts {'enabled' if enabled else 'disabled'}")