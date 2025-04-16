"""
Ransomware Detection & Mitigation Framework - PyQt6 Version
A modern, professional interface styled like commercial antivirus products
"""

import os
import sys
import json
import logging
import threading
import hashlib
from datetime import datetime
import time
import math

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QFrame, QStackedWidget, QLineEdit, 
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QDialog, QMessageBox, QTabWidget, QCheckBox, QSlider,
    QSplashScreen, QProgressBar, QGridLayout, QScrollArea,
    QGroupBox, QSpacerItem, QSizePolicy, QComboBox, QTextEdit,
    QFormLayout
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QTimer, QUrl, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor, QPalette, QCursor, QDesktopServices, QMovie, QFontDatabase

# Define a constant for maximum widget size to remove width restrictions
QWIDGETSIZE_MAX = 16777215

# Import our modules
import detection_engine
import file_monitor
import process_monitor
import alert_system
import quarantine
import sound_manager
import network_monitor
from config import ALERT_LEVELS, MONITOR_EXTENSIONS, DEFAULT_CNN_THRESHOLD, DEFAULT_LSTM_THRESHOLD

# Setup logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
DATABASE_PATH = "ransomware_detection.db"
quarantine_dir = "quarantine"
current_user = None  # Store logged in user

# Dark theme and colors
COLOR_BACKGROUND = "#1E1E2E"
COLOR_CARD_BG = "#282838"
COLOR_HIGHLIGHT = "#6D28D9"  # Purple
COLOR_PRIMARY = "#9D44F9"  # Lighter purple
COLOR_SUCCESS = "#10B981"  # Green
COLOR_WARNING = "#F59E0B"  # Yellow/Orange
COLOR_DANGER = "#EF4444"  # Red
COLOR_INFO = "#3B82F6"  # Blue
COLOR_TEXT = "#E2E8F0"  # Light Grey
COLOR_SECONDARY_TEXT = "#94A3B8"  # Medium Grey

# UI scale factor - adjust this to make everything smaller
UI_SCALE = 0.9  # Scale down to 90% of original size
FONT_SIZE_TITLE = int(18 * UI_SCALE)    # Titles
FONT_SIZE_HEADER = int(16 * UI_SCALE)   # Headers
FONT_SIZE_NORMAL = int(14 * UI_SCALE)   # Normal text
FONT_SIZE_SMALL = int(12 * UI_SCALE)    # Small text


# Import database class to keep consistency
from main_tkinter import DatabaseManager


class LoadingScreen(QSplashScreen):
    """Custom splash screen with loading animation."""
    
    def __init__(self):
        # Create a pixmap for the splash screen
        pixmap = QPixmap(400, 200)
        pixmap.fill(QColor(COLOR_BACKGROUND))
        super().__init__(pixmap)
        
        # Add layout to splash screen
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Add title
        title_label = QLabel("Ransomware Detection & Mitigation")
        title_label.setStyleSheet(f"color: {COLOR_PRIMARY}; font-size: 18px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Add subtitle
        subtitle_label = QLabel("Loading system components...")
        subtitle_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14px;")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle_label)
        
        # Add progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                background-color: {COLOR_CARD_BG};
                height: 8px;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_PRIMARY};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(self.progress_bar)
        
        # Add status label
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet(f"color: {COLOR_SECONDARY_TEXT}; font-size: 12px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Set layout to widget and render on splash screen
        self.setLayout(layout)
        
        # Setup animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.progress = 0
        
    def start_animation(self):
        """Start the loading animation."""
        self.timer.start(30)
        
    def update_progress(self):
        """Update the progress bar."""
        steps = ["Initializing database...", 
                 "Loading detection engine...",
                 "Setting up file monitoring...",
                 "Setting up process monitoring...",
                 "Setting up network monitoring...",
                 "Setting up alert system...",
                 "Initializing quarantine...",
                 "Loading user interface..."]
                 
        self.progress += 1
        
        if self.progress <= 100:
            self.progress_bar.setValue(self.progress)
            
            # Update status text
            step_index = min(int(self.progress / (100/len(steps))), len(steps)-1)
            self.status_label.setText(steps[step_index])
        else:
            self.timer.stop()
            
    def set_message(self, message):
        """Set the status message."""
        self.status_label.setText(message)


class LoginDialog(QDialog):
    """Custom login dialog."""
    
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.user = None
        
        self.setWindowTitle("Login")
        self.setFixedSize(480, 520)  # Increased width and height for better fit
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
                border-radius: 10px;
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Logo/header
        logo_frame = QFrame()
        logo_layout = QVBoxLayout()
        logo_layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("Ransomware Detection")
        title.setStyleSheet(f"color: {COLOR_PRIMARY}; font-size: 22px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_layout.addWidget(title)
        
        subtitle = QLabel("& Mitigation Framework")
        subtitle.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; margin-centre: -10px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_layout.addWidget(subtitle)
        
        version = QLabel("v1.0")
        version.setStyleSheet(f"color: {COLOR_SECONDARY_TEXT}; font-size: 12px;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_layout.addWidget(version)
        
        logo_frame.setLayout(logo_layout)
        layout.addWidget(logo_frame)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet(f"background-color: {COLOR_CARD_BG}; max-height: 1px;")
        layout.addWidget(separator)
        layout.addSpacing(20)
        
        # Form fields
        layout.addWidget(QLabel("Username"))
        self.username_input = QLineEdit()
        self.username_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 12px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        layout.addWidget(self.username_input)
        
        layout.addWidget(QLabel("Password"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 12px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        layout.addWidget(self.password_input)
        
        # Error message label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet(f"color: {COLOR_DANGER}; font-size: 12px;")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.error_label)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
            QPushButton:pressed {{
                background-color: {COLOR_PRIMARY};
            }}
        """)
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 12px;
                font-weight: bold;
                border: 1px solid {COLOR_CARD_BG};
            }}
            QPushButton:hover {{
                background-color: {COLOR_CARD_BG};
            }}
        """)
        self.register_button.clicked.connect(self.show_register_dialog)
        layout.addWidget(self.register_button)
        
        self.setLayout(layout)
        
    def login(self):
        """Authenticate user and close dialog if successful."""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            self.error_label.setText("Please enter username and password")
            return
        
        user = self.db.authenticate_user(username, password)
        
        if user:
            self.user = user
            self.accept()
        else:
            self.error_label.setText("Invalid username or password")
    
    def show_register_dialog(self):
        """Show the registration dialog."""
        dialog = RegisterDialog(self.db)
        if dialog.exec():
            # Registration successful
            self.username_input.setText(dialog.username_input.text())
            self.password_input.setText(dialog.password_input.text())
            self.error_label.setText("")


class RegisterDialog(QDialog):
    """Custom registration dialog."""
    
    def __init__(self, db):
        super().__init__()
        self.db = db
        
        self.setWindowTitle("Create Account")
        self.setFixedSize(480, 570)  # Increased width and height for better fit
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
                border-radius: 10px;
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Create Account")
        title.setStyleSheet(f"color: {COLOR_PRIMARY}; font-size: 22px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        layout.addSpacing(20)
        
        # Form fields
        layout.addWidget(QLabel("Username"))
        self.username_input = QLineEdit()
        self.username_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 12px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        layout.addWidget(self.username_input)
        
        layout.addWidget(QLabel("Email"))
        self.email_input = QLineEdit()
        self.email_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 12px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        layout.addWidget(self.email_input)
        
        layout.addWidget(QLabel("Password"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 12px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        layout.addWidget(self.password_input)
        
        layout.addWidget(QLabel("Confirm Password"))
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 12px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        layout.addWidget(self.confirm_password_input)
        
        # Error message label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet(f"color: {COLOR_DANGER}; font-size: 12px;")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.error_label)
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
            QPushButton:pressed {{
                background-color: {COLOR_PRIMARY};
            }}
        """)
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 12px;
                font-weight: bold;
                border: 1px solid {COLOR_CARD_BG};
            }}
            QPushButton:hover {{
                background-color: {COLOR_CARD_BG};
            }}
        """)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)
        
        self.setLayout(layout)
        
    def register(self):
        """Register a new user."""
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        # Validate input
        if not username or not email or not password or not confirm_password:
            self.error_label.setText("Please fill in all fields")
            return
        
        if password != confirm_password:
            self.error_label.setText("Passwords do not match")
            return
        
        # Validate email format (simple check)
        if "@" not in email or "." not in email:
            self.error_label.setText("Invalid email format")
            return
        
        # Register user
        success, message = self.db.register_user(username, email, password)
        
        if success:
            QMessageBox.information(self, "Registration Successful", "Your account has been created. You can now log in.")
            self.accept()
        else:
            self.error_label.setText(message)


class CardFrame(QFrame):
    """Custom card frame with drop shadow and rounded corners."""
    
    def __init__(self, title=None, parent=None):
        super().__init__(parent)
        
        self.setObjectName("card")
        self.setStyleSheet(f"""
            #card {{
                background-color: {COLOR_CARD_BG};
                border-radius: 10px;
                padding: 15px;
            }}
        """)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Add title if provided
        if title:
            title_label = QLabel(title)
            title_label.setStyleSheet(f"""
                font-size: 14px;
                font-weight: bold;
                color: {COLOR_TEXT};
                margin-bottom: 10px;
            """)
            layout.addWidget(title_label)
        
        # Content frame
        self.content_frame = QFrame()
        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_frame.setLayout(self.content_layout)
        
        layout.addWidget(self.content_frame)
        self.setLayout(layout)
    
    def add_widget(self, widget):
        """Add a widget to the card content."""
        self.content_layout.addWidget(widget)


class StatCard(CardFrame):
    """Card displaying a statistic with title and value."""
    
    def __init__(self, title, value, icon=None, color=COLOR_PRIMARY, parent=None):
        super().__init__(parent=parent)
        
        # Layout
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Left side with icon (if provided)
        if icon:
            icon_label = QLabel()
            pixmap = QPixmap(icon)
            icon_label.setPixmap(pixmap)
            layout.addWidget(icon_label)
            
        # Right side with title and value
        text_layout = QVBoxLayout()
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 14px;
            color: {COLOR_SECONDARY_TEXT};
        """)
        text_layout.addWidget(title_label)
        
        # Value
        value_label = QLabel(str(value))
        value_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {color};
        """)
        text_layout.addWidget(value_label)
        
        layout.addLayout(text_layout)
        self.content_layout.addLayout(layout)


class SidebarButton(QPushButton):
    """Custom sidebar button with icon and text."""
    
    def __init__(self, text, icon=None, is_active=False, parent=None):
        super().__init__(text, parent)
        
        self.is_active = is_active
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))  # Change cursor to hand when hovering
        self.setText("  " + text)  # Add spacing for icon
        
        if icon:
            self.setIcon(QIcon(icon))
            self.setIconSize(QSize(20, 20))
        
        # Make sure button is clickable
        self.setAutoDefault(False)
        self.setDefault(False)
        self.setFlat(False)
        
        # Set focus policy to ensure button can receive clicks
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        
        self.update_style()
    
    def update_style(self):
        """Update button style based on active state."""
        if self.is_active:
            self.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding: 12px 15px;
                    background-color: {COLOR_PRIMARY};
                    border-radius: 8px;
                    color: white;
                    font-weight: bold;
                    margin: 3px 0px;
                }}
                QPushButton:hover {{
                    background-color: {COLOR_HIGHLIGHT};
                }}
                QPushButton:pressed {{
                    background-color: {COLOR_HIGHLIGHT};
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding: 12px 15px;
                    background-color: transparent;
                    border-radius: 8px;
                    color: {COLOR_TEXT};
                    font-weight: bold;
                    margin: 3px 0px;
                }}
                QPushButton:hover {{
                    background-color: {COLOR_CARD_BG};
                }}
                QPushButton:pressed {{
                    background-color: {COLOR_CARD_BG};
                    color: white;
                }}
            """)
    
    def set_active(self, active):
        """Set the active state of the button."""
        self.is_active = active
        self.update_style()
        
    def mousePressEvent(self, event):
        """Override to ensure click events are captured."""
        super().mousePressEvent(event)
        # Add debug print
        print(f"Button '{self.text()}' clicked!")


class ModernTable(QTableWidget):
    """Modern styled table widget."""
    
    def __init__(self, headers, parent=None):
        super().__init__(parent)
        
        # Set up table properties
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        
        # Apply style
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLOR_CARD_BG};
                gridline-color: {COLOR_BACKGROUND};
                border-radius: 10px;
                border: none;
            }}
            QTableWidget::item {{
                padding: 5px;
                border-bottom: 1px solid {COLOR_BACKGROUND};
            }}
            QHeaderView::section {{
                background-color: {COLOR_CARD_BG};
                padding: 5px;
                border: none;
                font-weight: bold;
                color: {COLOR_TEXT};
            }}
            QTableWidget::item:selected {{
                background-color: {COLOR_HIGHLIGHT};
                color: white;
            }}
        """)


class DashboardPage(QWidget):
    """Dashboard page displaying overview and alerts."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 20)
        layout.setSpacing(20)
        
        # Header section with quick actions
        header = QFrame()
        header_layout = QHBoxLayout()
        
        header_title = QLabel("Protection Dashboard")
        header_title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header_layout.addWidget(header_title)
        
        # Add spacer
        header_layout.addStretch()
        
        # Scan button
        scan_button = QPushButton("Quick Scan")
        scan_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
        """)
        scan_button.setMinimumWidth(120)
        scan_button.clicked.connect(self.quick_scan)
        header_layout.addWidget(scan_button)
        
        # Full scan button
        full_scan_button = QPushButton("Full Scan")
        full_scan_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        full_scan_button.setMinimumWidth(120)
        full_scan_button.clicked.connect(self.full_scan)
        header_layout.addWidget(full_scan_button)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Status card
        status_card = CardFrame()
        status_layout = QHBoxLayout()
        
        # Protection status icon
        status_icon = QLabel()
        status_icon.setPixmap(QPixmap("shield-check.png").scaled(50, 50, Qt.AspectRatioMode.KeepAspectRatio))
        status_layout.addWidget(status_icon)
        
        # Status text
        status_text = QVBoxLayout()
        status_title = QLabel("Protection Status")
        status_title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_TEXT};")
        status_text.addWidget(status_title)
        
        status_message = QLabel("Your system is protected")
        status_message.setStyleSheet(f"font-size: 14px; color: {COLOR_SUCCESS};")
        status_text.addWidget(status_message)
        
        status_layout.addLayout(status_text)
        status_layout.addStretch()
        
        # Monitoring toggle
        monitoring_layout = QVBoxLayout()
        monitoring_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        monitoring_label = QLabel("Real-time Protection")
        monitoring_label.setStyleSheet(f"font-size: 14px; color: {COLOR_TEXT}; font-weight: bold;")
        monitoring_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        monitoring_layout.addWidget(monitoring_label)
        
        # Get current monitoring status
        monitoring_enabled = self.db.get_setting('monitoring_enabled', 'True').lower() == 'true'
        
        self.monitoring_toggle = QCheckBox("Enabled")
        self.monitoring_toggle.setChecked(monitoring_enabled)
        self.monitoring_toggle.stateChanged.connect(self.toggle_monitoring)
        self.monitoring_toggle.setStyleSheet(f"""
            QCheckBox {{
                font-size: 14px;
                color: {COLOR_SUCCESS if monitoring_enabled else COLOR_DANGER};
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:unchecked {{
                background-color: {COLOR_DANGER};
            }}
            QCheckBox::indicator:checked {{
                background-color: {COLOR_SUCCESS};
            }}
        """)
        monitoring_layout.addWidget(self.monitoring_toggle)
        
        status_layout.addLayout(monitoring_layout)
        status_card.content_layout.addLayout(status_layout)
        layout.addWidget(status_card)
        
        # Statistics grid
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(15)
        
        # Calculate stats
        detection_results = self.db.get_detection_results()
        alerts = self.db.get_alerts()
        quarantine_items = self.db.get_quarantine_items()
        
        total_scanned = len(detection_results)
        threats_detected = sum(1 for result in detection_results if result["risk_level"] >= ALERT_LEVELS["MEDIUM"])
        quarantined_files = len(quarantine_items)
        pending_alerts = sum(1 for alert in alerts if not alert["acknowledged"])
        
        # Create stat cards
        stats_layout.addWidget(StatCard("Files Scanned", total_scanned, color=COLOR_INFO))
        stats_layout.addWidget(StatCard("Threats Detected", threats_detected, color=COLOR_DANGER))
        stats_layout.addWidget(StatCard("Quarantined", quarantined_files, color=COLOR_WARNING))
        stats_layout.addWidget(StatCard("Pending Alerts", pending_alerts, color=COLOR_PRIMARY))
        
        layout.addLayout(stats_layout)
        
        # Recent alerts section
        alerts_section = QVBoxLayout()
        
        alerts_header = QHBoxLayout()
        alerts_title = QLabel("Recent Alerts")
        alerts_title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_TEXT};")
        alerts_header.addWidget(alerts_title)
        
        # View all button
        view_all_button = QPushButton("View All")
        view_all_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLOR_PRIMARY};
                border: none;
                font-weight: bold;
            }}
            QPushButton:hover {{
                color: {COLOR_HIGHLIGHT};
                text-decoration: underline;
            }}
        """)
        alerts_header.addWidget(view_all_button)
        
        alerts_section.addLayout(alerts_header)
        
        # Alerts table
        self.alerts_table = ModernTable(["Time", "Severity", "Message", "Status", "Actions"])
        self.alerts_table.cellClicked.connect(self.handle_alert_click)
        self.update_alerts_table()
        alerts_section.addWidget(self.alerts_table)
        
        # Acknowledge button
        ack_button = QPushButton("Acknowledge Selected")
        ack_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        ack_button.clicked.connect(self.acknowledge_alert)
        
        alerts_buttons = QHBoxLayout()
        alerts_buttons.addStretch()
        alerts_buttons.addWidget(ack_button)
        alerts_section.addLayout(alerts_buttons)
        
        layout.addLayout(alerts_section)
        
        self.setLayout(layout)
    
    def update_alerts_table(self):
        """Update the alerts table with latest alerts."""
        self.alerts_table.setRowCount(0)
        
        # Get count before update to detect new alerts
        current_alerts_count = self.alerts_table.rowCount()
        
        # Get alerts from database
        alerts = self.db.get_alerts(limit=10)
        
        # If there are more alerts than before, play the appropriate sound for the highest severity
        if len(alerts) > current_alerts_count and len(alerts) > 0:
            # Find the highest severity unacknowledged alert
            highest_severity = "INFO"
            for alert in alerts:
                if not alert["acknowledged"]:
                    if alert["severity"] == "CRITICAL":
                        highest_severity = "CRITICAL"
                        break
                    elif alert["severity"] == "WARNING" and highest_severity != "CRITICAL":
                        highest_severity = "WARNING"
            
            # Play sound for the highest severity
            sound_manager.play_alert_sound(highest_severity)
        
        for row, alert in enumerate(alerts):
            self.alerts_table.insertRow(row)
            
            # Time
            time_item = QTableWidgetItem(datetime.fromisoformat(alert["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"))
            self.alerts_table.setItem(row, 0, time_item)
            
            # Severity
            severity_item = QTableWidgetItem(alert["severity"])
            if alert["severity"] == "CRITICAL":
                severity_item.setForeground(QColor(COLOR_DANGER))
            elif alert["severity"] == "WARNING":
                severity_item.setForeground(QColor(COLOR_WARNING))
            else:
                severity_item.setForeground(QColor(COLOR_INFO))
            self.alerts_table.setItem(row, 1, severity_item)
            
            # Message
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert["message"]))
            
            # Status
            status_item = QTableWidgetItem("Acknowledged" if alert["acknowledged"] else "Pending")
            if alert["acknowledged"]:
                status_item.setForeground(QColor(COLOR_SECONDARY_TEXT))
            else:
                status_item.setForeground(QColor(COLOR_PRIMARY))
            self.alerts_table.setItem(row, 3, status_item)
            
            # Actions - placeholder
            self.alerts_table.setItem(row, 4, QTableWidgetItem("Details"))
            
            # Set row ID for reference
            self.alerts_table.setItem(row, 5, QTableWidgetItem(str(alert["id"])))
            self.alerts_table.hideColumn(5)
    
    def toggle_monitoring(self, state):
        """Toggle file and process monitoring."""
        enable = state == Qt.CheckState.Checked.value
        
        try:
            # Update database setting
            self.db.update_setting('monitoring_enabled', str(enable))
            
            # Update UI
            self.monitoring_toggle.setStyleSheet(f"""
                QCheckBox {{
                    font-size: 14px;
                    color: {COLOR_SUCCESS if enable else COLOR_DANGER};
                }}
                QCheckBox::indicator {{
                    width: 20px;
                    height: 20px;
                    border-radius: 10px;
                    border: 2px solid {COLOR_CARD_BG};
                }}
                QCheckBox::indicator:unchecked {{
                    background-color: {COLOR_DANGER};
                }}
                QCheckBox::indicator:checked {{
                    background-color: {COLOR_SUCCESS};
                }}
            """)
            
            # Update system
            if enable:
                file_monitor.start_monitoring(current_user["id"] if current_user else None)
                process_monitor.start_monitoring(current_user["id"] if current_user else None)
                network_monitor.start_monitoring(current_user["id"] if current_user else None)
                self.db.add_log("All monitoring enabled", "INFO", current_user["id"] if current_user else None)
            else:
                file_monitor.stop_monitoring(current_user["id"] if current_user else None)
                process_monitor.stop_monitoring(current_user["id"] if current_user else None)
                network_monitor.stop_monitoring(current_user["id"] if current_user else None)
                self.db.add_log("All monitoring disabled", "INFO", current_user["id"] if current_user else None)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to toggle monitoring: {str(e)}")
    
    def quick_scan(self):
        """Perform a quick scan of common directories."""
        try:
            # Ask for confirmation
            confirm = QMessageBox.question(
                self,
                "Quick Scan",
                "Do you want to perform a quick scan of common directories?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if confirm == QMessageBox.StandardButton.Yes:
                # Get common directories
                directories = [
                    os.path.expanduser("~/Documents"),
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop")
                ]
                
                # Start scan thread
                self.scan_thread = ScanThread(directories, self.db)
                self.scan_thread.scan_complete.connect(self.scan_finished)
                self.scan_thread.start()
                
                # Show progress dialog
                self.progress_dialog = QDialog(self)
                self.progress_dialog.setWindowTitle("Scanning...")
                self.progress_dialog.setFixedSize(400, 150)
                self.progress_dialog.setStyleSheet(f"background-color: {COLOR_BACKGROUND};")
                
                dialog_layout = QVBoxLayout()
                
                # Status label
                self.scan_status_label = QLabel("Scanning for threats...")
                self.scan_status_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14px;")
                self.scan_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                dialog_layout.addWidget(self.scan_status_label)
                
                # Progress bar
                self.scan_progress = QProgressBar()
                self.scan_progress.setRange(0, 0)  # Indeterminate
                self.scan_progress.setTextVisible(False)
                self.scan_progress.setStyleSheet(f"""
                    QProgressBar {{
                        border: none;
                        background-color: {COLOR_CARD_BG};
                        height: 8px;
                        border-radius: 4px;
                    }}
                    QProgressBar::chunk {{
                        background-color: {COLOR_PRIMARY};
                        border-radius: 4px;
                    }}
                """)
                dialog_layout.addWidget(self.scan_progress)
                
                # Cancel button
                cancel_button = QPushButton("Cancel")
                cancel_button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLOR_CARD_BG};
                        color: {COLOR_TEXT};
                        border-radius: 6px;
                        padding: 10px 20px;
                    }}
                    QPushButton:hover {{
                        background-color: #373747;
                    }}
                """)
                cancel_button.clicked.connect(self.cancel_scan)
                
                button_layout = QHBoxLayout()
                button_layout.addStretch()
                button_layout.addWidget(cancel_button)
                dialog_layout.addLayout(button_layout)
                
                self.progress_dialog.setLayout(dialog_layout)
                self.progress_dialog.exec()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
    
    def full_scan(self):
        """Perform a full system scan."""
        try:
            # Ask for directory
            directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
            
            if directory:
                # Start scan thread
                self.scan_thread = ScanThread([directory], self.db)
                self.scan_thread.scan_complete.connect(self.scan_finished)
                self.scan_thread.start()
                
                # Show progress dialog
                self.progress_dialog = QDialog(self)
                self.progress_dialog.setWindowTitle("Scanning...")
                self.progress_dialog.setFixedSize(400, 150)
                self.progress_dialog.setStyleSheet(f"background-color: {COLOR_BACKGROUND};")
                
                dialog_layout = QVBoxLayout()
                
                # Status label
                self.scan_status_label = QLabel(f"Scanning {directory}...")
                self.scan_status_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14px;")
                self.scan_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                dialog_layout.addWidget(self.scan_status_label)
                
                # Progress bar
                self.scan_progress = QProgressBar()
                self.scan_progress.setRange(0, 0)  # Indeterminate
                self.scan_progress.setTextVisible(False)
                self.scan_progress.setStyleSheet(f"""
                    QProgressBar {{
                        border: none;
                        background-color: {COLOR_CARD_BG};
                        height: 8px;
                        border-radius: 4px;
                    }}
                    QProgressBar::chunk {{
                        background-color: {COLOR_PRIMARY};
                        border-radius: 4px;
                    }}
                """)
                dialog_layout.addWidget(self.scan_progress)
                
                # Cancel button
                cancel_button = QPushButton("Cancel")
                cancel_button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLOR_CARD_BG};
                        color: {COLOR_TEXT};
                        border-radius: 6px;
                        padding: 10px 20px;
                    }}
                    QPushButton:hover {{
                        background-color: #373747;
                    }}
                """)
                cancel_button.clicked.connect(self.cancel_scan)
                
                button_layout = QHBoxLayout()
                button_layout.addStretch()
                button_layout.addWidget(cancel_button)
                dialog_layout.addLayout(button_layout)
                
                self.progress_dialog.setLayout(dialog_layout)
                self.progress_dialog.exec()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
    
    def cancel_scan(self):
        """Cancel the current scan."""
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scan_thread.terminate()
        
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
    
    def scan_finished(self, results):
        """Handle scan completion."""
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        
        # Update UI
        self.update_alerts_table()
        
        # Show results
        total_scanned = sum(result["files_scanned"] for result in results)
        total_threats = sum(result["threats_found"] for result in results)
        
        message = f"Scan completed.\n\nFiles scanned: {total_scanned}\nThreats found: {total_threats}"
        
        if total_threats > 0:
            message += "\n\nSee the Reports tab for details."
        
        QMessageBox.information(self, "Scan Results", message)
    
    def handle_alert_click(self, row, col):
        """Handle clicking on an alert item."""
        # Get alert ID from hidden column
        alert_id = int(self.alerts_table.item(row, 5).text())
        
        # If clicking on the Actions column
        if col == 4:
            # Get the alert data
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
                alert = cursor.fetchone()
                
                # If alert has a detection_result_id, show the details
                if alert and alert["detection_result_id"]:
                    # Get the detection result
                    cursor.execute("SELECT * FROM detection_results WHERE id = ?", (alert["detection_result_id"],))
                    result = cursor.fetchone()
                    
                    if result:
                        # Show threat details dialog
                        details_dialog = ThreatDetailsDialog(result, self)
                        details_dialog.exec()
                        
                        # Refresh tables if needed
                        self.update_alerts_table()
    
    def acknowledge_alert(self):
        """Acknowledge the selected alert."""
        selected_items = self.alerts_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select an alert to acknowledge.")
            return
        
        # Get alert ID from hidden column
        row = selected_items[0].row()
        alert_id = int(self.alerts_table.item(row, 5).text())
        
        # Acknowledge in database
        success = self.db.acknowledge_alert(alert_id, current_user["id"] if current_user else None)
        
        if success:
            # Update UI
            self.update_alerts_table()
            QMessageBox.information(self, "Success", "Alert acknowledged successfully.")
        else:
            QMessageBox.critical(self, "Error", "Failed to acknowledge alert.")


class ScanThread(QThread):
    """Thread for running scans in the background."""
    
    scan_complete = pyqtSignal(list)
    
    def __init__(self, directories, db):
        super().__init__()
        self.directories = directories
        self.db = db
    
    def run(self):
        """Run the scan."""
        try:
            results = []
            
            for directory in self.directories:
                # Initialize detection engine
                detection_engine.initialize(self.db)
                
                # Scan directory
                result = detection_engine.scan_directory(directory, current_user["id"] if current_user else None)
                
                if result:
                    results.append(result)
            
            # Emit results
            self.scan_complete.emit(results)
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")


class ThreatDetailsDialog(QDialog):
    """Dialog showing detailed information about a detected threat."""
    
    def __init__(self, result, parent=None):
        super().__init__(parent)
        
        self.result = result
        self.setWindowTitle("Threat Details")
        self.setMinimumSize(700, 500)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
                border-radius: 10px;
            }}
        """)
        
        # Play alert sound based on risk level
        risk_level = result["risk_level"] * 100
        if risk_level >= 70:
            sound_manager.play_alert_sound("HIGH")
        elif risk_level >= 40:
            sound_manager.play_alert_sound("MEDIUM")
        else:
            sound_manager.play_alert_sound("LOW")
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header with risk level
        header = QHBoxLayout()
        
        risk_level = result["risk_level"] * 100
        risk_color = COLOR_DANGER if risk_level >= 70 else (COLOR_WARNING if risk_level >= 40 else COLOR_SUCCESS)
        
        title = QLabel("Threat Analysis")
        title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header.addWidget(title)
        
        risk_label = QLabel(f"Risk Level: {risk_level:.1f}%")
        risk_label.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {risk_color};")
        risk_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        header.addWidget(risk_label)
        
        layout.addLayout(header)
        
        # Create a card for the file details
        details_card = CardFrame("File Information")
        details_layout = QGridLayout()
        details_layout.setColumnStretch(1, 1)
        details_layout.setColumnMinimumWidth(0, 150)
        
        # Path
        details_layout.addWidget(QLabel("Path:"), 0, 0)
        path_label = QLabel(result["file_path"])
        path_label.setStyleSheet(f"color: {COLOR_TEXT}; font-weight: bold;")
        path_label.setWordWrap(True)
        details_layout.addWidget(path_label, 0, 1)
        
        # File hash
        details_layout.addWidget(QLabel("SHA-256 Hash:"), 1, 0)
        hash_label = QLabel(result["file_hash"])
        hash_label.setStyleSheet(f"color: {COLOR_TEXT}; font-family: monospace;")
        details_layout.addWidget(hash_label, 1, 1)
        
        # File size
        details_layout.addWidget(QLabel("Size:"), 2, 0)
        size_label = QLabel(f"{result['file_size']/1024:.1f} KB")
        details_layout.addWidget(size_label, 2, 1)
        
        # Detection method
        details_layout.addWidget(QLabel("Detection Method:"), 3, 0)
        method_label = QLabel(result["detection_method"])
        method_label.setStyleSheet(f"color: {COLOR_PRIMARY}; font-weight: bold;")
        details_layout.addWidget(method_label, 3, 1)
        
        # Time detected
        details_layout.addWidget(QLabel("Detection Time:"), 4, 0)
        time_label = QLabel(datetime.fromisoformat(result["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"))
        details_layout.addWidget(time_label, 4, 1)
        
        details_card.add_widget(details_layout)
        layout.addWidget(details_card)
        
        # Create a card for the threat analysis
        analysis_card = CardFrame("Threat Analysis")
        analysis_layout = QVBoxLayout()
        
        # Add features visualization if available
        features = result.get("features")
        if features:
            try:
                features_dict = json.loads(features)
                features_layout = QGridLayout()
                row = 0
                for key, value in features_dict.items():
                    # Create feature name
                    feature_name = QLabel(key.replace('_', ' ').title())
                    feature_name.setStyleSheet(f"color: {COLOR_SECONDARY_TEXT};")
                    features_layout.addWidget(feature_name, row, 0)
                    
                    # Create value bar
                    value_normalized = min(1.0, float(value) / 100.0)  # Normalize to 0-1 range
                    value_bar = QProgressBar()
                    value_bar.setRange(0, 100)
                    value_bar.setValue(int(value_normalized * 100))
                    
                    # Color based on contribution to risk
                    color = COLOR_DANGER if value_normalized > 0.7 else (
                        COLOR_WARNING if value_normalized > 0.4 else COLOR_SUCCESS)
                    
                    value_bar.setStyleSheet(f"""
                        QProgressBar {{
                            border: none;
                            background-color: {COLOR_CARD_BG};
                            height: 8px;
                            border-radius: 4px;
                            text-align: center;
                        }}
                        QProgressBar::chunk {{
                            background-color: {color};
                            border-radius: 4px;
                        }}
                    """)
                    features_layout.addWidget(value_bar, row, 1)
                    
                    # Value percentage
                    value_label = QLabel(f"{value_normalized*100:.1f}%")
                    value_label.setStyleSheet(f"color: {color};")
                    features_layout.addWidget(value_label, row, 2)
                    
                    row += 1
                
                analysis_layout.addLayout(features_layout)
            except Exception as e:
                analysis_layout.addWidget(QLabel(f"Could not parse features: {str(e)}"))
        else:
            analysis_layout.addWidget(QLabel("No detailed features available."))
        
        analysis_card.add_widget(analysis_layout)
        layout.addWidget(analysis_card)
        
        # Actions
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        # Quarantine button
        quarantine_button = QPushButton("Quarantine File")
        quarantine_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_DANGER};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #FF3333;
            }}
        """)
        quarantine_button.clicked.connect(self.quarantine_file)
        buttons_layout.addWidget(quarantine_button)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        close_button.clicked.connect(self.accept)
        buttons_layout.addWidget(close_button)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def quarantine_file(self):
        """Quarantine the file."""
        try:
            # Initialize quarantine module
            quarantine.initialize(self.parent().db)
            
            # Quarantine the file
            success = quarantine.quarantine_file(
                self.result["file_path"], 
                current_user["id"] if current_user else None
            )
            
            if success:
                QMessageBox.information(self, "Success", f"File has been moved to quarantine.")
                self.accept()
            else:
                QMessageBox.critical(self, "Error", f"Failed to quarantine file.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to quarantine file: {str(e)}")


class ReportsPage(QWidget):
    """Reports page displaying scan results."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 20)
        layout.setSpacing(20)
        
        # Header section with actions
        header = QFrame()
        header_layout = QHBoxLayout()
        
        header_title = QLabel("Scan Reports")
        header_title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header_layout.addWidget(header_title)
        
        # Add spacer
        header_layout.addStretch()
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        refresh_button.clicked.connect(self.refresh_data)
        header_layout.addWidget(refresh_button)
        
        # New scan button
        scan_button = QPushButton("New Scan")
        scan_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
        """)
        scan_button.clicked.connect(self.new_scan)
        header_layout.addWidget(scan_button)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Risk summary cards
        risk_summary = QHBoxLayout()
        
        # Calculate risk stats
        detection_results = self.db.get_detection_results()
        low_risk = sum(1 for result in detection_results if result["risk_level"] < ALERT_LEVELS["MEDIUM"])
        medium_risk = sum(1 for result in detection_results if ALERT_LEVELS["MEDIUM"] <= result["risk_level"] < ALERT_LEVELS["HIGH"])
        high_risk = sum(1 for result in detection_results if result["risk_level"] >= ALERT_LEVELS["HIGH"])
        
        # Create risk cards
        risk_summary.addWidget(StatCard("Low Risk", low_risk, color=COLOR_SUCCESS))
        risk_summary.addWidget(StatCard("Medium Risk", medium_risk, color=COLOR_WARNING))
        risk_summary.addWidget(StatCard("High Risk", high_risk, color=COLOR_DANGER))
        
        layout.addLayout(risk_summary)
        
        # Detection results table
        results_card = CardFrame("Detection Results")
        
        self.results_table = ModernTable(["Time", "File Path", "Risk Level", "Method", "Size", "Actions"])
        self.results_table.cellClicked.connect(self.handle_result_click)
        self.update_results_table()
        results_card.add_widget(self.results_table)
        
        # Quarantine button
        quarantine_button = QPushButton("Quarantine Selected")
        quarantine_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_DANGER};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #f43f5e;
            }}
        """)
        quarantine_button.clicked.connect(self.quarantine_file)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(quarantine_button)
        
        results_layout = QVBoxLayout()
        results_layout.addWidget(self.results_table)
        results_layout.addLayout(button_layout)
        
        results_card.content_layout.addLayout(results_layout)
        layout.addWidget(results_card)
        
        self.setLayout(layout)
    
    def update_results_table(self):
        """Update the results table with latest data."""
        self.results_table.setRowCount(0)
        
        # Get detection results from database
        results = self.db.get_detection_results()
        
        for row, result in enumerate(results):
            self.results_table.insertRow(row)
            
            # Time
            time_item = QTableWidgetItem(datetime.fromisoformat(result["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"))
            self.results_table.setItem(row, 0, time_item)
            
            # File path
            self.results_table.setItem(row, 1, QTableWidgetItem(result["file_path"]))
            
            # Risk level
            risk_level_item = QTableWidgetItem(f"{result['risk_level']*100:.1f}%")
            if result["risk_level"] >= ALERT_LEVELS["HIGH"]:
                risk_level_item.setForeground(QColor(COLOR_DANGER))
            elif result["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
                risk_level_item.setForeground(QColor(COLOR_WARNING))
            else:
                risk_level_item.setForeground(QColor(COLOR_SUCCESS))
            self.results_table.setItem(row, 2, risk_level_item)
            
            # Detection method
            self.results_table.setItem(row, 3, QTableWidgetItem(result["detection_method"]))
            
            # File size
            file_size = QTableWidgetItem(f"{result['file_size']/1024:.1f} KB")
            self.results_table.setItem(row, 4, file_size)
            
            # Actions
            actions_item = QTableWidgetItem("Details | Quarantine")
            actions_item.setForeground(QColor(COLOR_PRIMARY))
            self.results_table.setItem(row, 5, actions_item)
            
            # Set row ID for reference
            self.results_table.setItem(row, 6, QTableWidgetItem(str(result["id"])))
            self.results_table.hideColumn(6)
    
    def refresh_data(self):
        """Refresh the table data."""
        self.update_results_table()
    
    def new_scan(self):
        """Initiate a new scan."""
        try:
            # Ask for directory
            directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
            
            if directory:
                # Start scan thread
                self.scan_thread = ScanThread([directory], self.db)
                self.scan_thread.scan_complete.connect(self.scan_finished)
                self.scan_thread.start()
                
                # Show progress dialog
                self.progress_dialog = QDialog(self)
                self.progress_dialog.setWindowTitle("Scanning...")
                self.progress_dialog.setFixedSize(400, 150)
                self.progress_dialog.setStyleSheet(f"background-color: {COLOR_BACKGROUND};")
                
                dialog_layout = QVBoxLayout()
                
                # Status label
                self.scan_status_label = QLabel(f"Scanning {directory}...")
                self.scan_status_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14px;")
                self.scan_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                dialog_layout.addWidget(self.scan_status_label)
                
                # Progress bar
                self.scan_progress = QProgressBar()
                self.scan_progress.setRange(0, 0)  # Indeterminate
                self.scan_progress.setTextVisible(False)
                self.scan_progress.setStyleSheet(f"""
                    QProgressBar {{
                        border: none;
                        background-color: {COLOR_CARD_BG};
                        height: 8px;
                        border-radius: 4px;
                    }}
                    QProgressBar::chunk {{
                        background-color: {COLOR_PRIMARY};
                        border-radius: 4px;
                    }}
                """)
                dialog_layout.addWidget(self.scan_progress)
                
                # Cancel button
                cancel_button = QPushButton("Cancel")
                cancel_button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLOR_CARD_BG};
                        color: {COLOR_TEXT};
                        border-radius: 6px;
                        padding: 10px 20px;
                    }}
                    QPushButton:hover {{
                        background-color: #373747;
                    }}
                """)
                cancel_button.clicked.connect(self.cancel_scan)
                
                button_layout = QHBoxLayout()
                button_layout.addStretch()
                button_layout.addWidget(cancel_button)
                dialog_layout.addLayout(button_layout)
                
                self.progress_dialog.setLayout(dialog_layout)
                self.progress_dialog.exec()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
    
    def cancel_scan(self):
        """Cancel the current scan."""
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scan_thread.terminate()
        
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
    
    def scan_finished(self, results):
        """Handle scan completion."""
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        
        # Update UI
        self.update_results_table()
        
        # Show results
        total_scanned = sum(result["files_scanned"] for result in results)
        total_threats = sum(result["threats_found"] for result in results)
        
        message = f"Scan completed.\n\nFiles scanned: {total_scanned}\nThreats found: {total_threats}"
        
        QMessageBox.information(self, "Scan Results", message)
    
    def handle_result_click(self, row, col):
        """Handle clicking on a detection result item."""
        try:
            # Get result ID from hidden column
            result_id = int(self.results_table.item(row, 6).text())
            
            # Show details dialog regardless of column (make entire row clickable)
            # Get the full result data
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM detection_results WHERE id = ?", (result_id,))
                result = cursor.fetchone()
            
            if result:
                # Show threat details dialog
                details_dialog = ThreatDetailsDialog(result, self)
                details_dialog.exec()
                
                # Refresh table if needed (e.g., if file was quarantined)
                self.update_results_table()
            else:
                print(f"Warning: No result found with ID {result_id}")
        except Exception as e:
            print(f"Error handling result click: {str(e)}")
            QMessageBox.warning(self, "Error", f"Could not display details: {str(e)}")
    
    def quarantine_file(self):
        """Quarantine the selected file."""
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a file to quarantine.")
            return
        
        # Get result ID from hidden column
        row = selected_items[0].row()
        result_id = int(self.results_table.item(row, 6).text())
        
        # Get file path
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_results WHERE id = ?", (result_id,))
            result = cursor.fetchone()
        
        if not result:
            QMessageBox.critical(self, "Error", "Detection result not found.")
            return
        
        # Confirm quarantine
        confirm = QMessageBox.question(
            self,
            "Confirm Quarantine",
            f"Are you sure you want to quarantine the file?\n\n{result['file_path']}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Initialize quarantine module
            quarantine.initialize(self.db)
            
            # Quarantine the file
            success = quarantine.quarantine_file(result["file_path"], current_user["id"] if current_user else None)
            
            if success:
                QMessageBox.information(self, "Success", f"File quarantined successfully: {result['file_path']}")
                self.update_results_table()
            else:
                QMessageBox.critical(self, "Error", f"Failed to quarantine file: {result['file_path']}")


class BackupBinPage(QWidget):
    """Backup bin management page for deleted files."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 20)
        layout.setSpacing(20)
        
        # Header section
        header = QFrame()
        header_layout = QHBoxLayout()
        
        header_title = QLabel("Backup Bin")
        header_title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header_layout.addWidget(header_title)
        
        # Add spacer
        header_layout.addStretch()
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        refresh_button.clicked.connect(self.refresh_data)
        header_layout.addWidget(refresh_button)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Description
        description = QLabel("Files deleted from quarantine are stored here temporarily. You can restore them to quarantine or permanently delete them.")
        description.setStyleSheet(f"color: {COLOR_SECONDARY_TEXT};")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Backup bin items table
        backup_bin_card = CardFrame("Deleted Files")
        
        self.backup_bin_table = ModernTable(["Time", "Original Path", "Size", "Actions"])
        self.update_backup_bin_table()
        backup_bin_card.add_widget(self.backup_bin_table)
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Only admins can restore/delete files
        if current_user and current_user["is_admin"]:
            # Restore button
            restore_button = QPushButton("Restore Selected")
            restore_button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLOR_INFO};
                    color: white;
                    border-radius: 6px;
                    padding: 10px 20px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: #60a5fa;
                }}
            """)
            restore_button.clicked.connect(self.restore_file)
            button_layout.addWidget(restore_button)
            
            # Delete button
            delete_button = QPushButton("Permanently Delete")
            delete_button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLOR_DANGER};
                    color: white;
                    border-radius: 6px;
                    padding: 10px 20px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: #f43f5e;
                }}
            """)
            delete_button.clicked.connect(self.permanently_delete)
            button_layout.addWidget(delete_button)
        else:
            permission_label = QLabel("Only administrators can restore or permanently delete files")
            permission_label.setStyleSheet(f"color: {COLOR_SECONDARY_TEXT};")
            button_layout.addWidget(permission_label)
        
        backup_bin_card.content_layout.addLayout(button_layout)
        layout.addWidget(backup_bin_card)
        
        self.setLayout(layout)
    
    def update_backup_bin_table(self):
        """Update the backup bin table with latest data."""
        self.backup_bin_table.setRowCount(0)
        
        # Initialize quarantine module
        quarantine.initialize(self.db)
        
        # Get backup bin items
        items = quarantine.get_backup_bin_items()
        
        for row, item in enumerate(items):
            self.backup_bin_table.insertRow(row)
            
            # Time
            timestamp = item.get("timestamp", "Unknown")
            if timestamp != "Unknown":
                try:
                    time_str = datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    time_str = timestamp
            else:
                time_str = "Unknown"
            
            time_item = QTableWidgetItem(time_str)
            self.backup_bin_table.setItem(row, 0, time_item)
            
            # Original path
            original_path = "Unknown"
            if item.get("metadata") and "original_path" in item["metadata"]:
                original_path = item["metadata"]["original_path"]
            else:
                original_path = item["filename"]
            
            self.backup_bin_table.setItem(row, 1, QTableWidgetItem(original_path))
            
            # File size
            file_size = QTableWidgetItem(f"{item['size']/1024:.1f} KB")
            self.backup_bin_table.setItem(row, 2, file_size)
            
            # Actions
            actions_item = QTableWidgetItem("Restore | Delete Permanently")
            actions_item.setForeground(QColor(COLOR_PRIMARY))
            self.backup_bin_table.setItem(row, 3, actions_item)
            
            # Store filename (hidden)
            self.backup_bin_table.setItem(row, 4, QTableWidgetItem(item["filename"]))
            self.backup_bin_table.hideColumn(4)
    
    def refresh_data(self):
        """Refresh the table data."""
        self.update_backup_bin_table()
    
    def restore_file(self):
        """Restore the selected file to quarantine."""
        # Check if user is admin
        if not current_user or not current_user["is_admin"]:
            QMessageBox.warning(self, "Access Denied", "Only administrators can restore files.")
            return
        
        selected_items = self.backup_bin_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a file to restore.")
            return
        
        # Get filename from hidden column
        row = selected_items[0].row()
        filename = self.backup_bin_table.item(row, 4).text()
        
        # Confirm restore
        confirm = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Are you sure you want to restore this file to quarantine?\n\n{self.backup_bin_table.item(row, 1).text()}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Initialize quarantine module
            quarantine.initialize(self.db)
            
            # Restore the file
            user_id = current_user["id"] if current_user else None
            success = quarantine.restore_from_backup(filename, user_id)
            
            if success:
                QMessageBox.information(self, "Success", "File restored to quarantine successfully.")
                self.update_backup_bin_table()
            else:
                QMessageBox.critical(self, "Error", "Failed to restore file.")
    
    def permanently_delete(self):
        """Permanently delete the selected file."""
        # Check if user is admin
        if not current_user or not current_user["is_admin"]:
            QMessageBox.warning(self, "Access Denied", "Only administrators can permanently delete files.")
            return
        
        selected_items = self.backup_bin_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a file to delete.")
            return
        
        # Get filename from hidden column
        row = selected_items[0].row()
        filename = self.backup_bin_table.item(row, 4).text()
        
        # Confirm permanent deletion
        confirm = QMessageBox.warning(
            self,
            "Confirm Permanent Deletion",
            f"Are you sure you want to PERMANENTLY delete this file?\n\n{self.backup_bin_table.item(row, 1).text()}\n\nThis action CANNOT be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Initialize quarantine module
            quarantine.initialize(self.db)
            
            # Delete the file permanently
            user_id = current_user["id"] if current_user else None
            success = quarantine.permanently_delete_from_backup(filename, user_id)
            
            if success:
                QMessageBox.information(self, "Success", "File permanently deleted.")
                self.update_backup_bin_table()
            else:
                QMessageBox.critical(self, "Error", "Failed to delete file.")


class QuarantinePage(QWidget):
    """Quarantine management page."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 20)
        layout.setSpacing(20)
        
        # Header section
        header = QFrame()
        header_layout = QHBoxLayout()
        
        header_title = QLabel("Quarantine Management")
        header_title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header_layout.addWidget(header_title)
        
        # Add spacer
        header_layout.addStretch()
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        refresh_button.clicked.connect(self.refresh_data)
        header_layout.addWidget(refresh_button)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Quarantine stats
        stats_layout = QHBoxLayout()
        
        # Get quarantine statistics
        quarantine.initialize(self.db)
        stats = quarantine.get_quarantine_stats()
        
        if stats:
            # Create stat cards
            stats_layout.addWidget(StatCard("Quarantined Files", stats["total_items"], color=COLOR_INFO))
            stats_layout.addWidget(StatCard("Total Size", f"{stats['total_size_mb']:.2f} MB", color=COLOR_PRIMARY))
            
            # Risk distribution
            risk_layout = QVBoxLayout()
            risk_card = CardFrame("Risk Distribution")
            
            risk_grid = QGridLayout()
            risk_grid.setColumnStretch(1, 1)
            
            # High risk
            risk_grid.addWidget(QLabel("High Risk:"), 0, 0)
            high_risk_bar = QProgressBar()
            high_risk_bar.setRange(0, stats["total_items"] if stats["total_items"] > 0 else 1)
            high_risk_bar.setValue(stats["high_risk"])
            high_risk_bar.setTextVisible(False)
            high_risk_bar.setStyleSheet(f"""
                QProgressBar {{
                    border: none;
                    background-color: {COLOR_CARD_BG};
                    height: 8px;
                    border-radius: 4px;
                }}
                QProgressBar::chunk {{
                    background-color: {COLOR_DANGER};
                    border-radius: 4px;
                }}
            """)
            risk_grid.addWidget(high_risk_bar, 0, 1)
            risk_grid.addWidget(QLabel(str(stats["high_risk"])), 0, 2)
            
            # Medium risk
            risk_grid.addWidget(QLabel("Medium Risk:"), 1, 0)
            medium_risk_bar = QProgressBar()
            medium_risk_bar.setRange(0, stats["total_items"] if stats["total_items"] > 0 else 1)
            medium_risk_bar.setValue(stats["medium_risk"])
            medium_risk_bar.setTextVisible(False)
            medium_risk_bar.setStyleSheet(f"""
                QProgressBar {{
                    border: none;
                    background-color: {COLOR_CARD_BG};
                    height: 8px;
                    border-radius: 4px;
                }}
                QProgressBar::chunk {{
                    background-color: {COLOR_WARNING};
                    border-radius: 4px;
                }}
            """)
            risk_grid.addWidget(medium_risk_bar, 1, 1)
            risk_grid.addWidget(QLabel(str(stats["medium_risk"])), 1, 2)
            
            # Low risk
            risk_grid.addWidget(QLabel("Low Risk:"), 2, 0)
            low_risk_bar = QProgressBar()
            low_risk_bar.setRange(0, stats["total_items"] if stats["total_items"] > 0 else 1)
            low_risk_bar.setValue(stats["low_risk"])
            low_risk_bar.setTextVisible(False)
            low_risk_bar.setStyleSheet(f"""
                QProgressBar {{
                    border: none;
                    background-color: {COLOR_CARD_BG};
                    height: 8px;
                    border-radius: 4px;
                }}
                QProgressBar::chunk {{
                    background-color: {COLOR_SUCCESS};
                    border-radius: 4px;
                }}
            """)
            risk_grid.addWidget(low_risk_bar, 2, 1)
            risk_grid.addWidget(QLabel(str(stats["low_risk"])), 2, 2)
            
            risk_card.content_layout.addLayout(risk_grid)
            stats_layout.addWidget(risk_card)
        
        layout.addLayout(stats_layout)
        
        # Quarantine items table
        quarantine_card = CardFrame("Quarantined Files")
        
        self.quarantine_table = ModernTable(["Time", "Original Path", "Risk Level", "Size", "Actions"])
        self.update_quarantine_table()
        quarantine_card.add_widget(self.quarantine_table)
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Allow all users to restore files, but only admins to delete
        restore_button = QPushButton("Restore Selected")
        restore_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_INFO};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #60a5fa;
            }}
        """)
        restore_button.clicked.connect(self.restore_file)
        button_layout.addWidget(restore_button)
        
        # Only admins can delete files
        if current_user and current_user["is_admin"]:
            # Delete button
            delete_button = QPushButton("Delete Selected")
            delete_button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLOR_DANGER};
                    color: white;
                    border-radius: 6px;
                    padding: 10px 20px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: #f43f5e;
                }}
            """)
            delete_button.clicked.connect(self.delete_file)
            button_layout.addWidget(delete_button)
        else:
            permission_label = QLabel("Only administrators can delete files")
            permission_label.setStyleSheet(f"color: {COLOR_SECONDARY_TEXT};")
            button_layout.addWidget(permission_label)
        
        quarantine_card.content_layout.addLayout(button_layout)
        layout.addWidget(quarantine_card)
        
        self.setLayout(layout)
    
    def update_quarantine_table(self):
        """Update the quarantine table with latest data."""
        self.quarantine_table.setRowCount(0)
        
        # Get user-specific quarantine items from database
        user_id = current_user["id"] if current_user else None
        items = self.db.get_quarantine_items(user_id)
        
        for row, item in enumerate(items):
            self.quarantine_table.insertRow(row)
            
            # Time
            time_item = QTableWidgetItem(datetime.fromisoformat(item["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"))
            self.quarantine_table.setItem(row, 0, time_item)
            
            # Original path
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(item["original_path"]))
            
            # Risk level
            risk_level_item = QTableWidgetItem(f"{item['risk_level']*100:.1f}%")
            if item["risk_level"] >= ALERT_LEVELS["HIGH"]:
                risk_level_item.setForeground(QColor(COLOR_DANGER))
            elif item["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
                risk_level_item.setForeground(QColor(COLOR_WARNING))
            else:
                risk_level_item.setForeground(QColor(COLOR_SUCCESS))
            self.quarantine_table.setItem(row, 2, risk_level_item)
            
            # File size
            file_size = QTableWidgetItem(f"{item['file_size']/1024:.1f} KB")
            self.quarantine_table.setItem(row, 3, file_size)
            
            # Actions
            actions_item = QTableWidgetItem("Restore | Delete")
            actions_item.setForeground(QColor(COLOR_PRIMARY))
            self.quarantine_table.setItem(row, 4, actions_item)
            
            # Set row ID for reference
            self.quarantine_table.setItem(row, 5, QTableWidgetItem(str(item["id"])))
            self.quarantine_table.hideColumn(5)
    
    def refresh_data(self):
        """Refresh the table data."""
        self.update_quarantine_table()
    
    def restore_file(self):
        """Restore the selected file from quarantine."""
        # Ensure user is logged in
        if not current_user:
            QMessageBox.warning(self, "Access Denied", "Please log in to restore files.")
            return
        
        selected_items = self.quarantine_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a file to restore.")
            return
        
        # Get quarantine ID from hidden column
        row = selected_items[0].row()
        quarantine_id = int(self.quarantine_table.item(row, 5).text())
        
        # Get quarantine item details
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (quarantine_id,))
            item = cursor.fetchone()
        
        if not item:
            QMessageBox.critical(self, "Error", "Quarantine item not found.")
            return
        
        # Confirm restore
        confirm = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Are you sure you want to restore the file?\n\n{item['original_path']}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Initialize quarantine module
            quarantine.initialize(self.db)
            
            # Restore the file
            user_id = current_user["id"] if current_user else None
            success = quarantine.restore_file(quarantine_id, user_id)
            
            if success:
                QMessageBox.information(self, "Success", "File restored successfully.")
                self.update_quarantine_table()
            else:
                QMessageBox.critical(self, "Error", "Failed to restore file.")
    
    def delete_file(self):
        """Delete the selected file from quarantine."""
        # Check if user is admin
        if not current_user or not current_user["is_admin"]:
            QMessageBox.warning(self, "Access Denied", "Only administrators can delete files.")
            return
        
        selected_items = self.quarantine_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a file to delete.")
            return
        
        # Get quarantine ID from hidden column
        row = selected_items[0].row()
        quarantine_id = int(self.quarantine_table.item(row, 5).text())
        
        # Get quarantine item details
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (quarantine_id,))
            item = cursor.fetchone()
        
        if not item:
            QMessageBox.critical(self, "Error", "Quarantine item not found.")
            return
        
        # Confirm delete
        confirm = QMessageBox.warning(
            self,
            "Confirm Delete",
            f"Are you sure you want to permanently delete the file?\n\n{item['original_path']}\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Initialize quarantine module
            quarantine.initialize(self.db)
            
            # Delete the file
            user_id = current_user["id"] if current_user else None
            success = quarantine.delete_file(quarantine_id, user_id)
            
            if success:
                QMessageBox.information(self, "Success", "File deleted successfully.")
                self.update_quarantine_table()
            else:
                QMessageBox.critical(self, "Error", "Failed to delete file.")


class LogsPage(QWidget):
    """System logs page."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 20)
        layout.setSpacing(20)
        
        # Header section
        header = QFrame()
        header_layout = QHBoxLayout()
        
        header_title = QLabel("System Logs")
        header_title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header_layout.addWidget(header_title)
        
        # Add spacer
        header_layout.addStretch()
        
        # Log level filter
        filter_label = QLabel("Filter by level:")
        filter_label.setStyleSheet(f"color: {COLOR_TEXT};")
        header_layout.addWidget(filter_label)
        
        self.level_filter = QComboBox()
        self.level_filter.addItems(["All", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.level_filter.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 8px;
                min-width: 120px;
            }}
            QComboBox:hover {{
                background-color: #373747;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                selection-background-color: {COLOR_PRIMARY};
            }}
        """)
        self.level_filter.currentIndexChanged.connect(self.apply_filter)
        header_layout.addWidget(self.level_filter)
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        refresh_button.clicked.connect(self.refresh_data)
        header_layout.addWidget(refresh_button)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Logs table
        logs_card = CardFrame("Log Entries")
        
        self.logs_table = ModernTable(["Time", "Level", "Message"])
        self.update_logs_table()
        logs_card.add_widget(self.logs_table)
        
        layout.addWidget(logs_card)
        
        self.setLayout(layout)
    
    def update_logs_table(self):
        """Update the logs table with latest data."""
        self.logs_table.setRowCount(0)
        
        # Get user-specific logs from database
        user_id = current_user["id"] if current_user else None
        logs = self.db.get_logs(user_id)
        
        # Apply filter if needed
        current_filter = self.level_filter.currentText()
        if current_filter != "All":
            logs = [log for log in logs if log["level"] == current_filter]
        
        for row, log in enumerate(logs):
            self.logs_table.insertRow(row)
            
            # Time
            time_item = QTableWidgetItem(datetime.fromisoformat(log["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"))
            self.logs_table.setItem(row, 0, time_item)
            
            # Level
            level_item = QTableWidgetItem(log["level"])
            if log["level"] == "ERROR" or log["level"] == "CRITICAL":
                level_item.setForeground(QColor(COLOR_DANGER))
            elif log["level"] == "WARNING":
                level_item.setForeground(QColor(COLOR_WARNING))
            elif log["level"] == "INFO":
                level_item.setForeground(QColor(COLOR_INFO))
            else:
                level_item.setForeground(QColor(COLOR_SECONDARY_TEXT))
            self.logs_table.setItem(row, 1, level_item)
            
            # Message
            self.logs_table.setItem(row, 2, QTableWidgetItem(log["message"]))
            
            # Set row ID for reference
            self.logs_table.setItem(row, 3, QTableWidgetItem(str(log["id"])))
            self.logs_table.hideColumn(3)
    
    def refresh_data(self):
        """Refresh the table data."""
        self.update_logs_table()
    
    def apply_filter(self):
        """Apply the level filter."""
        self.update_logs_table()


class SettingsPage(QWidget):
    """Settings page for system configuration."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 20)
        layout.setSpacing(20)
        
        # Header section
        header = QFrame()
        header_layout = QHBoxLayout()
        
        header_title = QLabel("System Settings")
        header_title.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {COLOR_TEXT};")
        header_layout.addWidget(header_title)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Check if user is admin
        # In Windows, we always allow access to settings for all users
        # This is because we're running a desktop app and the access control
        # will be handled by the operating system user accounts

        # Debug message for admin access
        print("Settings access granted")
        
        # Settings form
        settings_scroll = QScrollArea()
        settings_scroll.setWidgetResizable(True)
        settings_scroll.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                background-color: transparent;
            }}
            QScrollBar:vertical {{
                background-color: {COLOR_CARD_BG};
                width: 12px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background-color: #4b5563;
                border-radius: 6px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """)
        
        settings_widget = QWidget()
        settings_layout = QVBoxLayout()
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(20)
        
        # Detection settings section
        detection_card = CardFrame("Detection Settings")
        
        detection_grid = QGridLayout()
        detection_grid.setColumnStretch(1, 1)
        detection_grid.setVerticalSpacing(15)
        
        # Get settings
        cnn_threshold = float(self.db.get_setting('cnn_threshold', str(DEFAULT_CNN_THRESHOLD)))
        lstm_threshold = float(self.db.get_setting('lstm_threshold', str(DEFAULT_LSTM_THRESHOLD)))
        
        # CNN threshold
        detection_grid.addWidget(QLabel("CNN Model Threshold:"), 0, 0)
        
        self.cnn_threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.cnn_threshold_slider.setRange(0, 100)
        self.cnn_threshold_slider.setValue(int(cnn_threshold * 100))
        self.cnn_threshold_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{
                height: 8px;
                background: {COLOR_CARD_BG};
                border-radius: 4px;
            }}
            QSlider::handle:horizontal {{
                background: {COLOR_PRIMARY};
                border: none;
                width: 18px;
                margin: -6px 0;
                border-radius: 9px;
            }}
            QSlider::sub-page:horizontal {{
                background: {COLOR_PRIMARY};
                border-radius: 4px;
            }}
        """)
        detection_grid.addWidget(self.cnn_threshold_slider, 0, 1)
        
        self.cnn_threshold_value = QLabel(f"{cnn_threshold:.2f}")
        self.cnn_threshold_value.setStyleSheet(f"color: {COLOR_TEXT};")
        detection_grid.addWidget(self.cnn_threshold_value, 0, 2)
        
        # Connect slider to value update
        self.cnn_threshold_slider.valueChanged.connect(
            lambda value: self.cnn_threshold_value.setText(f"{value/100:.2f}")
        )
        
        # LSTM threshold
        detection_grid.addWidget(QLabel("LSTM Model Threshold:"), 1, 0)
        
        self.lstm_threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.lstm_threshold_slider.setRange(0, 100)
        self.lstm_threshold_slider.setValue(int(lstm_threshold * 100))
        self.lstm_threshold_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{
                height: 8px;
                background: {COLOR_CARD_BG};
                border-radius: 4px;
            }}
            QSlider::handle:horizontal {{
                background: {COLOR_PRIMARY};
                border: none;
                width: 18px;
                margin: -6px 0;
                border-radius: 9px;
            }}
            QSlider::sub-page:horizontal {{
                background: {COLOR_PRIMARY};
                border-radius: 4px;
            }}
        """)
        detection_grid.addWidget(self.lstm_threshold_slider, 1, 1)
        
        self.lstm_threshold_value = QLabel(f"{lstm_threshold:.2f}")
        self.lstm_threshold_value.setStyleSheet(f"color: {COLOR_TEXT};")
        detection_grid.addWidget(self.lstm_threshold_value, 1, 2)
        
        # Connect slider to value update
        self.lstm_threshold_slider.valueChanged.connect(
            lambda value: self.lstm_threshold_value.setText(f"{value/100:.2f}")
        )
        
        detection_card.content_layout.addLayout(detection_grid)
        settings_layout.addWidget(detection_card)
        
        # Monitoring settings section
        monitoring_card = CardFrame("Monitoring Settings")
        
        monitoring_grid = QVBoxLayout()
        monitoring_grid.setSpacing(15)
        
        # Get settings
        auto_quarantine_value = self.db.get_setting('enable_auto_quarantine', 'False')
        auto_quarantine = auto_quarantine_value.lower() == 'true' if auto_quarantine_value else False
        scan_interval_value = self.db.get_setting('scan_interval', '3600')
        scan_interval = int(scan_interval_value) if scan_interval_value else 3600
        
        # Auto quarantine
        self.auto_quarantine_check = QCheckBox("Automatically quarantine high-risk files")
        self.auto_quarantine_check.setChecked(auto_quarantine)
        self.auto_quarantine_check.setStyleSheet(f"""
            QCheckBox {{
                font-size: 14px;
                color: {COLOR_TEXT};
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border-radius: 4px;
                border: 2px solid {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:unchecked {{
                background-color: {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:checked {{
                background-color: {COLOR_PRIMARY};
            }}
        """)
        monitoring_grid.addWidget(self.auto_quarantine_check)
        
        # Scan interval
        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Automatic scan interval:"))
        
        self.scan_interval_input = QLineEdit(str(scan_interval))
        self.scan_interval_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 8px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
                max-width: 100px;
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        interval_layout.addWidget(self.scan_interval_input)
        
        interval_layout.addWidget(QLabel("seconds"))
        interval_layout.addStretch()
        
        monitoring_grid.addLayout(interval_layout)
        
        monitoring_card.content_layout.addLayout(monitoring_grid)
        settings_layout.addWidget(monitoring_card)
        
        # Notification settings section
        notification_card = CardFrame("Notification Settings")
        
        notification_grid = QVBoxLayout()
        notification_grid.setSpacing(15)
        
        # Get settings
        sound_enabled_value = self.db.get_setting('enable_sound_alerts', 'True')
        sound_enabled = sound_enabled_value.lower() == 'true' if sound_enabled_value else True
        
        # Sound alerts
        sound_layout = QHBoxLayout()
        
        self.sound_enabled_check = QCheckBox("Enable alert sounds for detected threats")
        self.sound_enabled_check.setChecked(sound_enabled)
        self.sound_enabled_check.setStyleSheet(f"""
            QCheckBox {{
                font-size: 14px;
                color: {COLOR_TEXT};
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border-radius: 4px;
                border: 2px solid {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:unchecked {{
                background-color: {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:checked {{
                background-color: {COLOR_PRIMARY};
            }}
        """)
        sound_layout.addWidget(self.sound_enabled_check)
        
        # Add test sound button
        test_sound_button = QPushButton("Test Sound")
        test_sound_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 8px 16px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        test_sound_button.clicked.connect(self.test_sound)
        sound_layout.addWidget(test_sound_button)
        sound_layout.addStretch()
        
        notification_grid.addLayout(sound_layout)
        
        notification_card.content_layout.addLayout(notification_grid)
        settings_layout.addWidget(notification_card)
        
        # User management section
        user_card = CardFrame("User Management")
        
        user_button = QPushButton("Manage Users")
        user_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
        """)
        user_button.clicked.connect(self.show_user_management)
        user_card.content_layout.addWidget(user_button)
        
        settings_layout.addWidget(user_card)
        
        # Apply settings
        settings_widget.setLayout(settings_layout)
        settings_scroll.setWidget(settings_widget)
        layout.addWidget(settings_scroll)
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Reset button
        reset_button = QPushButton("Reset to Defaults")
        reset_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        reset_button.clicked.connect(self.reset_settings)
        button_layout.addWidget(reset_button)
        
        # Save button
        save_button = QPushButton("Save Settings")
        save_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
        """)
        save_button.clicked.connect(self.save_settings)
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def save_settings(self):
        """Save the settings to the database."""
        try:
            # Get values from UI
            cnn_threshold = self.cnn_threshold_slider.value() / 100
            lstm_threshold = self.lstm_threshold_slider.value() / 100
            auto_quarantine = self.auto_quarantine_check.isChecked()
            sound_enabled = self.sound_enabled_check.isChecked()
            
            try:
                scan_interval = int(self.scan_interval_input.text())
            except ValueError:
                QMessageBox.warning(self, "Invalid Input", "Scan interval must be a number.")
                return
            
            # Update database
            self.db.update_setting('cnn_threshold', f"{cnn_threshold:.2f}")
            self.db.update_setting('lstm_threshold', f"{lstm_threshold:.2f}")
            self.db.update_setting('enable_auto_quarantine', str(auto_quarantine))
            self.db.update_setting('enable_sound_alerts', str(sound_enabled))
            self.db.update_setting('scan_interval', str(scan_interval))
            
            # Apply sound setting immediately
            import sound_manager
            sound_manager.set_sound_enabled(sound_enabled)
            
            # Log the changes
            self.db.add_log("Settings updated", "INFO", current_user["id"] if current_user else None)
            
            # Show success message
            QMessageBox.information(self, "Success", "Settings saved successfully.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")
    
    def reset_settings(self):
        """Reset settings to default values."""
        try:
            # Confirm reset
            confirm = QMessageBox.question(
                self,
                "Confirm Reset",
                "Are you sure you want to reset all settings to default values?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if confirm == QMessageBox.StandardButton.Yes:
                # Reset to default values
                self.cnn_threshold_slider.setValue(int(DEFAULT_CNN_THRESHOLD * 100))
                self.lstm_threshold_slider.setValue(int(DEFAULT_LSTM_THRESHOLD * 100))
                self.auto_quarantine_check.setChecked(False)
                self.sound_enabled_check.setChecked(True)
                self.scan_interval_input.setText("3600")
                
                # Update database
                self.db.update_setting('cnn_threshold', f"{DEFAULT_CNN_THRESHOLD:.2f}")
                self.db.update_setting('lstm_threshold', f"{DEFAULT_LSTM_THRESHOLD:.2f}")
                self.db.update_setting('enable_auto_quarantine', "False")
                self.db.update_setting('enable_sound_alerts', "True")
                self.db.update_setting('scan_interval', "3600")
                
                # Apply sound setting immediately
                import sound_manager
                sound_manager.set_sound_enabled(True)
                
                # Log the changes
                self.db.add_log("Settings reset to defaults", "INFO", current_user["id"] if current_user else None)
                
                # Show success message
                QMessageBox.information(self, "Success", "Settings reset to default values.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reset settings: {str(e)}")
    
    def test_sound(self):
        """Play a test sound based on current settings."""
        try:
            # Check if sounds are enabled
            sound_enabled = self.sound_enabled_check.isChecked()
            
            if sound_enabled:
                # Import sound manager and play medium alert sound
                import sound_manager
                sound_manager.play_alert_sound("MEDIUM")
                
                # Show confirmation
                QMessageBox.information(self, "Sound Test", "Test sound played. If you didn't hear anything, check your system volume settings.")
            else:
                QMessageBox.information(self, "Sound Test", "Sound alerts are currently disabled. Enable them to hear alert sounds.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to play test sound: {str(e)}")
    
    def show_user_management(self):
        """Show the user management dialog."""
        dialog = UserManagementDialog(self.db, self)
        dialog.exec()


class UserManagementDialog(QDialog):
    """User management dialog."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        self.setWindowTitle("User Management")
        self.setMinimumSize(600, 400)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("User Management")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLOR_TEXT};")
        layout.addWidget(title)
        
        # User table
        self.user_table = ModernTable(["ID", "Username", "Email", "Role", "Created"])
        self.update_user_table()
        layout.addWidget(self.user_table)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        # Add user button
        add_button = QPushButton("Add User")
        add_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
        """)
        add_button.clicked.connect(self.add_user)
        button_layout.addWidget(add_button)
        
        button_layout.addStretch()
        
        # Close button
        close_button = QPushButton("Close")
        close_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def update_user_table(self):
        """Update the user table with latest data."""
        self.user_table.setRowCount(0)
        
        # Get users from database
        users = self.db.get_all_users()
        
        for row, user in enumerate(users):
            self.user_table.insertRow(row)
            
            # ID
            self.user_table.setItem(row, 0, QTableWidgetItem(str(user["id"])))
            
            # Username
            self.user_table.setItem(row, 1, QTableWidgetItem(user["username"]))
            
            # Email
            self.user_table.setItem(row, 2, QTableWidgetItem(user["email"]))
            
            # Role
            role_item = QTableWidgetItem("Admin" if user["is_admin"] else "User")
            if user["is_admin"]:
                role_item.setForeground(QColor(COLOR_PRIMARY))
            self.user_table.setItem(row, 3, role_item)
            
            # Created
            created_item = QTableWidgetItem(datetime.fromisoformat(user["created_at"]).strftime("%Y-%m-%d %H:%M:%S"))
            self.user_table.setItem(row, 4, created_item)
    
    def add_user(self):
        """Show dialog to add a new user."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add User")
        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Add New User")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_TEXT};")
        layout.addWidget(title)
        
        # Form fields
        form_layout = QFormLayout()
        form_layout.setVerticalSpacing(15)
        
        # Username
        username_input = QLineEdit()
        username_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 8px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        form_layout.addRow("Username:", username_input)
        
        # Email
        email_input = QLineEdit()
        email_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 8px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        form_layout.addRow("Email:", email_input)
        
        # Password
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_input.setStyleSheet(f"""
            QLineEdit {{
                padding: 8px;
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_CARD_BG};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_PRIMARY};
            }}
        """)
        form_layout.addRow("Password:", password_input)
        
        # Admin checkbox
        admin_check = QCheckBox("Administrator")
        admin_check.setStyleSheet(f"""
            QCheckBox {{
                font-size: 14px;
                color: {COLOR_TEXT};
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border-radius: 4px;
                border: 2px solid {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:unchecked {{
                background-color: {COLOR_CARD_BG};
            }}
            QCheckBox::indicator:checked {{
                background-color: {COLOR_PRIMARY};
            }}
        """)
        form_layout.addRow("", admin_check)
        
        layout.addLayout(form_layout)
        
        # Error message
        error_label = QLabel("")
        error_label.setStyleSheet(f"color: {COLOR_DANGER}; font-size: 12px;")
        error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(error_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        # Cancel button
        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border-radius: 6px;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background-color: #373747;
            }}
        """)
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        # Add button
        add_button = QPushButton("Add User")
        add_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HIGHLIGHT};
            }}
        """)
        
        # Add user function
        def add_user_action():
            username = username_input.text()
            email = email_input.text()
            password = password_input.text()
            is_admin = admin_check.isChecked()
            
            if not username or not email or not password:
                error_label.setText("Please fill in all fields")
                return
            
            # Validate email format (simple check)
            if "@" not in email or "." not in email:
                error_label.setText("Invalid email format")
                return
            
            # Register user
            success, message = self.db.register_user(username, email, password, is_admin)
            
            if success:
                # Update user table
                self.update_user_table()
                
                # Add log
                self.db.add_log(f"User created: {username}", "INFO", current_user["id"] if current_user else None)
                
                # Close dialog
                dialog.accept()
                
                # Show success message
                QMessageBox.information(self, "Success", "User created successfully.")
            else:
                error_label.setText(message)
        
        add_button.clicked.connect(add_user_action)
        button_layout.addWidget(add_button)
        
        layout.addLayout(button_layout)
        
        dialog.setLayout(layout)
        dialog.exec()


class HamburgerMenu(QWidget):
    """Collapsible hamburger menu for navigation."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Create layout
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(0)
        
        # Create hamburger button
        self.hamburger_btn = QPushButton("☰")
        self.hamburger_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLOR_TEXT};
                font-size: 24px;
                font-weight: bold;
                border: none;
                padding: 10px;
            }}
            QPushButton:hover {{
                color: {COLOR_PRIMARY};
            }}
        """)
        self.hamburger_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.hamburger_btn.clicked.connect(self.toggle_menu)
        
        # Create container widget to hold the buttons
        self.container = QWidget()
        self.buttons_layout = QVBoxLayout(self.container)
        self.buttons_layout.setContentsMargins(0, 0, 0, 0)
        self.buttons_layout.setSpacing(5)
        
        # Initial state: menu is collapsed (showing only icons)
        self.is_collapsed = False
        self.buttons = []  # Store buttons for toggling
        
        # Main layout setup
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(10)
        self.main_layout.addWidget(self.hamburger_btn, 0, Qt.AlignmentFlag.AlignLeft)
        self.main_layout.addWidget(self.container)
        self.main_layout.addStretch()
        
    def add_button(self, button):
        """Add a button to the menu."""
        self.buttons.append(button)
        self.buttons_layout.addWidget(button)
        
    def toggle_menu(self):
        """Toggle between expanded and collapsed menu states."""
        self.is_collapsed = not self.is_collapsed
        
        # Get the main window reference
        main_window = None
        if isinstance(self.parent(), QMainWindow):
            main_window = self.parent()
        elif self.parent() and self.parent().parent() and isinstance(self.parent().parent(), QMainWindow):
            main_window = self.parent().parent()
        
        # Create animation for smooth transition
        if self.is_collapsed:
            self.hamburger_btn.setText("☰")
            # Hide text, show only icons
            for button in self.buttons:
                text = button.text().strip()
                button.setText("")
                # Store the original text for later
                button.setProperty("original_text", text)
                button.setFixedWidth(40)  # Collapse to icon-only width
                
            # Change sidebar width if MainWindow is available
            if main_window and hasattr(main_window, 'sidebar') and hasattr(main_window, 'sidebar_collapsed_width'):
                main_window.sidebar.setFixedWidth(main_window.sidebar_collapsed_width)
        else:
            self.hamburger_btn.setText("×")
            # Restore text
            for button in self.buttons:
                original_text = button.property("original_text")
                if original_text:
                    button.setText("  " + original_text)
                    button.setMinimumWidth(180)  # Ensure plenty of width for text
                    button.setFixedWidth(QWIDGETSIZE_MAX)  # Remove width restriction
            
            # Change sidebar width if MainWindow is available
            if main_window and hasattr(main_window, 'sidebar') and hasattr(main_window, 'sidebar_expanded_width'):
                main_window.sidebar.setFixedWidth(main_window.sidebar_expanded_width)
        
        # Update layout
        self.updateGeometry()
        if self.parent():
            self.parent().adjustSize()


class MainWindow(QMainWindow):
    """Main application window."""
    
    def get_bool_setting(self, key, default="True"):
        """Safely get a boolean setting from the database."""
        value = self.db.get_setting(key, default)
        if value is None:
            return default.lower() == 'true'
        return value.lower() == 'true'
        
    def __init__(self):
        super().__init__()
        
        # Initialize sound manager for alert sounds
        sound_manager.initialize()
        
        # Initialize database first (for settings)
        self.db = DatabaseManager(DATABASE_PATH)
        
        # Apply sound settings from database
        sound_enabled = self.get_bool_setting('enable_sound_alerts', 'True')
        sound_manager.set_sound_enabled(sound_enabled)
        
        # Setup UI
        self.setWindowTitle("Ransomware Detection & Mitigation")
        self.setMinimumSize(1000, 650)  # Smaller interface size
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLOR_BACKGROUND};
            }}
        """)
        
        # Create and show splash screen
        self.splash = LoadingScreen()
        self.splash.show()
        self.splash.start_animation()
        
        # Database already initialized above
        self.splash.set_message("Database initialized")
        
        # Create quarantine directory if it doesn't exist
        global quarantine_dir
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Initialize modules
        detection_engine.initialize(self.db)
        self.splash.set_message("Detection engine initialized")
        
        file_monitor.initialize(self.db, detection_engine)
        self.splash.set_message("File monitoring initialized")
        
        process_monitor.initialize(self.db, detection_engine)
        self.splash.set_message("Process monitoring initialized")
        
        network_monitor.initialize(self.db, alert_system)
        self.splash.set_message("Network monitoring initialized")
        
        alert_system.initialize(self.db)
        self.splash.set_message("Alert system initialized")
        
        quarantine.initialize(self.db, quarantine_dir)
        self.splash.set_message("Quarantine system initialized")
        
        # Add initial log
        self.db.add_log("Application started", "INFO")
        
        # Show login dialog
        self.splash.set_message("Loading user interface...")
        QTimer.singleShot(1500, self.show_login)
    
    def show_login(self):
        """Show the login dialog."""
        self.splash.finish(self)
        
        login_dialog = LoginDialog(self.db)
        if login_dialog.exec():
            # Set global current user
            global current_user
            current_user = login_dialog.user
            
            # Initialize UI
            self.init_ui()
            
            # Start monitoring based on settings
            monitoring_enabled = self.get_bool_setting('monitoring_enabled', 'True')
            if monitoring_enabled and current_user:
                file_monitor.start_monitoring(current_user["id"])
                process_monitor.start_monitoring(current_user["id"])
                network_monitor.start_monitoring(current_user["id"])
            
            # Start alert system
            if current_user:
                alert_system.start_alert_system(current_user["id"])
            
                # Start quarantine maintenance
                quarantine.start_quarantine_maintenance(current_user["id"])
            
            # Show the main window
            self.showMaximized()
        else:
            # Exit application if login canceled
            self.close()
    
    def init_ui(self):
        """Initialize the main UI after login."""
        # Create central widget
        central_widget = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar using hamburger menu
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet(f"""
            #sidebar {{
                background-color: {COLOR_BACKGROUND};
                border-right: 1px solid {COLOR_CARD_BG};
            }}
        """)
        # When we first initialize, sidebar is collapsed
        self.sidebar_collapsed_width = 70  
        self.sidebar_expanded_width = 220  # Wider width to fit menu text
        sidebar.setFixedWidth(self.sidebar_collapsed_width)
        
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 20, 0, 20)
        sidebar_layout.setSpacing(15)
        
        # App title (icon only when collapsed)
        app_title = QLabel("RS")
        app_title.setStyleSheet(f"""
            font-size: 18px; 
            font-weight: bold; 
            color: {COLOR_PRIMARY};
            padding: 5px 10px;
            background-color: {COLOR_CARD_BG};
            border-radius: 5px;
        """)
        app_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(app_title, 0, Qt.AlignmentFlag.AlignCenter)
        
        # User info (minimal in collapsed state)
        initial = 'U'  # Default initial if user is None
        if current_user and 'username' in current_user and current_user['username']:
            initial = current_user['username'][0].upper()
        user_initial = QLabel(initial)
        user_initial.setStyleSheet(f"""
            font-size: 16px; 
            font-weight: bold; 
            color: {COLOR_TEXT};
            background-color: {COLOR_PRIMARY};
            border-radius: 15px;
            padding: 5px;
            min-width: 30px;
            min-height: 30px;
        """)
        user_initial.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(user_initial, 0, Qt.AlignmentFlag.AlignCenter)
        
        sidebar_layout.addSpacing(20)
        
        # Create hamburger menu and store the sidebar reference
        self.sidebar = sidebar  # Store reference to sidebar for toggling width
        self.hamburger_menu = HamburgerMenu(self)
        
        # Navigation buttons - add a minimum width to ensure text is fully visible when expanded
        self.dashboard_btn = SidebarButton("Dashboard", is_active=True)
        self.dashboard_btn.setMinimumWidth(180)  # Ensure enough width for text
        self.dashboard_btn.clicked.connect(lambda: self.switch_page(0))
        self.hamburger_menu.add_button(self.dashboard_btn)
        
        self.reports_btn = SidebarButton("Detection Reports")
        self.reports_btn.setMinimumWidth(180)  # Ensure enough width for text
        self.reports_btn.clicked.connect(lambda: self.switch_page(1))
        self.hamburger_menu.add_button(self.reports_btn)
        
        self.quarantine_btn = SidebarButton("Quarantine")
        self.quarantine_btn.setMinimumWidth(180)  # Ensure enough width for text
        self.quarantine_btn.clicked.connect(lambda: self.switch_page(2))
        self.hamburger_menu.add_button(self.quarantine_btn)
        
        self.backup_bin_btn = SidebarButton("Backup Bin")
        self.backup_bin_btn.setMinimumWidth(180)  # Ensure enough width for text
        self.backup_bin_btn.clicked.connect(lambda: self.switch_page(3))
        self.hamburger_menu.add_button(self.backup_bin_btn)
        
        self.logs_btn = SidebarButton("System Logs")
        self.logs_btn.setMinimumWidth(180)  # Ensure enough width for text
        self.logs_btn.clicked.connect(lambda: self.switch_page(4))
        self.hamburger_menu.add_button(self.logs_btn)
        
        # Settings button
        self.settings_btn = SidebarButton("Settings")
        self.settings_btn.setMinimumWidth(180)  # Ensure enough width for text
        self.settings_btn.clicked.connect(lambda: self.switch_page(5))
        self.hamburger_menu.add_button(self.settings_btn)
        
        sidebar_layout.addWidget(self.hamburger_menu)
        
        # Add spacer
        sidebar_layout.addStretch()
        
        # Logout button
        self.logout_btn = QPushButton("×")
        self.logout_btn.setToolTip("Logout")
        self.logout_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_DANGER};
                border-radius: 15px;
                min-width: 30px;
                min-height: 30px;
                font-size: 18px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_DANGER};
                color: white;
            }}
        """)
        self.logout_btn.clicked.connect(self.logout)
        sidebar_layout.addWidget(self.logout_btn, 0, Qt.AlignmentFlag.AlignCenter)
        
        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)
        
        # Content area
        content_container = QFrame()
        content_container.setStyleSheet(f"background-color: {COLOR_BACKGROUND};")
        
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(20, 20, 20, 0)
        
        # Stack of pages
        self.pages = QStackedWidget()
        
        # Create pages
        self.dashboard_page = DashboardPage(self.db)
        self.reports_page = ReportsPage(self.db)
        self.quarantine_page = QuarantinePage(self.db)
        self.backup_bin_page = BackupBinPage(self.db)
        self.logs_page = LogsPage(self.db)
        self.settings_page = SettingsPage(self.db)
        
        # Add pages to stack
        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.reports_page)
        self.pages.addWidget(self.quarantine_page)
        self.pages.addWidget(self.backup_bin_page)
        self.pages.addWidget(self.logs_page)
        self.pages.addWidget(self.settings_page)
        
        content_layout.addWidget(self.pages)
        content_container.setLayout(content_layout)
        
        main_layout.addWidget(content_container)
        
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
    
    def switch_page(self, index):
        """Switch to the specified page index."""
        # Add debug print
        print(f"Switching to page index: {index}")
        
        # Update active button
        self.dashboard_btn.set_active(index == 0)
        self.reports_btn.set_active(index == 1)
        self.quarantine_btn.set_active(index == 2)
        self.backup_bin_btn.set_active(index == 3)
        self.logs_btn.set_active(index == 4)
        self.settings_btn.set_active(index == 5)
        
        # Switch page - ensure valid index
        if 0 <= index < self.pages.count():
            self.pages.setCurrentIndex(index)
            print(f"Page switched to {index}")
        else:
            print(f"Invalid page index: {index}, max={self.pages.count()-1}")
            
        # Force update display to ensure UI reflects changes
        QApplication.processEvents()
    
    def logout(self):
        """Log out the current user and exit."""
        # Add log
        if current_user:
            self.db.add_log(f"User {current_user['username']} logged out", "INFO", current_user["id"])
        
        # Confirm logout
        confirm = QMessageBox.question(
            self,
            "Confirm Logout",
            "Are you sure you want to log out?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Close the application
            self.close()


if __name__ == "__main__":
    # Create application
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create dark palette
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(COLOR_BACKGROUND))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(COLOR_TEXT))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(COLOR_CARD_BG))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(COLOR_BACKGROUND))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(COLOR_CARD_BG))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(COLOR_TEXT))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor(COLOR_TEXT))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(COLOR_CARD_BG))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLOR_TEXT))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor(COLOR_PRIMARY))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(COLOR_PRIMARY))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(COLOR_TEXT))
    
    app.setPalette(dark_palette)
    
    # Create and show main window
    main_window = MainWindow()
    
    # Start application
    sys.exit(app.exec())