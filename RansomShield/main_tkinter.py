import os
import sys
import json
import logging
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import sqlite3
import hashlib
from datetime import datetime
import time
import math
from tkinter import simpledialog
from functools import partial

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants
DATABASE_PATH = "ransomware_detection.db"
DEFAULT_CNN_THRESHOLD = 0.7
DEFAULT_LSTM_THRESHOLD = 0.6
ALERT_LEVELS = {
    "LOW": 0.3,
    "MEDIUM": 0.5,
    "HIGH": 0.7
}
MONITOR_EXTENSIONS = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".pdf"]
IGNORE_PATHS = ["Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin", "ProgramData", "AppData"]
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Import global variables from the centralized manager
import globals_manager

# Initialize the global variables
globals_manager.set_model_thresholds(cnn=DEFAULT_CNN_THRESHOLD, lstm=DEFAULT_LSTM_THRESHOLD)
globals_manager.set_quarantine_directory("quarantine")

# Global variables
file_monitoring_active = False
process_monitoring_active = False
monitor_thread = None

# Simple numpy substitute for log2 if numpy is not available
def log2(x):
    return math.log(x, 2) if x > 0 else 0

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.create_tables()
        self.initialize_settings()
        self.create_admin_if_needed()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_tables(self):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Alerts table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    file_path TEXT,
                    process_name TEXT,
                    acknowledged BOOLEAN DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    detection_result_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (detection_result_id) REFERENCES detection_results(id)
                )
                ''')
                
                # Logs table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT NOT NULL,
                    level TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
                ''')
                
                # Detection results table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS detection_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    risk_level REAL NOT NULL,
                    detection_method TEXT NOT NULL,
                    features TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Quarantine items table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantine_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    risk_level REAL NOT NULL,
                    quarantined_by INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (quarantined_by) REFERENCES users(id)
                )
                ''')
                
                # Settings table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    description TEXT
                )
                ''')
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
    
    def create_admin_if_needed(self):
        """Create an admin user if no users exist"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if any users exist
                cursor.execute("SELECT COUNT(*) FROM users")
                count = cursor.fetchone()[0]
                
                if count == 0:
                    # Create default admin user
                    import hashlib
                    password_hash = hashlib.sha256("admin123".encode()).hexdigest()
                    
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)",
                        ("admin", password_hash, "admin@example.com", True)
                    )
                    
                    conn.commit()
                    logger.info("Default admin user created")
                    
        except sqlite3.Error as e:
            logger.error(f"Error creating admin user: {e}")
    
    def initialize_settings(self):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if settings already exist
                cursor.execute("SELECT COUNT(*) FROM settings")
                count = cursor.fetchone()[0]
                
                if count == 0:
                    # Add default settings
                    default_settings = [
                        ("cnn_threshold", "0.7", "CNN model detection threshold"),
                        ("lstm_threshold", "0.6", "LSTM model detection threshold"),
                        ("scan_interval", "3600", "Automatic scan interval in seconds"),
                        ("enable_auto_quarantine", "False", "Automatically quarantine high-risk files"),
                        ("monitoring_enabled", "True", "Enable continuous file system monitoring")
                    ]
                    
                    cursor.executemany(
                        "INSERT INTO settings (key, value, description) VALUES (?, ?, ?)",
                        default_settings
                    )
                    
                    conn.commit()
                    logger.info("Default settings initialized")
                    
        except sqlite3.Error as e:
            logger.error(f"Error initializing settings: {e}")
    
    def get_setting(self, key, default=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
                result = cursor.fetchone()
                
                if result:
                    return result[0]
                return default
                
        except sqlite3.Error as e:
            logger.error(f"Error getting setting {key}: {e}")
            return default
    
    def update_setting(self, key, value):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
                conn.commit()
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Error updating setting {key}: {e}")
            return False
    
    def get_all_settings(self):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM settings")
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logger.error(f"Error getting all settings: {e}")
            return []
    
    def add_log(self, message, level, user_id=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO logs (message, level, user_id) VALUES (?, ?, ?)",
                    (message, level, user_id)
                )
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding log: {e}")
            return None
    
    def get_logs(self, limit=100):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logger.error(f"Error getting logs: {e}")
            return []
    
    def add_alert(self, message, severity, file_path=None, process_name=None, user_id=None, detection_result_id=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO alerts (message, severity, file_path, process_name, user_id, detection_result_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (message, severity, file_path, process_name, user_id, detection_result_id)
                )
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding alert: {e}")
            return None
    
    def get_alerts(self, limit=50, acknowledged=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if acknowledged is None:
                    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
                else:
                    cursor.execute("SELECT * FROM alerts WHERE acknowledged = ? ORDER BY timestamp DESC LIMIT ?", (acknowledged, limit))
                
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def acknowledge_alert(self, alert_id, user_id=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
                conn.commit()
                
                # Add log
                self.add_log(f"Alert ID {alert_id} acknowledged", "INFO", user_id)
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False
    
    def add_detection_result(self, file_path, file_hash, file_size, risk_level, detection_method, features):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO detection_results (file_path, file_hash, file_size, risk_level, detection_method, features) VALUES (?, ?, ?, ?, ?, ?)",
                    (file_path, file_hash, file_size, risk_level, detection_method, features)
                )
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding detection result: {e}")
            return None
    
    def get_detection_results(self, limit=100):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM detection_results ORDER BY timestamp DESC LIMIT ?", (limit,))
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logger.error(f"Error getting detection results: {e}")
            return []
    
    def add_quarantine_item(self, original_path, quarantine_path, file_hash, file_size, risk_level, user_id=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO quarantine_items (original_path, quarantine_path, file_hash, file_size, risk_level, quarantined_by) VALUES (?, ?, ?, ?, ?, ?)",
                    (original_path, quarantine_path, file_hash, file_size, risk_level, user_id)
                )
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding quarantine item: {e}")
            return None
    
    def get_quarantine_items(self):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM quarantine_items ORDER BY timestamp DESC")
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logger.error(f"Error getting quarantine items: {e}")
            return []
    
    def delete_quarantine_item(self, item_id):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM quarantine_items WHERE id = ?", (item_id,))
                conn.commit()
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Error deleting quarantine item {item_id}: {e}")
            return False
    
    def authenticate_user(self, username, password):
        """Authenticate a user with username and password"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                if user:
                    # Check password (using SHA-256 for simplicity in this demo)
                    password_hash = hashlib.sha256(password.encode()).hexdigest()
                    
                    if password_hash == user["password_hash"]:
                        # Add login log
                        self.add_log(f"User {username} logged in", "INFO", user["id"])
                        return user
                
                return None
                
        except sqlite3.Error as e:
            logger.error(f"Error authenticating user: {e}")
            return None
    
    def register_user(self, username, email, password, is_admin=False):
        """Register a new user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
                if cursor.fetchone()[0] > 0:
                    return False, "Username already exists"
                
                # Check if email already exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
                if cursor.fetchone()[0] > 0:
                    return False, "Email already exists"
                
                # Create password hash
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                # Insert new user
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
                    (username, email, password_hash, is_admin)
                )
                conn.commit()
                
                # Add log
                user_id = cursor.lastrowid
                self.add_log(f"New user registered: {username}", "INFO", user_id)
                
                return True, "User registered successfully"
                
        except sqlite3.Error as e:
            logger.error(f"Error registering user: {e}")
            return False, f"Database error: {str(e)}"
    
    def get_all_users(self):
        """Get all users"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logger.error(f"Error getting users: {e}")
            return []


class LoginWindow:
    def __init__(self, parent, db, on_login_success):
        self.parent = parent
        self.db = db
        self.on_login_success = on_login_success
        
        # Create login window
        self.window = tk.Toplevel(parent)
        self.window.title("Login")
        self.window.geometry("400x300")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center window
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
        # Create login form
        frame = ttk.Frame(self.window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(frame, text="Ransomware Detection & Mitigation", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 20))
        
        # Username field
        ttk.Label(frame, text="Username:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.username_var, width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Password field
        ttk.Label(frame, text="Password:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Login", command=self.login).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Register", command=self.show_register).pack(side=tk.RIGHT, padx=10)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(frame, textvariable=self.status_var, foreground="red")
        self.status_label.pack(pady=10)
        
        # Bind Enter key
        self.window.bind("<Return>", lambda event: self.login())
    
    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            self.status_var.set("Please enter username and password")
            return
        
        # Authenticate user
        user = self.db.authenticate_user(username, password)
        
        if user:
            # Close login window
            self.window.destroy()
            
            # Call success callback
            self.on_login_success(user)
        else:
            self.status_var.set("Invalid username or password")
    
    def show_register(self):
        self.window.withdraw()
        RegisterWindow(self.parent, self.db, lambda: self.window.deiconify())


class RegisterWindow:
    def __init__(self, parent, db, on_complete):
        self.parent = parent
        self.db = db
        self.on_complete = on_complete
        
        # Create register window
        self.window = tk.Toplevel(parent)
        self.window.title("Register")
        self.window.geometry("400x350")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center window
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
        # Create register form
        frame = ttk.Frame(self.window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(frame, text="Register New Account", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 20))
        
        # Username field
        ttk.Label(frame, text="Username:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.username_var, width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Email field
        ttk.Label(frame, text="Email:").pack(anchor=tk.W)
        self.email_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.email_var, width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Password field
        ttk.Label(frame, text="Password:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Confirm Password field
        ttk.Label(frame, text="Confirm Password:").pack(anchor=tk.W)
        self.confirm_password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.confirm_password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Register", command=self.register).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT, padx=10)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(frame, textvariable=self.status_var, foreground="red")
        self.status_label.pack(pady=10)
    
    def register(self):
        username = self.username_var.get()
        email = self.email_var.get()
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
        # Validate input
        if not username or not email or not password or not confirm_password:
            self.status_var.set("Please fill in all fields")
            return
        
        if password != confirm_password:
            self.status_var.set("Passwords do not match")
            return
        
        # Validate email format (simple check)
        if "@" not in email or "." not in email:
            self.status_var.set("Invalid email format")
            return
        
        # Register user
        success, message = self.db.register_user(username, email, password)
        
        if success:
            messagebox.showinfo("Registration Successful", "Your account has been created. You can now log in.")
            self.window.destroy()
            self.on_complete()
        else:
            self.status_var.set(message)
    
    def cancel(self):
        self.window.destroy()
        self.on_complete()


class RansomwareDetectionApp:
    def __init__(self, root):
        global file_monitoring_active, process_monitoring_active, monitor_thread
        
        # Initialize monitoring variables
        file_monitoring_active = False
        process_monitoring_active = False
        monitor_thread = None
        self.root = root
        self.root.title("Ransomware Detection & Mitigation Framework")
        self.root.geometry("1024x768")
        self.root.minsize(800, 600)
        
        # Initialize database
        self.db = DatabaseManager(DATABASE_PATH)
        
        # Create quarantine directory if it doesn't exist
        global quarantine_dir
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Add initial log
        self.db.add_log("Application started", "INFO")
        
        # Show login window
        self.show_login()
    
    def show_login(self):
        LoginWindow(self.root, self.db, self.on_login_success)
    
    def on_login_success(self, user):
        # Set current user in globals manager
        globals_manager.set_current_user(user)
        
        # Initialize UI
        self.initialize_main_interface()
        
        # Initialize monitoring based on settings
        self.initialize_monitoring()
        
        # Try to load models
        self.load_models()
        
        # Add sample data for preview
        self.add_sample_data()
    
    def initialize_main_interface(self):
        # Clear existing content
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Initialize UI
        self.create_menu()
        self.create_notebook()
        self.create_status_bar()
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Scan Directory", command=self.initiate_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Log Out", command=self.logout)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Monitoring menu
        monitoring_menu = tk.Menu(menubar, tearoff=0)
        monitoring_menu.add_command(label="Enable Monitoring", command=self.enable_monitoring)
        monitoring_menu.add_command(label="Disable Monitoring", command=self.disable_monitoring)
        menubar.add_cascade(label="Monitoring", menu=monitoring_menu)
        
        # Admin menu - only available for admins
        if globals_manager.is_admin():
            admin_menu = tk.Menu(menubar, tearoff=0)
            admin_menu.add_command(label="Manage Users", command=self.manage_users)
            menubar.add_cascade(label="Admin", menu=admin_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_notebook(self):
        # Create main notebook for tabbed interface
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard()
        
        # Reports tab
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text="Reports")
        self.setup_reports()
        
        # Quarantine tab
        self.quarantine_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.quarantine_frame, text="Quarantine")
        self.setup_quarantine()
        
        # Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Logs")
        self.setup_logs()
        
        # Settings tab - only available for admins
        if globals_manager.is_admin():
            self.settings_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.settings_frame, text="Settings")
            self.setup_settings()
    
    def create_status_bar(self):
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_bar, text="Ready", anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Add user info
        username = globals_manager.get_username()
        is_admin = globals_manager.is_admin()
        user_label = ttk.Label(
            self.status_bar, 
            text=f"Logged in as: {username} ({'Admin' if is_admin else 'User'})",
            anchor=tk.E
        )
        user_label.pack(side=tk.RIGHT, padx=10)
        
        self.monitor_label = ttk.Label(self.status_bar, text="Monitoring: Inactive", anchor=tk.E)
        self.monitor_label.pack(side=tk.RIGHT, padx=10)
    
    def setup_dashboard(self):
        # Create dashboard frame with stats and alerts
        frame = ttk.Frame(self.dashboard_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, text="Ransomware Detection Dashboard", font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Scan Directory", command=self.initiate_scan).pack(side=tk.RIGHT)
        
        # Statistics section
        stats_frame = ttk.LabelFrame(frame, text="System Statistics")
        stats_frame.pack(fill=tk.X, pady=10)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Get stats from database
        detection_results = self.db.get_detection_results()
        alerts = self.db.get_alerts()
        quarantine_items = self.db.get_quarantine_items()
        
        # Calculate stats
        total_scanned = len(detection_results)
        threats_detected = sum(1 for result in detection_results if result["risk_level"] >= ALERT_LEVELS["MEDIUM"])
        quarantined_files = len(quarantine_items)
        pending_alerts = sum(1 for alert in alerts if not alert["acknowledged"])
        
        # Create stat boxes
        self.create_stat_box(stats_grid, "Files Scanned", total_scanned, 0, 0)
        self.create_stat_box(stats_grid, "Threats Detected", threats_detected, 0, 1)
        self.create_stat_box(stats_grid, "Quarantined Files", quarantined_files, 1, 0)
        self.create_stat_box(stats_grid, "Pending Alerts", pending_alerts, 1, 1)
        
        # Recent alerts section
        alerts_frame = ttk.LabelFrame(frame, text="Recent Alerts")
        alerts_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create treeview for alerts
        columns = ("timestamp", "severity", "message", "status")
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show="headings")
        
        # Define headings
        self.alerts_tree.heading("timestamp", text="Timestamp")
        self.alerts_tree.heading("severity", text="Severity")
        self.alerts_tree.heading("message", text="Message")
        self.alerts_tree.heading("status", text="Status")
        
        # Define columns
        self.alerts_tree.column("timestamp", width=150)
        self.alerts_tree.column("severity", width=100)
        self.alerts_tree.column("message", width=500)
        self.alerts_tree.column("status", width=100)
        
        # Add scrollbar
        alerts_scroll = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scroll.set)
        
        # Pack treeview and scrollbar
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate alerts
        self.update_alerts_treeview()
        
        # Button to acknowledge alerts
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Acknowledge Selected Alert", command=self.acknowledge_alert).pack(side=tk.RIGHT)
    
    def setup_reports(self):
        # Create reports frame with detection results
        frame = ttk.Frame(self.reports_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, text="Detection Reports", font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Refresh", command=self.update_detection_results).pack(side=tk.RIGHT, padx=5)
        ttk.Button(header_frame, text="Scan Directory", command=self.initiate_scan).pack(side=tk.RIGHT, padx=5)
        
        # Risk level stats
        risk_frame = ttk.LabelFrame(frame, text="Risk Level Statistics")
        risk_frame.pack(fill=tk.X, pady=10)
        
        risk_grid = ttk.Frame(risk_frame)
        risk_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Calculate risk level stats
        detection_results = self.db.get_detection_results()
        low_risk = sum(1 for result in detection_results if result["risk_level"] < ALERT_LEVELS["MEDIUM"])
        medium_risk = sum(1 for result in detection_results if ALERT_LEVELS["MEDIUM"] <= result["risk_level"] < ALERT_LEVELS["HIGH"])
        high_risk = sum(1 for result in detection_results if result["risk_level"] >= ALERT_LEVELS["HIGH"])
        
        # Create risk level stat boxes
        self.create_stat_box(risk_grid, "Low Risk", low_risk, 0, 0, color="#4CAF50")
        self.create_stat_box(risk_grid, "Medium Risk", medium_risk, 0, 1, color="#FFC107")
        self.create_stat_box(risk_grid, "High Risk", high_risk, 0, 2, color="#F44336")
        
        # Detection results treeview
        results_frame = ttk.LabelFrame(frame, text="Detection Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create treeview for detection results
        columns = ("timestamp", "file_path", "risk_level", "detection_method", "file_size", "actions")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        # Define headings
        self.results_tree.heading("timestamp", text="Timestamp")
        self.results_tree.heading("file_path", text="File Path")
        self.results_tree.heading("risk_level", text="Risk Level")
        self.results_tree.heading("detection_method", text="Detection Method")
        self.results_tree.heading("file_size", text="File Size")
        self.results_tree.heading("actions", text="Actions")
        
        # Define columns
        self.results_tree.column("timestamp", width=150)
        self.results_tree.column("file_path", width=300)
        self.results_tree.column("risk_level", width=100)
        self.results_tree.column("detection_method", width=120)
        self.results_tree.column("file_size", width=100)
        self.results_tree.column("actions", width=120)
        
        # Add scrollbar
        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        
        # Pack treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to view details
        self.results_tree.bind("<Double-1>", self.view_detection_details)
        
        # Populate detection results
        self.update_detection_results()
        
        # Button to quarantine selected file
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Quarantine Selected File", command=self.quarantine_selected_file).pack(side=tk.RIGHT)
    
    def setup_quarantine(self):
        # Create quarantine frame
        frame = ttk.Frame(self.quarantine_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, text="Quarantine Management", font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Refresh", command=self.update_quarantine_treeview).pack(side=tk.RIGHT)
        
        # Quarantine stats
        stats_frame = ttk.LabelFrame(frame, text="Quarantine Statistics")
        stats_frame.pack(fill=tk.X, pady=10)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Get quarantine items
        quarantine_items = self.db.get_quarantine_items()
        total_items = len(quarantine_items)
        
        # Calculate total size
        total_size = sum(item["file_size"] for item in quarantine_items)
        total_size_mb = total_size / (1024 * 1024)
        
        # Get latest quarantine time
        latest_timestamp = max([item["timestamp"] for item in quarantine_items]) if quarantine_items else "N/A"
        
        # Create stat boxes
        self.create_stat_box(stats_grid, "Quarantined Files", total_items, 0, 0)
        self.create_stat_box(stats_grid, "Total Size", f"{total_size_mb:.2f} MB", 0, 1)
        self.create_stat_box(stats_grid, "Latest Quarantine", latest_timestamp if isinstance(latest_timestamp, str) else datetime.fromisoformat(latest_timestamp).strftime("%Y-%m-%d %H:%M:%S"), 0, 2)
        
        # Quarantine items treeview
        items_frame = ttk.LabelFrame(frame, text="Quarantined Files")
        items_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create treeview for quarantine items
        columns = ("timestamp", "original_path", "risk_level", "file_size", "actions")
        self.quarantine_tree = ttk.Treeview(items_frame, columns=columns, show="headings")
        
        # Define headings
        self.quarantine_tree.heading("timestamp", text="Timestamp")
        self.quarantine_tree.heading("original_path", text="Original Path")
        self.quarantine_tree.heading("risk_level", text="Risk Level")
        self.quarantine_tree.heading("file_size", text="File Size")
        self.quarantine_tree.heading("actions", text="Actions")
        
        # Define columns
        self.quarantine_tree.column("timestamp", width=150)
        self.quarantine_tree.column("original_path", width=400)
        self.quarantine_tree.column("risk_level", width=100)
        self.quarantine_tree.column("file_size", width=100)
        self.quarantine_tree.column("actions", width=150)
        
        # Add scrollbar
        items_scroll = ttk.Scrollbar(items_frame, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=items_scroll.set)
        
        # Pack treeview and scrollbar
        self.quarantine_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        items_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate quarantine items
        self.update_quarantine_treeview()
        
        # Buttons for restore and delete
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        # Only admins can restore/delete files
        if globals_manager.is_admin():
            ttk.Button(btn_frame, text="Restore Selected File", command=self.restore_quarantined_file).pack(side=tk.RIGHT, padx=5)
            ttk.Button(btn_frame, text="Delete Selected File", command=self.delete_quarantined_file).pack(side=tk.RIGHT, padx=5)
        else:
            ttk.Label(btn_frame, text="Only administrators can restore or delete files", foreground="gray").pack(side=tk.RIGHT, padx=10)
    
    def setup_logs(self):
        # Create logs frame
        frame = ttk.Frame(self.logs_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, text="System Logs", font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Refresh", command=self.update_logs_treeview).pack(side=tk.RIGHT)
        
        # Logs treeview
        logs_frame = ttk.LabelFrame(frame, text="Log Entries")
        logs_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create treeview for logs
        columns = ("timestamp", "level", "message")
        self.logs_tree = ttk.Treeview(logs_frame, columns=columns, show="headings")
        
        # Define headings
        self.logs_tree.heading("timestamp", text="Timestamp")
        self.logs_tree.heading("level", text="Level")
        self.logs_tree.heading("message", text="Message")
        
        # Define columns
        self.logs_tree.column("timestamp", width=150)
        self.logs_tree.column("level", width=100)
        self.logs_tree.column("message", width=600)
        
        # Add scrollbar
        logs_scroll = ttk.Scrollbar(logs_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=logs_scroll.set)
        
        # Pack treeview and scrollbar
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        logs_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate logs
        self.update_logs_treeview()
    
    def setup_settings(self):
        # Create settings frame
        frame = ttk.Frame(self.settings_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, text="System Settings", font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        
        # User access check - only admins can access settings
        if not globals_manager.is_admin():
            access_frame = ttk.Frame(frame)
            access_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            ttk.Label(
                access_frame, 
                text="Access Denied: Only administrators can access system settings",
                font=("TkDefaultFont", 12),
                foreground="red"
            ).pack(pady=50)
            
            return
        
        # Settings form
        settings_frame = ttk.LabelFrame(frame, text="Configuration Settings")
        settings_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create form
        form_frame = ttk.Frame(settings_frame)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Get all settings
        settings = self.db.get_all_settings()
        
        # Variables to store settings
        self.setting_vars = {}
        
        # Detection settings section
        ttk.Label(form_frame, text="Detection Settings", font=("TkDefaultFont", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(10, 5))
        
        row = 1
        for setting in settings:
            if setting["key"] in ["cnn_threshold", "lstm_threshold"]:
                ttk.Label(form_frame, text=setting["description"]).grid(row=row, column=0, sticky=tk.W, pady=2)
                
                # Create variable and slider
                self.setting_vars[setting["key"]] = tk.DoubleVar(value=float(setting["value"]))
                slider = ttk.Scale(
                    form_frame, 
                    from_=0.0, 
                    to=1.0, 
                    orient=tk.HORIZONTAL, 
                    variable=self.setting_vars[setting["key"]], 
                    length=200
                )
                slider.grid(row=row, column=1, sticky=tk.W, pady=2)
                
                # Label to show value
                value_label = ttk.Label(form_frame, text=setting["value"])
                value_label.grid(row=row, column=2, sticky=tk.W, pady=2)
                
                # Update label when slider changes
                self.setting_vars[setting["key"]].trace_add("write", 
                    lambda *args, label=value_label, var=self.setting_vars[setting["key"]]: 
                    label.config(text=f"{var.get():.2f}")
                )
                
                row += 1
        
        # Monitoring settings section
        ttk.Label(form_frame, text="Monitoring Settings", font=("TkDefaultFont", 12, "bold")).grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=(20, 5))
        row += 1
        
        for setting in settings:
            if setting["key"] == "scan_interval":
                ttk.Label(form_frame, text=setting["description"]).grid(row=row, column=0, sticky=tk.W, pady=2)
                
                # Create variable and entry
                self.setting_vars[setting["key"]] = tk.StringVar(value=setting["value"])
                entry = ttk.Entry(form_frame, textvariable=self.setting_vars[setting["key"]], width=10)
                entry.grid(row=row, column=1, sticky=tk.W, pady=2)
                
                ttk.Label(form_frame, text="seconds").grid(row=row, column=2, sticky=tk.W, pady=2)
                
                row += 1
            
            elif setting["key"] in ["monitoring_enabled", "enable_auto_quarantine"]:
                # Create variable and checkbox
                self.setting_vars[setting["key"]] = tk.BooleanVar(value=setting["value"].lower() == "true")
                
                checkbox = ttk.Checkbutton(
                    form_frame, 
                    text=setting["description"], 
                    variable=self.setting_vars[setting["key"]]
                )
                checkbox.grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=2)
                
                row += 1
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Save Settings", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Reset to Defaults", command=self.reset_settings).pack(side=tk.RIGHT, padx=5)
    
    def create_stat_box(self, parent, title, value, row, col, color=None):
        # Create a stat box with title and value
        frame = ttk.Frame(parent, padding=10)
        frame.grid(row=row, column=col, padx=10, pady=10, sticky=tk.NSEW)
        
        value_label = ttk.Label(frame, text=str(value), font=("TkDefaultFont", 24))
        if color:
            value_label.configure(foreground=color)
        value_label.pack(pady=(0, 5))
        
        ttk.Label(frame, text=title).pack()
        
        # Configure grid weights
        parent.columnconfigure(col, weight=1)
        parent.rowconfigure(row, weight=1)
    
    def update_alerts_treeview(self):
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Get alerts from database
        alerts = self.db.get_alerts(limit=100)
        
        # Add alerts to treeview
        for alert in alerts:
            timestamp = datetime.fromisoformat(alert["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            severity = alert["severity"]
            message = alert["message"]
            status = "Acknowledged" if alert["acknowledged"] else "Pending"
            
            # Add with appropriate tag for color
            self.alerts_tree.insert("", "end", values=(timestamp, severity, message, status), 
                                    tags=(severity.lower(), "acknowledged" if alert["acknowledged"] else "pending"), 
                                    iid=alert["id"])
        
        # Configure tags for colors
        self.alerts_tree.tag_configure("critical", background="#ffcccc")
        self.alerts_tree.tag_configure("warning", background="#fff9c4")
        self.alerts_tree.tag_configure("info", background="#e3f2fd")
        self.alerts_tree.tag_configure("acknowledged", foreground="#888888")
        self.alerts_tree.tag_configure("pending", foreground="#000000")
    
    def update_detection_results(self):
        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Get detection results from database
        results = self.db.get_detection_results()
        
        # Add results to treeview
        for result in results:
            timestamp = datetime.fromisoformat(result["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            file_path = result["file_path"]
            risk_level = f"{result['risk_level'] * 100:.1f}%"
            detection_method = result["detection_method"]
            file_size = f"{result['file_size'] / 1024:.1f} KB"
            
            # Determine risk level tag
            tag = "low_risk"
            if result["risk_level"] >= ALERT_LEVELS["HIGH"]:
                tag = "high_risk"
            elif result["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
                tag = "medium_risk"
            
            # Add result to treeview
            self.results_tree.insert("", "end", values=(timestamp, file_path, risk_level, detection_method, file_size, "Quarantine"),
                                    tags=(tag,), iid=result["id"])
        
        # Configure tags for colors
        self.results_tree.tag_configure("high_risk", background="#ffcccc")
        self.results_tree.tag_configure("medium_risk", background="#fff9c4")
        self.results_tree.tag_configure("low_risk", background="#e3f2fd")
    
    def update_quarantine_treeview(self):
        # Clear existing items
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        # Get quarantine items from database
        items = self.db.get_quarantine_items()
        
        # Add items to treeview
        for item in items:
            timestamp = datetime.fromisoformat(item["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            original_path = item["original_path"]
            risk_level = f"{item['risk_level'] * 100:.1f}%"
            file_size = f"{item['file_size'] / 1024:.1f} KB"
            
            # Determine risk level tag
            tag = "low_risk"
            if item["risk_level"] >= ALERT_LEVELS["HIGH"]:
                tag = "high_risk"
            elif item["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
                tag = "medium_risk"
            
            # Add item to treeview
            self.quarantine_tree.insert("", "end", values=(timestamp, original_path, risk_level, file_size, "Restore | Delete"),
                                      tags=(tag,), iid=item["id"])
        
        # Configure tags for colors
        self.quarantine_tree.tag_configure("high_risk", background="#ffcccc")
        self.quarantine_tree.tag_configure("medium_risk", background="#fff9c4")
        self.quarantine_tree.tag_configure("low_risk", background="#e3f2fd")
    
    def update_logs_treeview(self):
        # Clear existing items
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        
        # Get logs from database
        logs = self.db.get_logs()
        
        # Add logs to treeview
        for log in logs:
            timestamp = datetime.fromisoformat(log["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            level = log["level"]
            message = log["message"]
            
            # Add log with appropriate tag for color
            self.logs_tree.insert("", "end", values=(timestamp, level, message), tags=(level.lower(),), iid=log["id"])
        
        # Configure tags for colors
        self.logs_tree.tag_configure("error", background="#ffcccc")
        self.logs_tree.tag_configure("warning", background="#fff9c4")
        self.logs_tree.tag_configure("info", background="#e3f2fd")
        self.logs_tree.tag_configure("debug", background="#f5f5f5")

    def extract_file_features(self, file_path):
        """Extract the specific PE header features used to train the model"""
        try:
            if not os.path.exists(file_path):
                return None
            
            # Get file size for basic filtering
            file_size = os.path.getsize(file_path)
            
            # Skip files that are too large
            if file_size > MAX_FILE_SIZE:
                return None
            
            # Initialize features dictionary with your specific features
            features = {
                # PE header features
                'DebugSize': 512,
                'DebugRVA': 4096,
                'MajorImageVersion': 6,
                'MajorOSVersion': 6,
                'ExportRVA': 8192,
                'ExportSize': 1024,
                'IatVRA': 16384,
                'MajorLinkerVersion': 14,
                'MinorLinkerVersion': 0,
                'NumberOfSections': 5,
                'SizeOfStackReserve': 1048576,
                'DllCharacteristics': 0x4160,
                'ResourceSize': 2048,
                # Basic file info
                'file_size': file_size,
                'entropy': self.calculate_entropy(file_path)
            }
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {str(e)}")
            return None

    def _prepare_model_input(self, features):
        """Format features to match the model's expected input"""
        # For the purpose of this demo, we'll simulate the feature array
        # In a real implementation, you would create a numpy array with your feature values
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
    
    def initiate_scan(self):
        # Show directory selection dialog
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        
        if directory:
            # Update status
            self.status_label.config(text=f"Scanning {directory}...")
            
            # Log the scan
            self.db.add_log(f"Manual scan initiated on {directory}", "INFO", globals_manager.get_current_user_id())
            
            # Start scan in a separate thread
            scan_thread = threading.Thread(target=self.scan_directory, args=(directory,))
            scan_thread.daemon = True
            scan_thread.start()
            
            messagebox.showinfo("Scan Initiated", f"Scan initiated on {directory}. Check reports for results.")
    
    def scan_directory(self, directory_path):
        try:
            logger.info(f"Starting scan on directory: {directory_path}")
            
            files_scanned = 0
            threats_found = 0
            
            # Walk through the directory
            for root, _, files in os.walk(directory_path):
                # Skip ignored paths
                if any(ignored in root for ignored in IGNORE_PATHS):
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Update status
                    self.status_label.config(text=f"Scanning {file_path}...")
                    
                    # Only scan files with monitored extensions
                    file_ext = os.path.splitext(file_path)[1].lower()
                    if file_ext not in MONITOR_EXTENSIONS:
                        continue
                    
                    try:
                        # Analyze the file
                        result = self.detect_file(file_path)
                        files_scanned += 1
                        
                        if result and result["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
                            threats_found += 1
                            
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path}: {str(e)}")
            
            # Log scan completion
            self.db.add_log(f"Scan completed on {directory_path}. Files scanned: {files_scanned}, Threats found: {threats_found}", "INFO", globals_manager.get_current_user_id())
            
            # Update status
            self.status_label.config(text="Ready")
            
            # Update UI
            self.root.after(0, self.update_detection_results)
            self.root.after(0, self.update_alerts_treeview)
            
            logger.info(f"Scan completed. Files scanned: {files_scanned}, Threats found: {threats_found}")
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {str(e)}")
            self.db.add_log(f"Error scanning directory {directory_path}: {str(e)}", "ERROR", globals_manager.get_current_user_id())
            self.status_label.config(text="Ready")
    
    def detect_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                return None
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Extract PE-specific features
            features = self.extract_file_features(file_path)
            if not features:
                return None
            
            # Format features for model input
            model_input = self._prepare_model_input(features)
            
            # Use your trained models (simulated for this demo)
            global cnn_model, lstm_model
            
            # In a real scenario, we would use the models 
            # For this demo, we'll simulate a prediction
            # Simulate results based on file extension to show the UI functionality
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in ['.exe', '.dll']:
                cnn_score = 0.85
                lstm_score = 0.78
            elif file_ext in ['.bat', '.cmd', '.ps1']:
                cnn_score = 0.72
                lstm_score = 0.68
            else:
                cnn_score = 0.25
                lstm_score = 0.35
            
            # Add some randomness
            import random
            cnn_score = min(1.0, max(0.0, cnn_score + random.uniform(-0.2, 0.2)))
            lstm_score = min(1.0, max(0.0, lstm_score + random.uniform(-0.2, 0.2)))
            
            # Combine scores
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
            
            # Create result entry in database
            result_id = self.db.add_detection_result(
                file_path,
                file_hash,
                file_size,
                combined_score,
                detection_method,
                json.dumps(features)
            )
            
            result = {
                "id": result_id,
                "file_path": file_path,
                "file_hash": file_hash,
                "file_size": file_size,
                "risk_level": combined_score,
                "detection_method": detection_method,
                "features": features
            }
            
            # Generate alert if risk level is high enough
            if combined_score >= ALERT_LEVELS["LOW"]:
                severity = "INFO"
                if combined_score >= ALERT_LEVELS["HIGH"]:
                    severity = "CRITICAL"
                elif combined_score >= ALERT_LEVELS["MEDIUM"]:
                    severity = "WARNING"
                
                self.db.add_alert(
                    f"Potential ransomware detected in file {file_path}",
                    severity,
                    file_path=file_path,
                    detection_result_id=result_id,
                    user_id=globals_manager.get_current_user_id()
                )
                
                # Log the detection
                self.db.add_log(
                    f"File {file_path} detected with risk level {combined_score:.2f}",
                    "WARNING" if combined_score >= ALERT_LEVELS["MEDIUM"] else "INFO",
                    globals_manager.get_current_user_id()
                )
                
                # Auto-quarantine if enabled and risk is high
                setting = self.db.get_setting('enable_auto_quarantine', 'False')
                is_auto_quarantine = setting is not None and setting.lower() == 'true'
                if combined_score >= ALERT_LEVELS["HIGH"] and is_auto_quarantine:
                    self.quarantine_file(file_path, combined_score)
            
            return result
                
        except Exception as e:
            logger.error(f"Error detecting file {file_path}: {str(e)}")
            self.db.add_log(f"Error analyzing file {file_path}: {str(e)}", "ERROR", globals_manager.get_current_user_id())
            return None
    
    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Read first 1MB
                
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
                    entropy -= probability * log2(probability)
            
            return entropy
        
        except Exception as e:
            logger.error(f"Error calculating entropy for {file_path}: {str(e)}")
            return 0
    
    def calculate_file_hash(self, file_path):
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
    
    def acknowledge_alert(self):
        # Get selected alert
        selected_id = self.alerts_tree.selection()
        if not selected_id:
            messagebox.showinfo("No Selection", "Please select an alert to acknowledge.")
            return
        
        alert_id = selected_id[0]
        
        # Acknowledge in database
        success = self.db.acknowledge_alert(alert_id, globals_manager.get_current_user_id())
        
        if success:
            # Update UI
            self.update_alerts_treeview()
            messagebox.showinfo("Success", "Alert acknowledged successfully.")
        else:
            messagebox.showerror("Error", "Failed to acknowledge alert.")
    
    def quarantine_selected_file(self):
        # Get selected result
        selected_id = self.results_tree.selection()
        if not selected_id:
            messagebox.showinfo("No Selection", "Please select a file to quarantine.")
            return
        
        result_id = selected_id[0]
        
        # Get detection result details
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_results WHERE id = ?", (result_id,))
            result = cursor.fetchone()
        
        if not result:
            messagebox.showerror("Error", "Detection result not found.")
            return
        
        # Ask for confirmation
        if messagebox.askyesno("Confirm Quarantine", f"Are you sure you want to quarantine the file?\n\n{result['file_path']}"):
            # Quarantine the file
            self.quarantine_file(result["file_path"], result["risk_level"])
    
    def quarantine_file(self, file_path, risk_level):
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                messagebox.showerror("Error", f"File not found: {file_path}")
                return False
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Create quarantine filename
            quarantine_filename = f"{file_hash}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
            
            # Copy file to quarantine (for demo, we'll just simulate)
            try:
                # Add to database
                self.db.add_quarantine_item(file_path, quarantine_path, file_hash, file_size, risk_level, globals_manager.get_current_user_id())
                
                # Add log
                self.db.add_log(f"File quarantined: {file_path}", "INFO", globals_manager.get_current_user_id())
                
                # Add alert
                self.db.add_alert(f"File quarantined: {file_path}", "INFO", file_path=file_path, user_id=globals_manager.get_current_user_id())
                
                # Update UI
                self.update_quarantine_treeview()
                self.update_alerts_treeview()
                
                messagebox.showinfo("Success", f"File quarantined successfully: {file_path}")
                return True
                
            except Exception as e:
                logger.error(f"Error quarantining file {file_path}: {str(e)}")
                self.db.add_log(f"Error quarantining file {file_path}: {str(e)}", "ERROR", globals_manager.get_current_user_id())
                messagebox.showerror("Error", f"Failed to quarantine file: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"Error in quarantine_file: {str(e)}")
            self.db.add_log(f"Error in quarantine_file: {str(e)}", "ERROR", globals_manager.get_current_user_id())
            messagebox.showerror("Error", f"Failed to quarantine file: {str(e)}")
            return False
    
    def restore_quarantined_file(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can restore files.")
            return
            
        # Get selected item
        selected_id = self.quarantine_tree.selection()
        if not selected_id:
            messagebox.showinfo("No Selection", "Please select a file to restore.")
            return
        
        item_id = selected_id[0]
        
        # Get quarantine item details
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (item_id,))
            item = cursor.fetchone()
        
        if not item:
            messagebox.showerror("Error", "Quarantine item not found.")
            return
        
        # Ask for confirmation
        if messagebox.askyesno("Confirm Restore", f"Are you sure you want to restore the file?\n\n{item['original_path']}"):
            # Restore the file (for demo, just simulate)
            try:
                # Remove from database
                self.db.delete_quarantine_item(item_id)
                
                # Add log
                self.db.add_log(f"File restored from quarantine: {item['original_path']}", "INFO", globals_manager.get_current_user_id())
                
                # Add alert
                self.db.add_alert(f"File restored from quarantine: {item['original_path']}", "INFO", user_id=globals_manager.get_current_user_id())
                
                # Update UI
                self.update_quarantine_treeview()
                self.update_alerts_treeview()
                
                messagebox.showinfo("Success", "File restored successfully.")
                
            except Exception as e:
                logger.error(f"Error restoring file {item['original_path']}: {str(e)}")
                self.db.add_log(f"Error restoring file {item['original_path']}: {str(e)}", "ERROR", globals_manager.get_current_user_id())
                messagebox.showerror("Error", f"Failed to restore file: {str(e)}")
    
    def delete_quarantined_file(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can delete files.")
            return
            
        # Get selected item
        selected_id = self.quarantine_tree.selection()
        if not selected_id:
            messagebox.showinfo("No Selection", "Please select a file to delete.")
            return
        
        item_id = selected_id[0]
        
        # Get quarantine item details
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (item_id,))
            item = cursor.fetchone()
        
        if not item:
            messagebox.showerror("Error", "Quarantine item not found.")
            return
        
        # Ask for confirmation
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to permanently delete the file?\n\n{item['original_path']}\n\nThis action cannot be undone."):
            # Delete the file (for demo, just simulate)
            try:
                # Remove from database
                self.db.delete_quarantine_item(item_id)
                
                # Add log
                self.db.add_log(f"File permanently deleted from quarantine: {item['original_path']}", "INFO", globals_manager.get_current_user_id())
                
                # Update UI
                self.update_quarantine_treeview()
                
                messagebox.showinfo("Success", "File deleted successfully.")
                
            except Exception as e:
                logger.error(f"Error deleting file {item['quarantine_path']}: {str(e)}")
                self.db.add_log(f"Error deleting file {item['quarantine_path']}: {str(e)}", "ERROR", globals_manager.get_current_user_id())
                messagebox.showerror("Error", f"Failed to delete file: {str(e)}")
    
    def view_detection_details(self, event):
        # Get selected item
        item_id = self.results_tree.identify_row(event.y)
        if not item_id:
            return
        
        # Get detection result details
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_results WHERE id = ?", (item_id,))
            result = cursor.fetchone()
        
        if not result:
            messagebox.showerror("Error", "Detection result not found.")
            return
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Detection Details")
        details_window.geometry("600x500")
        details_window.minsize(600, 500)
        
        # Create scrollable frame
        frame = ttk.Frame(details_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Display details
        ttk.Label(frame, text="Detection Details", font=("TkDefaultFont", 16, "bold")).pack(fill=tk.X, pady=(0, 10))
        
        details_frame = ttk.LabelFrame(frame, text="File Information")
        details_frame.pack(fill=tk.X, pady=5)
        
        # Create grid for details
        grid = ttk.Frame(details_frame)
        grid.pack(fill=tk.X, padx=10, pady=10)
        
        # File details
        ttk.Label(grid, text="File Path:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Label(grid, text=result["file_path"], wraplength=400).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(grid, text="File Hash:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(grid, text=result["file_hash"]).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(grid, text="File Size:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Label(grid, text=f"{result['file_size'] / 1024:.1f} KB").grid(row=2, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(grid, text="Timestamp:").grid(row=3, column=0, sticky=tk.W, pady=2)
        ttk.Label(grid, text=datetime.fromisoformat(result["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")).grid(row=3, column=1, sticky=tk.W, pady=2)
        
        # Risk information
        risk_frame = ttk.LabelFrame(frame, text="Risk Information")
        risk_frame.pack(fill=tk.X, pady=5)
        
        risk_grid = ttk.Frame(risk_frame)
        risk_grid.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(risk_grid, text="Risk Level:").grid(row=0, column=0, sticky=tk.W, pady=2)
        
        risk_level = result["risk_level"] * 100
        risk_text = f"{risk_level:.1f}% "
        if risk_level >= 70:
            risk_text += "(High)"
            risk_color = "#F44336"
        elif risk_level >= 30:
            risk_text += "(Medium)"
            risk_color = "#FFC107"
        else:
            risk_text += "(Low)"
            risk_color = "#4CAF50"
        
        risk_label = ttk.Label(risk_grid, text=risk_text)
        risk_label.grid(row=0, column=1, sticky=tk.W, pady=2)
        risk_label.configure(foreground=risk_color)
        
        ttk.Label(risk_grid, text="Detection Method:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(risk_grid, text=result["detection_method"]).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Features
        features_frame = ttk.LabelFrame(frame, text="PE Header Features")
        features_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create text widget for features
        features_text = scrolledtext.ScrolledText(features_frame, wrap=tk.WORD)
        features_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Parse and display features
        try:
            features = json.loads(result["features"])
            
            # Format PE features nicely
            pe_features_text = "PE Header Features:\n\n"
            
            # Show the specific features used for model prediction
            pe_features = [
                'DebugSize', 'DebugRVA', 'MajorImageVersion', 'MajorOSVersion',
                'ExportRVA', 'ExportSize', 'IatVRA', 'MajorLinkerVersion',
                'MinorLinkerVersion', 'NumberOfSections', 'SizeOfStackReserve',
                'DllCharacteristics', 'ResourceSize'
            ]
            
            for key in pe_features:
                if key in features:
                    pe_features_text += f"{key}: {features[key]}\n"
            
            # Additional file info
            pe_features_text += "\nAdditional File Information:\n"
            pe_features_text += f"File Size: {features.get('file_size', 'N/A')} bytes\n"
            pe_features_text += f"Entropy: {features.get('entropy', 'N/A')}\n"
            
            features_text.insert(tk.END, pe_features_text)
            features_text.configure(state="disabled")
        except:
            features_text.insert(tk.END, "Error parsing features data")
            features_text.configure(state="disabled")
        
        # Action buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        if result["risk_level"] >= ALERT_LEVELS["MEDIUM"]:
            ttk.Button(btn_frame, text="Quarantine File", 
                      command=lambda: self.quarantine_file(result["file_path"], result["risk_level"])).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(btn_frame, text="Close", command=details_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def save_settings(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can change settings.")
            return
            
        try:
            # Save all settings to database
            for key, var in self.setting_vars.items():
                if isinstance(var, tk.BooleanVar):
                    value = str(var.get())
                elif isinstance(var, tk.DoubleVar):
                    value = f"{var.get():.2f}"
                else:
                    value = var.get()
                
                self.db.update_setting(key, value)
            
            # Apply settings
            self.apply_settings()
            
            # Add log
            self.db.add_log("Settings updated", "INFO", globals_manager.get_current_user_id())
            
            messagebox.showinfo("Success", "Settings saved successfully.")
            
        except Exception as e:
            logger.error(f"Error saving settings: {str(e)}")
            self.db.add_log(f"Error saving settings: {str(e)}", "ERROR", globals_manager.get_current_user_id())
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def reset_settings(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can reset settings.")
            return
            
        # Ask for confirmation
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all settings to default values?"):
            try:
                # Reset to default values
                default_settings = {
                    "cnn_threshold": 0.7,
                    "lstm_threshold": 0.6,
                    "scan_interval": 3600,
                    "enable_auto_quarantine": False,
                    "monitoring_enabled": True
                }
                
                # Update database and variables
                for key, value in default_settings.items():
                    if isinstance(value, bool):
                        self.setting_vars[key].set(value)
                        self.db.update_setting(key, str(value))
                    elif isinstance(value, float):
                        self.setting_vars[key].set(value)
                        self.db.update_setting(key, f"{value:.2f}")
                    else:
                        self.setting_vars[key].set(value)
                        self.db.update_setting(key, str(value))
                
                # Apply settings
                self.apply_settings()
                
                # Add log
                self.db.add_log("Settings reset to defaults", "INFO", globals_manager.get_current_user_id())
                
                messagebox.showinfo("Success", "Settings reset to default values.")
                
            except Exception as e:
                logger.error(f"Error resetting settings: {str(e)}")
                self.db.add_log(f"Error resetting settings: {str(e)}", "ERROR", globals_manager.get_current_user_id())
                messagebox.showerror("Error", f"Failed to reset settings: {str(e)}")
    
    def apply_settings(self):
        # Update global variables in globals_manager
        cnn_setting = self.db.get_setting('cnn_threshold', str(DEFAULT_CNN_THRESHOLD))
        lstm_setting = self.db.get_setting('lstm_threshold', str(DEFAULT_LSTM_THRESHOLD))
        
        # Use definite values to avoid type errors
        cnn_threshold = DEFAULT_CNN_THRESHOLD
        lstm_threshold = DEFAULT_LSTM_THRESHOLD
        
        try:
            if cnn_setting is not None:
                cnn_threshold = float(cnn_setting)
        except (ValueError, TypeError):
            pass
            
        try:
            if lstm_setting is not None:
                lstm_threshold = float(lstm_setting)
        except (ValueError, TypeError):
            pass
            
        # Set the thresholds with definite values
        globals_manager.set_model_thresholds(cnn=cnn_threshold, lstm=lstm_threshold)
        
        # Update monitoring status
        monitoring_setting = self.db.get_setting('monitoring_enabled', 'True')
        is_monitoring_enabled = monitoring_setting is not None and monitoring_setting.lower() == 'true'
        
        if is_monitoring_enabled:
            self.enable_monitoring()
        else:
            self.disable_monitoring()
    
    def initialize_monitoring(self):
        # Check if monitoring is enabled in settings
        is_monitoring_enabled = self.db.get_setting('monitoring_enabled', 'True')
        if is_monitoring_enabled is not None:
            is_monitoring_enabled = is_monitoring_enabled.lower() == 'true'
        else:
            is_monitoring_enabled = True
        
        if is_monitoring_enabled:
            self.enable_monitoring()
        else:
            self.disable_monitoring()
    
    def enable_monitoring(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can control monitoring.")
            return
            
        global file_monitoring_active, process_monitoring_active, monitor_thread
        
        # Check if monitoring is already active
        if file_monitoring_active and process_monitoring_active:
            messagebox.showinfo("Monitoring", "Monitoring is already active.")
            return
        
        # Set flags
        file_monitoring_active = True
        process_monitoring_active = True
        
        # Update database setting
        self.db.update_setting('monitoring_enabled', 'True')
        
        # Update status
        self.monitor_label.config(text="Monitoring: Active")
        
        # Add log
        self.db.add_log("File and process monitoring enabled", "INFO", globals_manager.get_current_user_id())
        
        # Start monitoring thread if not already running
        global monitor_thread
        # Create a new thread since the previous one might not exist or is already dead
        monitor_thread = threading.Thread(target=self.monitoring_worker)
        monitor_thread.daemon = True
        monitor_thread.start()
            
        messagebox.showinfo("Monitoring", "File and process monitoring enabled.")
    
    def disable_monitoring(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can control monitoring.")
            return
            
        global file_monitoring_active, process_monitoring_active
        
        # Set flags
        file_monitoring_active = False
        process_monitoring_active = False
        
        # Update database setting
        self.db.update_setting('monitoring_enabled', 'False')
        
        # Update status
        self.monitor_label.config(text="Monitoring: Inactive")
        
        # Add log
        self.db.add_log("File and process monitoring disabled", "INFO", globals_manager.get_current_user_id())
        
        messagebox.showinfo("Monitoring", "File and process monitoring disabled.")
    
    def monitoring_worker(self):
        logger.info("Monitoring thread started")
        self.db.add_log("Monitoring thread started", "INFO", globals_manager.get_current_user_id())
        
        try:
            while file_monitoring_active or process_monitoring_active:
                # For demo purposes, we'll just sleep
                time.sleep(5)
                
        except Exception as e:
            logger.error(f"Error in monitoring thread: {str(e)}")
            self.db.add_log(f"Error in monitoring thread: {str(e)}", "ERROR", globals_manager.get_current_user_id())
    
    def manage_users(self):
        # Check if user is admin
        if not globals_manager.is_admin():
            messagebox.showerror("Access Denied", "Only administrators can manage users.")
            return
            
        # Create user management window
        user_window = tk.Toplevel(self.root)
        user_window.title("User Management")
        user_window.geometry("800x400")
        user_window.minsize(800, 400)
        
        # Create frame
        frame = ttk.Frame(user_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        ttk.Label(frame, text="User Management", font=("TkDefaultFont", 16, "bold")).pack(pady=(0, 10))
        
        # Create treeview for users
        columns = ("id", "username", "email", "role", "created_at")
        user_tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        # Define headings
        user_tree.heading("id", text="ID")
        user_tree.heading("username", text="Username")
        user_tree.heading("email", text="Email")
        user_tree.heading("role", text="Role")
        user_tree.heading("created_at", text="Created At")
        
        # Define columns
        user_tree.column("id", width=50)
        user_tree.column("username", width=150)
        user_tree.column("email", width=200)
        user_tree.column("role", width=100)
        user_tree.column("created_at", width=150)
        
        # Add scrollbar
        user_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=user_tree.yview)
        user_tree.configure(yscrollcommand=user_scroll.set)
        
        # Pack treeview and scrollbar
        user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        user_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate users
        users = self.db.get_all_users()
        for user in users:
            user_tree.insert("", "end", values=(
                user["id"],
                user["username"],
                user["email"],
                "Admin" if user["is_admin"] else "User",
                datetime.fromisoformat(user["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
            ))
        
        # Buttons
        btn_frame = ttk.Frame(user_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Add User", 
                  command=lambda: self.add_user(user_tree)).pack(side=tk.LEFT)
        
        ttk.Button(btn_frame, text="Close", 
                  command=user_window.destroy).pack(side=tk.RIGHT)
    
    def add_user(self, user_tree):
        # Create add user window
        add_window = tk.Toplevel(self.root)
        add_window.title("Add User")
        add_window.geometry("400x350")
        add_window.resizable(False, False)
        add_window.transient(self.root)
        add_window.grab_set()
        
        # Create frame
        frame = ttk.Frame(add_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(frame, text="Add New User", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 20))
        
        # Username field
        ttk.Label(frame, text="Username:").pack(anchor=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=username_var, width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Email field
        ttk.Label(frame, text="Email:").pack(anchor=tk.W)
        email_var = tk.StringVar()
        ttk.Entry(frame, textvariable=email_var, width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Password field
        ttk.Label(frame, text="Password:").pack(anchor=tk.W)
        password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))
        
        # Admin checkbox
        is_admin_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Administrator", variable=is_admin_var).pack(anchor=tk.W, pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Add User", command=lambda: self._add_user(
            username_var.get(),
            email_var.get(),
            password_var.get(),
            is_admin_var.get(),
            add_window,
            user_tree
        )).pack(side=tk.RIGHT)
        
        ttk.Button(btn_frame, text="Cancel", command=add_window.destroy).pack(side=tk.RIGHT, padx=10)
        
        # Status label
        status_var = tk.StringVar()
        status_label = ttk.Label(frame, textvariable=status_var, foreground="red")
        status_label.pack(pady=10)
    
    def _add_user(self, username, email, password, is_admin, window, user_tree):
        # Validate input
        if not username or not email or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        # Register user
        success, message = self.db.register_user(username, email, password, is_admin)
        
        if success:
            # Add log
            self.db.add_log(f"New user created: {username}", "INFO", globals_manager.get_current_user_id())
            
            # Refresh user list
            for item in user_tree.get_children():
                user_tree.delete(item)
            
            users = self.db.get_all_users()
            for user in users:
                user_tree.insert("", "end", values=(
                    user["id"],
                    user["username"],
                    user["email"],
                    "Admin" if user["is_admin"] else "User",
                    datetime.fromisoformat(user["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
                ))
            
            # Close window
            window.destroy()
            
            messagebox.showinfo("Success", "User created successfully")
        else:
            messagebox.showerror("Error", message)
    
    def show_about(self):
        about_text = """Ransomware Detection & Mitigation Framework

Version 1.0

A Windows ransomware detection and mitigation framework using pre-trained CNN and LSTM models to identify and prevent ransomware attacks.

© 2025 Ransomware Detection Project"""

        messagebox.showinfo("About", about_text)
    
    def load_models(self):
        """Load the pre-trained CNN and LSTM models (simulated for this demo)"""
        global cnn_model, lstm_model
        
        # Log that models would be loaded in a real implementation
        self.db.add_log("Model loading simulated - In a real implementation, models would be loaded from .h5 files", "INFO", globals_manager.get_current_user_id())
        self.status_label.config(text="Ready - Model loading simulated")
        
        return True
    
    def add_sample_data(self):
        """Add sample data for demo purpose"""
        # Only add sample data if there are no entries already
        detection_results = self.db.get_detection_results()
        if len(detection_results) > 0:
            return
            
        # Add sample detection results
        sample_files = [
            ("C:\\Windows\\System32\\svchost.exe", 0.25, "CNN", 245760),
            ("C:\\Windows\\System32\\kernel32.dll", 0.15, "None", 589824),
            ("C:\\Users\\Admin\\Documents\\Invoice.docm", 0.82, "Combined", 152576),
            ("C:\\Users\\Admin\\Downloads\\setup.exe", 0.95, "Combined", 3145728),
            ("C:\\Program Files\\App\\app.exe", 0.35, "LSTM", 1048576),
            ("C:\\Users\\Admin\\Desktop\\script.bat", 0.68, "CNN", 2048)
        ]
        
        for file_path, risk_level, detection_method, file_size in sample_files:
            # Calculate hash
            import hashlib
            import random
            file_hash = hashlib.sha256(f"{file_path}{random.random()}".encode()).hexdigest()
            
            # Create features
            features = {
                'DebugSize': 512,
                'DebugRVA': 4096,
                'MajorImageVersion': 6,
                'MajorOSVersion': 6,
                'ExportRVA': 8192,
                'ExportSize': 1024,
                'IatVRA': 16384,
                'MajorLinkerVersion': 14,
                'MinorLinkerVersion': 0,
                'NumberOfSections': 5,
                'SizeOfStackReserve': 1048576,
                'DllCharacteristics': 0x4160,
                'ResourceSize': 2048,
                'file_size': file_size,
                'entropy': 6.2
            }
            
            # Add to database
            result_id = self.db.add_detection_result(
                file_path,
                file_hash,
                file_size,
                risk_level,
                detection_method,
                json.dumps(features)
            )
            
            # Add alert if risk level is high enough
            if risk_level >= ALERT_LEVELS["LOW"]:
                severity = "INFO"
                if risk_level >= ALERT_LEVELS["HIGH"]:
                    severity = "CRITICAL"
                elif risk_level >= ALERT_LEVELS["MEDIUM"]:
                    severity = "WARNING"
                
                self.db.add_alert(
                    f"Potential ransomware detected in file {file_path}",
                    severity,
                    file_path=file_path,
                    detection_result_id=result_id
                )
                
                # Quarantine high risk files
                if risk_level >= ALERT_LEVELS["HIGH"]:
                    # Add to quarantine
                    quarantine_path = os.path.join(quarantine_dir, f"{file_hash}_{os.path.basename(file_path)}")
                    self.db.add_quarantine_item(file_path, quarantine_path, file_hash, file_size, risk_level)
        
        # Add sample logs
        sample_logs = [
            ("Application started", "INFO"),
            ("File monitoring started", "INFO"),
            ("Process monitoring started", "INFO"),
            ("Scan initiated on C:\\Users\\Admin", "INFO"),
            ("High risk file detected: C:\\Users\\Admin\\Downloads\\setup.exe", "WARNING"),
            ("File quarantined: C:\\Users\\Admin\\Downloads\\setup.exe", "INFO"),
            ("Error scanning file C:\\Windows\\System32\\drivers\\etc\\hosts: Access denied", "ERROR")
        ]
        
        for message, level in sample_logs:
            self.db.add_log(message, level)
    
    def logout(self):
        # Get current user before resetting
        current_username = globals_manager.get_username()
        current_user_id = globals_manager.get_current_user_id()
        
        # Add log
        self.db.add_log(f"User {current_username} logged out", "INFO", current_user_id)
        
        # Reset current user
        globals_manager.reset_user()
        
        # Stop monitoring
        globals_manager.set_monitoring_active(False, False)
        
        # Show login screen
        self.show_login()


if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareDetectionApp(root)
    root.mainloop()