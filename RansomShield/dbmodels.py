from flask_sqlalchemy import SQLAlchemy

# Import db as a global variable
from app import db
from flask_login import UserMixin
from datetime import datetime
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    alerts = db.relationship('Alert', backref='user', lazy=True)
    logs = db.relationship('Log', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH
    file_path = db.Column(db.String(255))
    process_name = db.Column(db.String(100))
    acknowledged = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    detection_result_id = db.Column(db.Integer, db.ForeignKey('detection_result.id'))
    
    def __repr__(self):
        return f'<Alert {self.severity}: {self.message[:30]}...>'

class DetectionResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer)
    risk_level = db.Column(db.Float)
    detection_method = db.Column(db.String(50))  # CNN, LSTM, HEURISTIC
    features = db.Column(db.Text)  # JSON string of extracted features
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    alerts = db.relationship('Alert', backref='detection_result', lazy=True)
    
    def set_features(self, features_dict):
        self.features = json.dumps(features_dict)
    
    def get_features(self):
        return json.loads(self.features) if self.features else {}
    
    def __repr__(self):
        return f'<DetectionResult {self.file_path}: {self.risk_level}>'

class QuarantineItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_path = db.Column(db.String(255), nullable=False)
    quarantine_path = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer)
    risk_level = db.Column(db.Float)
    quarantined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<QuarantineItem {self.original_path}>'

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20), nullable=False)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Log {self.level}: {self.message[:30]}...>'

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f'<Setting {self.key}: {self.value[:30]}...>'