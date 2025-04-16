from flask import render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Import app and db from app.py
from app import app, db

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Import models after initializing db to avoid circular imports
# Import models
from dbmodels import User, Alert, DetectionResult, QuarantineItem, Log, Setting

with app.app_context():
    # Create tables if they don't exist
    db.create_all()
    
    # Create admin user if no users exist
    if not User.query.first():
        admin = User(
            username="admin",
            email="admin@example.com",
            password_hash=generate_password_hash("admin123"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent alerts
    alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', alerts=alerts)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)