# Ransomware Detection & Mitigation Framework

A Windows-based ransomware detection and mitigation framework leveraging advanced machine learning techniques with CNN and LSTM models for comprehensive threat analysis.

## Key Features

- **ML-based Detection**: Pre-trained machine learning models for intelligent threat detection
- **Comprehensive Monitoring**: Multi-layered monitoring of files, processes, and network traffic
- **Modern User Interface**: Responsive PyQt6-based graphical user interface with modern design
- **Robust Alert System**: Configurable alert thresholds with sound notifications
- **Secure Database**: SQLite database for secure alert and detection result tracking
- **User Management**: Dual user and admin interface with granular access controls
- **Protection Tools**: Enhanced quarantine and file management capabilities
- **Network Monitoring**: Detection of ransomware-related network communications

## System Architecture

The framework is designed with a modular architecture consisting of several key components:

1. **Detection Engine**: Analyzes files and processes using advanced ML models
2. **Monitoring System**: Watches file system, processes, and network for suspicious activities
3. **Alert System**: Notifies users of potential threats with configurable severity levels
4. **Quarantine System**: Safely isolates and manages suspicious files
5. **Backup System**: Provides recovery options for quarantined or removed files
6. **User Interface**: Modern desktop application with intuitive controls

## Usage

The application can be run with either the PyQt6 or Tkinter interface:

- **PyQt6 Interface**: Run `run_pyqt.bat` (Windows) or `run_pyqt.sh` (Linux)
- **Tkinter Interface**: Run `run_app.bat` (Windows) or `run_app.sh` (Linux)

## System Requirements

- Windows 7/10/11 (64-bit recommended)
- Python 3.9 or higher
- Required Python packages:
  - PyQt6 (for the modern UI)
  - TensorFlow
  - NumPy
  - watchdog
  - psutil
  - pefile
  - scapy
  - requests

## Network Monitoring

The framework monitors network traffic to detect communication with known malicious domains and IP addresses associated with ransomware. It tracks:

- Connections to known malicious IPs
- DNS queries to known malicious domains
- Abnormal network connection patterns
- Unusual network traffic volume
- Possible command and control (C&C) communication

## Development

The project includes UML diagrams for:
- Use Case Diagram
- Data Flow Diagram (DFD)
- Context Diagram (CD)
- Sequence Diagram

These diagrams can be found in the `attached_assets` folder.