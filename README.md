# Web Network Scanner

A comprehensive web-based network scanning tool that provides port scanning and packet sniffing capabilities through an intuitive web interface. Built with Python, Flask, and Scapy, this tool offers a powerful combination of network analysis features with a user-friendly web interface.


## 🚀 Features

- **Port Scanner**: Fast multi-threaded port scanning with customizable parameters
- **Packet Sniffer**: Real-time network traffic capture and analysis using Scapy
- **Web Interface**: Modern, responsive web UI built with Bootstrap
- **REST API**: RESTful API endpoints for programmatic access
- **Export Functionality**: Export scan results and packet captures to JSON/CSV
- **Real-time Updates**: Live updates during packet capture sessions
- **Network Discovery**: CIDR network range scanning support
- **Service Detection**: Automatic service identification for open ports

## 📋 Requirements

### System Requirements
- Python 3.7 or higher
- Administrator/root privileges (recommended for packet sniffing)
- Modern web browser with JavaScript enabled

### Network Requirements
- Network interface access for packet sniffing
- Appropriate firewall configurations

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd web-network-scanner
```

### 2. Create Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Verify Installation
```bash
python app.py --version
```

## 🎮 Usage

### Basic Usage
```bash
# Run with default settings (localhost:5000)
python app.py

# Run on all interfaces
python app.py --host 0.0.0.0 --port 8080

# Enable debug mode
python app.py --debug
```

### Command Line Options
```
usage: app.py [-h] [--host HOST] [--port PORT] [--debug] [--version]

Web Network Scanner - Port Scanner and Packet Sniffer

options:
  -h, --help   show this help message and exit
  --host HOST  Host to bind the server to (default: 127.0.0.1)
  --port PORT  Port to bind the server to (default: 5000)
  --debug      Enable debug mode
  --version    show program's version number and exit
```

### Access the Web Interface
1. Start the application: `python app.py`
2. Open your browser and navigate to: `http://127.0.0.1:5000`
3. Use the web interface to configure and run scans

## 🌐 Web Interface Guide

### Dashboard
- Overview of system information
- Recent scan history
- Quick access to tools

### Port Scanner
- Scan single hosts or CIDR ranges
- Select specific ports or use predefined ranges
- Adjust timeout and thread settings
- View real-time scan results
- Export scan results to JSON/CSV

### Packet Sniffer
- Capture network traffic on any interface
- Apply BPF filters to capture specific traffic
- Real-time protocol and service statistics
- Export packet captures to JSON/CSV
- Monitor HTTP, HTTPS, DNS, and other common protocols

## 🚛 API Reference

### Port Scanner Endpoints

#### Scan Ports

curl -X POST http://localhost:5000/api/scan/port
   -H "Content-Type: application/json"

   -d '{
      "target": "192.168.1.1",        # Single IP or CIDR range (192.168.1.0/24)
      "ports": [80, 443, 22],         # Specific ports list
      "ports": "common",              # Or use common ports
      "ports": "1-1000",             # Or port range
      "timeout": 1.0,                # Seconds per port
      "threads": 100                 # Max concurrent threads
   }'

Response 200 OK:
{
    "scan_id": "20250919_123456",
    "target": "192.168.1.1",
    "results": [
        {
            "host": "192.168.1.1",
            "open_ports": [
                {"port": 80, "service": "HTTP"},
                {"port": 443, "service": "HTTPS"}
            ],
            "scan_time": "1.5s"
        }
    ]
}
```

### Packet Sniffer Endpoints

#### Start Capture
```http
POST /api/capture/start
Content-Type: application/json

{
    "interface": "eth0",           # Network interface (optional)
    "filter": "tcp port 80",       # BPF filter string (optional)
    "timeout": 0,                  # Capture timeout in seconds (0 = unlimited)
    "packet_count": 0             # Max packets to capture (0 = unlimited)
}

Response 200 OK:
{
    "status": "success",
    "message": "Packet capture started",
    "interface": "eth0",
    "filter": "tcp port 80"
}
```

#### Stop Capture
```http
POST /api/capture/stop

Response 200 OK:
{
    "status": "success",
    "message": "Packet capture stopped",
    "statistics": {
        "total_packets": 2225,
        "stored_packets": 1000,
        "duration_seconds": 346.11,
        "packets_per_second": 6.43,
        "protocol_distribution": {
            "TCP": 1000
        },
        "service_distribution": {
            "HTTP": 42,
            "HTTPS": 958
        }
    },
    "capture_id": "capture_2025-09-19_15_22_35"
}
```

#### Get Capture Status
```http
GET /api/capture/status

Response 200 OK:
{
    "status": "success",
    "is_active": true,
    "start_time": "2025-09-19T15:22:35.140332",
    "interface": "eth0",
    "statistics": {
        "total_packets": 1500,
        "stored_packets": 1000,
        "duration_seconds": 180.5,
        "packets_per_second": 8.31,
        "protocol_distribution": {
            "TCP": 800,
            "UDP": 150,
            "ICMP": 50
        },
        "service_distribution": {
            "HTTP": 300,
            "HTTPS": 500,
            "DNS": 150,
            "SSH": 50
        }
    }
}
```

#### List Available Network Interfaces
```http
GET /api/capture/interfaces

Response 200 OK:
{
    "status": "success",
    "interfaces": [
        "eth0",
        "lo",
        "wlan0"
    ]
}
```

### Error Responses
All endpoints may return the following error responses:

```http
Response 400 Bad Request:
{
    "status": "error",
    "message": "Invalid request parameters"
}

Response 401 Unauthorized:
{
    "status": "error",
    "message": "Authentication required"
}

Response 403 Forbidden:
{
    "status": "error",
    "message": "Insufficient permissions"
}

Response 500 Internal Server Error:
{
    "status": "error",
    "message": "Internal server error occurred"
}
```

### API Usage Examples

#### Start TCP Port Scan
```bash
curl -X POST http://localhost:5000/api/scan/port \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "ports": [22, 80, 443],
    "timeout": 1.0,
    "threads": 50
  }'
```

#### Start Packet Capture
```bash
curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{
    "interface": "eth0",
    "filter": "tcp port 80 or port 443",
    "timeout": 300
  }'
```

#### Monitor Capture Status
```bash
curl http://localhost:5000/api/capture/status | jq
```

## 📊 Example Output

### Port Scan Results
```json
{
    "scan_id": "20250919_123456",
    "target": "192.168.1.1",
    "open_ports": [
        {"port": 80, "service": "HTTP"},
        {"port": 443, "service": "HTTPS"},
        {"port": 22, "service": "SSH"}
    ],
    "scan_time": "2.5s"
}
```

### Packet Capture Statistics
```json
{
    "total_packets": 2225,
    "stored_packets": 1000,
    "duration_seconds": 346.11,
    "packets_per_second": 6.43,
    "protocol_distribution": {
        "TCP": 1000
    },
    "service_distribution": {
        "HTTP": 42,
        "HTTPS": 958
    }
}
```

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   sudo python app.py --host 0.0.0.0 --port 5000
   ```
   Root privileges are required for packet sniffing.

2. **No Packets Captured**
   - Verify interface exists and is up
   - Check BPF filter syntax
   - Ensure sufficient permissions
   - Generate some network traffic

3. **Port Scan Timeouts**
   - Adjust timeout settings
   - Check firewall rules
   - Reduce thread count

## 📜 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

- Open an issue for bug reports
- Submit feature requests through issues
- Check documentation for common questions
1. **Target Configuration**:
   - Single IP: `192.168.1.1`
   - IP range: `192.168.1.0/24`
   - Hostname: `example.com`

2. **Port Selection**:
   - Common ports (default 20 most common)
   - Port range: `1-1000`
   - Custom list: `80,443,22,21`

3. **Scan Options**:
   - Timeout: Connection timeout in seconds
   - Max Threads: Concurrent scanning threads

### Packet Sniffer
1. **Capture Configuration**:
   - Network Interface: Select or use default
   - BPF Filter: Berkeley Packet Filter (e.g., `tcp port 80`)
   - Max Packets: Maximum packets to capture
   - Timeout: Capture duration in seconds

2. **Real-time Monitoring**:
   - Live packet display
   - Protocol statistics
   - Export captured data

## 📡 API Endpoints

### Port Scanning
```http
POST /api/scan/port
Content-Type: application/json

{
  "target": "192.168.1.1",
  "ports": "common",
  "timeout": 1.0,
  "threads": 100
}
```

### Packet Sniffing

# Capture
curl http://localhost:5000/api/capture/interfaces

# Start capture

curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "filter": "tcp"}'


# Check Status
curl http://localhost:5000/api/capture/status

# Stop capture
curl -X POST http://localhost:5000/api/capture/stop

# Get packets


# Get statistics
GET /api/sniffer/statistics
```

### System Information
```http
GET /api/system/info
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file for custom configuration:
```env
FLASK_SECRET_KEY=your-secret-key-here
DEFAULT_TIMEOUT=1.0
MAX_THREADS=100
MAX_PACKETS=1000
```

### Logging
Logs are automatically saved to the `logs/` directory:
- `logs/app_YYYYMMDD.log`: Application logs
- Debug mode: More verbose logging

## 🐧 Linux/Unix Specific Notes

### Permission Requirements
For full packet sniffing functionality:
```bash
# Run with sudo (recommended)
sudo python app.py

# Or set capabilities (advanced)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python)
```

### Firewall Configuration
```bash
# Allow the application port (example for port 5000)
sudo ufw allow 5000/tcp
```

## 🪟 Windows Specific Notes

### Administrator Privileges
- Run Command Prompt or PowerShell as Administrator
- Or right-click on the Python script and "Run as Administrator"

### WinPcap/Npcap Installation
For packet sniffing on Windows, install Npcap:
1. Download from: https://npcap.com/#download
2. Install with "WinPcap API-compatible mode" enabled

## 🚀 Development

### Project Structure
```
web-network-scanner/
├── app.py                 # Main application entry point
├── web_app.py            # Flask web application
├── scanner/              # Core scanning modules
│   ├── __init__.py
│   ├── port_scanner.py   # Port scanning functionality
│   └── packet_sniffer.py # Packet sniffing functionality
├── templates/            # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── port_scanner.html
│   └── packet_sniffer.html
├── static/               # Static web assets
│   ├── css/style.css
│   └── js/main.js
├── logs/                 # Application logs
├── exports/              # Exported data files
└── requirements.txt      # Python dependencies
```

### Adding New Features
1. Create feature branch: `git checkout -b feature/new-feature`
2. Implement changes in appropriate modules
3. Add tests if applicable
4. Update documentation
5. Submit pull request

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/

# Run with coverage
pytest --cov=scanner tests/
```

## 🔒 Security Considerations

### Network Security
- Run on trusted networks only
- Use firewall rules to restrict access
- Consider VPN for remote access

### Application Security
- Change default Flask secret key in production
- Use HTTPS in production environments
- Implement authentication for multi-user scenarios
- Regular security updates for dependencies

### Scanning Ethics
- Obtain written permission before scanning
- Respect rate limits and system resources
- Follow responsible disclosure for vulnerabilities
- Document and report scanning activities

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" errors**:
- Run with administrator/root privileges
- Check firewall settings
- Verify network interface access

**"Module not found" errors**:
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt`
- Check Python version compatibility

**Packet capture not working**:
- Install Npcap (Windows) or ensure raw socket access (Linux)
- Run with elevated privileges
- Check network interface availability

**Web interface not loading**:
- Verify the server is running
- Check if port is already in use
- Try different host/port combination

### Getting Help
1. Check the logs in `logs/` directory
2. Run with `--debug` flag for verbose output
3. Verify all dependencies are installed
4. Check system permissions and firewall settings

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📚 Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Bootstrap Documentation](https://getbootstrap.com/docs/)
- [Network Security Best Practices](https://www.nist.gov/cybersecurity)

## 🔄 Changelog

### Version 1.0.0
- Initial release
- Port scanner with multi-threading
- Packet sniffer with real-time capture
- Web interface with Bootstrap UI
- REST API endpoints
- Export functionality
- Cross-platform support

---
