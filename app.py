#!/usr/bin/env python3
"""
Web Network Scanner - Main Application Entry Point
A web-based port scanner and packet sniffer application

Usage:
    python app.py [--host HOST] [--port PORT] [--debug]
    
Example:
    python app.py --host 0.0.0.0 --port 5000 --debug
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from web_app import app
except ImportError as e:
    print(f"Error importing web_app: {e}")
    print("Please ensure all required dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)


def setup_logging(debug=False):
    """Setup logging configuration"""
    log_level = logging.DEBUG if debug else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(f'logs/app_{datetime.now().strftime("%Y%m%d")}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Suppress some verbose logs in production
    if not debug:
        logging.getLogger('werkzeug').setLevel(logging.WARNING)


def check_requirements():
    """Check if all required packages are available"""
    required_packages = [
        ('flask', 'Flask'),
        ('scapy', 'Scapy'),
        ('requests', 'Requests'),
        ('psutil', 'psutil'),
        ('netifaces', 'netifaces')
    ]
    
    missing_packages = []
    
    for package, display_name in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(display_name)
    
    if missing_packages:
        print("Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nInstall missing packages with:")
        print("pip install -r requirements.txt")
        return False
    
    return True


def check_permissions():
    """Check if running with appropriate permissions for packet sniffing"""
    if os.name == 'nt':  # Windows
        # On Windows, check if running as administrator
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("WARNING: Packet sniffing may require administrator privileges on Windows.")
        except:
            pass
    else:  # Unix-like systems
        if os.geteuid() != 0:
            print("WARNING: Packet sniffing may require root privileges on Unix-like systems.")
            print("Consider running with sudo for full functionality.")


def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Web Network Scanner                       ║
    ║                                                              ║
    ║  A comprehensive web-based network scanning tool             ║
    ║  Features: Port Scanner, Packet Sniffer, Web Interface       ║
    ║                                                              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='Web Network Scanner - Port Scanner and Packet Sniffer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app.py                          # Run on default host/port
  python app.py --host 0.0.0.0 --port 8080  # Custom host/port
  python app.py --debug                  # Enable debug mode
        """
    )
    
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind the server to (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind the server to (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Web Network Scanner v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Setup logging
    setup_logging(args.debug)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Web Network Scanner...")
    
    # Check requirements
    if not check_requirements():
        logger.error("Missing required packages. Exiting.")
        sys.exit(1)
    
    # Check permissions
    check_permissions()
    
    # Ensure required directories exist
    directories = ['logs', 'exports', 'static/css', 'static/js', 'templates']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")
    
    # Configure Flask app
    if args.debug:
        app.config['DEBUG'] = True
        app.config['TEMPLATES_AUTO_RELOAD'] = True
        logger.info("Debug mode enabled")
    
    # Security warning for production use
    if args.host == '0.0.0.0' and not args.debug:
        logger.warning("Server is binding to all interfaces (0.0.0.0). "
                      "Ensure proper firewall rules are in place.")
    
    # Print startup information
    logger.info(f"Host: {args.host}")
    logger.info(f"Port: {args.port}")
    logger.info(f"Debug: {args.debug}")
    
    try:
        logger.info("Web Network Scanner is ready!")
        print(f"\n🌐 Access the web interface at: http://{args.host}:{args.port}")
        print("📋 Available endpoints:")
        print("   • Dashboard: /")
        print("   • Port Scanner: /port-scanner")
        print("   • Packet Sniffer: /packet-sniffer")
        print("   • API Documentation: Use browser developer tools to explore /api/* endpoints")
        print("\n🔧 Press Ctrl+C to stop the server\n")
        
        # Start the Flask development server
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True,
            use_reloader=args.debug
        )
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal. Shutting down gracefully...")
        print("\n👋 Web Network Scanner stopped. Goodbye!")
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()