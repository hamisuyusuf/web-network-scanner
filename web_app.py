"""
Web Network Scanner - Flask Application
Main web application providing REST API endpoints for port scanning and packet sniffing
"""

from flask import Flask, render_template, request, jsonify, send_file
import threading
import json
import os
from datetime import datetime
from scanner.port_scanner import PortScanner
from scanner.packet_sniffer import PacketSniffer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'

# Global instances
port_scanner = PortScanner()
packet_sniffer = PacketSniffer()  # Initialize with default interface
scan_results = {}
scan_history = []

# Store packet capture status
packet_capture_status = {
    'is_active': False,
    'start_time': None,
    'interface': None
}


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/port-scanner')
def port_scanner_page():
    """Port scanner interface"""
    return render_template('port_scanner.html')


@app.route('/packet-sniffer')
def packet_sniffer_page():
    """Packet sniffer interface"""
    return render_template('packet_sniffer.html')


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """
    Start packet capture
    Expected JSON: {
        "interface": "eth0",  # optional
        "filter": "tcp port 80",  # optional
        "timeout": 0,  # optional, 0 for no timeout
        "packet_count": 0  # optional, 0 for unlimited
    }
    """
    global packet_sniffer, packet_capture_status
    
    try:
        data = request.get_json() or {}
        
        # Get parameters with defaults
        interface = data.get('interface')
        filter_string = data.get('filter', '')
        timeout = int(data.get('timeout', 0))
        packet_count = int(data.get('packet_count', 0))
        
        # Initialize new sniffer if interface changes
        if interface != packet_capture_status['interface']:
            packet_sniffer = PacketSniffer(interface=interface)
            packet_capture_status['interface'] = interface
        
        # Start capture
        if packet_sniffer.start_sniffing(
            filter_string=filter_string,
            packet_count=packet_count,
            timeout=timeout
        ):
            packet_capture_status['is_active'] = True
            packet_capture_status['start_time'] = datetime.now().isoformat()
            
            return jsonify({
                'status': 'success',
                'message': 'Packet capture started',
                'interface': interface or 'default',
                'filter': filter_string or 'none'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to start packet capture'
            }), 400
            
    except Exception as e:
        app.logger.error(f"Error starting packet capture: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global packet_sniffer, packet_capture_status
    
    try:
        if packet_sniffer:
            packet_sniffer.stop_sniffing()
            
            # Get capture results
            stats = packet_sniffer.get_statistics()
            packets = packet_sniffer.get_captured_packets()
            
            # Generate capture ID and store results
            capture_id = datetime.now().strftime('capture_%Y-%m-%d_%H_%M_%S')
            
            # Export results
            os.makedirs('exports', exist_ok=True)
            export_file = f'exports/{capture_id}'
            packet_sniffer.export_packets(export_file, format='json')
            
            packet_capture_status['is_active'] = False
            
            return jsonify({
                'status': 'success',
                'message': 'Packet capture stopped',
                'statistics': stats,
                'capture_id': capture_id
            })
        
        return jsonify({
            'status': 'error',
            'message': 'No active packet capture'
        }), 400
        
    except Exception as e:
        app.logger.error(f"Error stopping packet capture: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    """Get packet capture status and statistics"""
    global packet_sniffer, packet_capture_status
    
    try:
        if packet_sniffer:
            stats = packet_sniffer.get_statistics()
            return jsonify({
                'status': 'success',
                'is_active': packet_capture_status['is_active'],
                'start_time': packet_capture_status['start_time'],
                'interface': packet_capture_status['interface'] or 'default',
                'statistics': stats
            })
        
        return jsonify({
            'status': 'error',
            'message': 'Packet sniffer not initialized'
        }), 400
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/capture/interfaces', methods=['GET'])
def get_interfaces():
    """Get list of available network interfaces"""
    global packet_sniffer
    
    try:
        if packet_sniffer:
            interfaces = packet_sniffer.get_available_interfaces()
            return jsonify({
                'status': 'success',
                'interfaces': interfaces
            })
        
        return jsonify({
            'status': 'error',
            'message': 'Packet sniffer not initialized'
        }), 400
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/scan/port', methods=['POST'])
def scan_ports():
    """
    Scan ports on target host(s)
    Expected JSON: {
        "target": "192.168.1.1" or "192.168.1.0/24",
        "ports": [80, 443, 22] or "common" or "1-1000",
        "timeout": 1.0,
        "threads": 100
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        target = data.get('target')
        ports_input = data.get('ports', 'common')
        timeout = float(data.get('timeout', 1.0))
        max_threads = int(data.get('threads', 100))
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Configure scanner
        scanner = PortScanner(timeout=timeout, max_threads=max_threads)
        
        # Parse ports
        if ports_input == 'common':
            ports = scanner.get_common_ports()
        elif isinstance(ports_input, str) and '-' in ports_input:
            start, end = map(int, ports_input.split('-'))
            ports = scanner.get_port_range(start, end)
        elif isinstance(ports_input, list):
            ports = [int(p) for p in ports_input]
        else:
            return jsonify({'error': 'Invalid ports format'}), 400
        
        # Perform scan
        if '/' in target:  # Network range
            results = scanner.scan_network_range(target, ports)
        else:  # Single host
            results = [scanner.scan_host_ports(target, ports)]
        
        # Store results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results[scan_id] = {
            'target': target,
            'results': results,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'port_scan'
        }
        
        # Add to history
        scan_history.append({
            'id': scan_id,
            'target': target,
            'type': 'Port Scan',
            'timestamp': datetime.now().isoformat(),
            'results_count': len(results)
        })
        
        return jsonify({
            'scan_id': scan_id,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/results/<scan_id>')
def get_scan_results(scan_id):
    """Get scan results by ID"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Scan results not found'}), 404


@app.route('/api/scan/history')
def get_scan_history():
    """Get scan history"""
    return jsonify({'history': scan_history})


@app.route('/api/sniffer/start', methods=['POST'])
def start_packet_capture():
    """
    Start packet capture
    Expected JSON: {
        "interface": "eth0" or null,
        "filter": "tcp port 80",
        "max_packets": 1000,
        "timeout": 60
    }
    """
    global packet_sniffer
    
    try:
        data = request.get_json() or {}
        
        interface = data.get('interface')
        filter_string = data.get('filter', '')
        max_packets = int(data.get('max_packets', 1000))
        timeout = int(data.get('timeout', 60))
        
        # Create new sniffer instance
        packet_sniffer = PacketSniffer(interface=interface, max_packets=max_packets)
        
        # Start capturing
        if packet_sniffer.start_sniffing(
            filter_string=filter_string,
            timeout=timeout
        ):
            return jsonify({
                'status': 'started',
                'interface': interface or 'default',
                'filter': filter_string,
                'max_packets': max_packets,
                'timeout': timeout
            })
        else:
            return jsonify({'error': 'Failed to start packet capture'}), 500
            
    except ImportError:
        return jsonify({'error': 'Scapy not available. Install with: pip install scapy'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sniffer/stop', methods=['POST'])
def stop_packet_capture():
    """Stop packet capture"""
    global packet_sniffer
    
    try:
        if packet_sniffer and packet_sniffer.is_sniffing:
            packet_sniffer.stop_sniffing()
            return jsonify({'status': 'stopped'})
        else:
            return jsonify({'error': 'No active capture session'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sniffer/packets')
def get_captured_packets():
    """Get captured packets"""
    global packet_sniffer
    
    try:
        if packet_sniffer:
            packets = packet_sniffer.get_captured_packets()
            return jsonify({
                'packets': packets,
                'count': len(packets)
            })
        else:
            return jsonify({'packets': [], 'count': 0})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sniffer/statistics')
def get_capture_statistics():
    """Get capture statistics"""
    global packet_sniffer
    
    try:
        if packet_sniffer:
            stats = packet_sniffer.get_statistics()
            return jsonify(stats)
        else:
            return jsonify({'error': 'No sniffer instance available'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sniffer/interfaces')
def get_network_interfaces():
    """Get available network interfaces"""
    try:
        temp_sniffer = PacketSniffer()
        interfaces = temp_sniffer.get_available_interfaces()
        return jsonify({'interfaces': interfaces})
        
    except ImportError:
        return jsonify({'error': 'Scapy not available'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sniffer/export', methods=['POST'])
def export_packets():
    """
    Export captured packets
    Expected JSON: {
        "format": "json" or "csv",
        "filename": "capture.json"
    }
    """
    global packet_sniffer
    
    try:
        if not packet_sniffer:
            return jsonify({'error': 'No capture data available'}), 400
        
        data = request.get_json() or {}
        format_type = data.get('format', 'json')
        filename = data.get('filename', f'capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format_type}')
        
        # Ensure exports directory exists
        os.makedirs('exports', exist_ok=True)
        filepath = os.path.join('exports', filename)
        
        if packet_sniffer.export_packets(filepath, format_type):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'Export failed'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/info')
def get_system_info():
    """Get system information"""
    try:
        import psutil
        import platform
        
        info = {
            'platform': platform.system(),
            'architecture': platform.architecture()[0],
            'hostname': platform.node(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'uptime': psutil.boot_time()
        }
        
        return jsonify(info)
        
    except ImportError:
        return jsonify({'error': 'psutil not available'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Ensure required directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('exports', exist_ok=True)
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)