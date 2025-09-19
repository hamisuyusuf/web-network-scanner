#!/usr/bin/env python3
import socket
import threading
import time

def start_server(port):
    """Start a simple TCP server that listens on the specified port"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to all interfaces
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"[*] Listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client.send(b"Hello from test server!\n")
            client.close()
        except Exception as e:
            print(f"[!] Error: {e}")
            break

def main():
    # Start servers on multiple ports
    ports = [8080, 8000]  # You can add more ports here
    threads = []
    
    for port in ports:
        thread = threading.Thread(target=start_server, args=(port,))
        thread.daemon = True  # This makes the thread exit when the main program exits
        threads.append(thread)
        thread.start()
        print(f"[+] Started server on port {port}")
    
    try:
        # Keep the main thread running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down servers...")

if __name__ == "__main__":
    main()