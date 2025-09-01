#!/usr/bin/env python3
"""
Mininet-WiFi Topology for XSS Attack Detection Testing
Creates IoT device simulation with WiFi access points
Bachelor's Final Year Project
"""

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
import sys
import time
import threading
import subprocess

try:
    from mn_wifi.net import Mininet_wifi
    from mn_wifi.node import Station, OVSKernelAP
    from mn_wifi.cli import CLI_wifi
    from mn_wifi.link import wmediumd
    from mn_wifi.wmediumdConnector import interference
    WIFI_AVAILABLE = True
except ImportError:
    print("Mininet-WiFi not available, falling back to regular Mininet")
    WIFI_AVAILABLE = False

class IoTXSSTopology:
    """IoT network topology for XSS attack testing"""
    
    def __init__(self, use_wifi=True):
        self.net = None
        self.use_wifi = use_wifi and WIFI_AVAILABLE
        self.devices = {}
        self.servers = {}
        
        print(f"Initializing topology with WiFi: {self.use_wifi}")
    
    def create_topology(self):
        """Create the network topology"""
        if self.use_wifi:
            self._create_wifi_topology()
        else:
            self._create_ethernet_topology()
    
    def _create_wifi_topology(self):
        """Create WiFi-based IoT topology"""
        print("Creating WiFi IoT topology...")
        
        # Create Mininet-WiFi network
        self.net = Mininet_wifi(
            controller=RemoteController,
            link=wmediumd,
            wmediumd_mode=interference,
            accessPoint=OVSKernelAP
        )
        
        print("Adding controller...")
        # Add POX controller
        c1 = self.net.addController('c1', controller=RemoteController, 
                                   ip='127.0.0.1', port=6633)
        
        print("Adding access points...")
        # Add WiFi access points
        ap1 = self.net.addAccessPoint('ap1', ssid='IoT-Network-1', 
                                     mode='g', channel='1', position='50,50,0')
        ap2 = self.net.addAccessPoint('ap2', ssid='IoT-Network-2', 
                                     mode='g', channel='6', position='150,50,0')
        
        print("Adding IoT devices (stations)...")
        # Add IoT devices as wireless stations
        # Smart home devices
        iot1 = self.net.addStation('iot1', mac='00:00:00:00:00:01', 
                                  ip='10.0.1.10/24', position='45,45,0')
        iot2 = self.net.addStation('iot2', mac='00:00:00:00:00:02', 
                                  ip='10.0.1.11/24', position='55,45,0')
        
        # Industrial IoT devices
        iot3 = self.net.addStation('iot3', mac='00:00:00:00:00:03', 
                                  ip='10.0.2.10/24', position='145,45,0')
        iot4 = self.net.addStation('iot4', mac='00:00:00:00:00:04', 
                                  ip='10.0.2.11/24', position='155,45,0')
        
        # Web server and attacker
        server = self.net.addStation('server', mac='00:00:00:00:00:05', 
                                   ip='10.0.1.100/24', position='50,70,0')
        attacker = self.net.addStation('attacker', mac='00:00:00:00:00:06', 
                                     ip='10.0.1.200/24', position='50,30,0')
        
        # Store device references
        self.devices = {
            'iot1': iot1, 'iot2': iot2, 'iot3': iot3, 'iot4': iot4,
            'server': server, 'attacker': attacker,
            'ap1': ap1, 'ap2': ap2
        }
        
        print("Configuring network...")
        self.net.configureWifiNodes()
        
        # Build the network
        self.net.build()
        c1.start()
        ap1.start([c1])
        ap2.start([c1])
        
        print("Setting up associations...")
        # Associate devices with access points
        self.net.addLink(iot1, ap1)
        self.net.addLink(iot2, ap1)
        self.net.addLink(server, ap1)
        self.net.addLink(attacker, ap1)
        
        self.net.addLink(iot3, ap2)
        self.net.addLink(iot4, ap2)
    
    def _create_ethernet_topology(self):
        """Create Ethernet-based topology as fallback"""
        print("Creating Ethernet IoT topology...")
        
        # Create regular Mininet network
        self.net = Mininet(controller=RemoteController, link=TCLink)
        
        # Add controller
        c1 = self.net.addController('c1', controller=RemoteController, 
                                   ip='127.0.0.1', port=6633)
        
        # Add switch
        s1 = self.net.addSwitch('s1')
        
        # Add hosts representing IoT devices
        iot1 = self.net.addHost('iot1', ip='10.0.1.10/24', mac='00:00:00:00:00:01')
        iot2 = self.net.addHost('iot2', ip='10.0.1.11/24', mac='00:00:00:00:00:02')
        iot3 = self.net.addHost('iot3', ip='10.0.1.12/24', mac='00:00:00:00:00:03')
        iot4 = self.net.addHost('iot4', ip='10.0.1.13/24', mac='00:00:00:00:00:04')
        
        # Web server and attacker
        server = self.net.addHost('server', ip='10.0.1.100/24', mac='00:00:00:00:00:05')
        attacker = self.net.addHost('attacker', ip='10.0.1.200/24', mac='00:00:00:00:00:06')
        
        # Create links
        self.net.addLink(iot1, s1)
        self.net.addLink(iot2, s1)
        self.net.addLink(iot3, s1)
        self.net.addLink(iot4, s1)
        self.net.addLink(server, s1)
        self.net.addLink(attacker, s1)
        
        # Store device references
        self.devices = {
            'iot1': iot1, 'iot2': iot2, 'iot3': iot3, 'iot4': iot4,
            'server': server, 'attacker': attacker, 's1': s1
        }
        
        # Start network
        self.net.build()
        c1.start()
        s1.start([c1])
    
    def start_vulnerable_server(self):
        """Start vulnerable web server for testing"""
        server = self.devices['server']
        
        # Create simple vulnerable web server
        server_script = '''
import http.server
import socketserver
import urllib.parse
from datetime import datetime

class VulnerableHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Parse URL parameters
        if '?' in self.path:
            path, query = self.path.split('?', 1)
            params = urllib.parse.parse_qs(query)
            
            # Vulnerable search feature
            if path == '/search':
                search_term = params.get('q', [''])[0]
                # Vulnerable: directly embedding user input in HTML
                html = f"""
                <html><body>
                <h1>Search Results</h1>
                <p>You searched for: {search_term}</p>
                <form method="GET" action="/search">
                <input type="text" name="q" placeholder="Search...">
                <input type="submit" value="Search">
                </form>
                </body></html>
                """
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())
                return
        
        # Default response
        html = """
        <html><body>
        <h1>IoT Device Web Interface</h1>
        <p>Device Status: Online</p>
        <a href="/search?q=test">Test Search</a>
        <p>Timestamp: """ + str(datetime.now()) + """</p>
        </body></html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Vulnerable comment feature
        if self.path == '/comment':
            comment = urllib.parse.parse_qs(post_data).get('comment', [''])[0]
            # Vulnerable: directly embedding user input
            html = f"""
            <html><body>
            <h1>Comment Posted</h1>
            <p>Your comment: {comment}</p>
            <form method="POST" action="/comment">
            <textarea name="comment" placeholder="Enter comment..."></textarea>
            <input type="submit" value="Post Comment">
            </form>
            </body></html>
            """
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())

PORT = 8080
Handler = VulnerableHTTPHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Vulnerable server running on port {PORT}")
    httpd.serve_forever()
'''
        
        # Write and execute server script
        server.cmd('echo \'%s\' > /tmp/vulnerable_server.py' % server_script.replace("'", "\\'"))
        server.cmd('python3 /tmp/vulnerable_server.py &')
        
        print("Vulnerable web server started on 10.0.1.100:8080")
        time.sleep(2)
    
    def generate_normal_traffic(self):
        """Generate normal IoT traffic"""
        def traffic_generator():
            while True:
                for device_name in ['iot1', 'iot2', 'iot3', 'iot4']:
                    device = self.devices[device_name]
                    # Normal HTTP requests
                    device.cmd('curl -s http://10.0.1.100:8080/ > /dev/null &')
                    device.cmd('curl -s http://10.0.1.100:8080/search?q=temperature > /dev/null &')
                time.sleep(5)
        
        # Start traffic generation in background
        traffic_thread = threading.Thread(target=traffic_generator, daemon=True)
        traffic_thread.start()
        print("Normal traffic generation started")
    
    def launch_xss_attacks(self):
        """Launch XSS attacks from attacker node"""
        attacker = self.devices['attacker']
        
        xss_payloads = [
            "<script>alert('XSS1')</script>",
            "javascript:alert('XSS2')",
            "<img src=x onerror=alert('XSS3')>",
            "<svg onload=alert('XSS4')>",
            "<iframe src='javascript:alert(5)'></iframe>",
            "' onclick=alert('XSS6') '",
            "<body onload=alert('XSS7')>",
            "<script>document.cookie</script>"
        ]
        
        print("Launching XSS attacks...")
        
        for i, payload in enumerate(xss_payloads):
            # URL-based attack
            encoded_payload = urllib.parse.quote_plus(payload)
            attack_url = f"http://10.0.1.100:8080/search?q={encoded_payload}"
            
            print(f"Attack {i+1}: {payload[:30]}...")
            attacker.cmd(f'curl -s "{attack_url}" > /dev/null')
            
            # POST-based attack
            post_data = f"comment={encoded_payload}"
            attacker.cmd(f'curl -s -X POST -d "{post_data}" http://10.0.1.100:8080/comment > /dev/null')
            
            time.sleep(1)
        
        print("XSS attacks completed")
    
    def run_test_scenario(self):
        """Run complete test scenario"""
        print("\\n" + "="*60)
        print("STARTING XSS ATTACK DETECTION TEST SCENARIO")
        print("="*60)
        
        print("\\n1. Starting vulnerable web server...")
        self.start_vulnerable_server()
        
        print("\\n2. Generating normal traffic...")
        self.generate_normal_traffic()
        
        print("\\n3. Waiting for baseline traffic...")
        time.sleep(10)
        
        print("\\n4. Launching XSS attacks...")
        self.launch_xss_attacks()
        
        print("\\n5. Test scenario completed!")
        print("Check POX controller logs for detection results.")
        print("="*60)
    
    def start_cli(self):
        """Start Mininet CLI"""
        if self.use_wifi:
            CLI_wifi(self.net)
        else:
            CLI(self.net)
    
    def cleanup(self):
        """Cleanup network"""
        if self.net:
            self.net.stop()

def main():
    """Main function"""
    setLogLevel('info')
    
    print("IoT XSS Detection Test Environment")
    print("=" * 40)
    
    # Check if WiFi is requested
    use_wifi = '--wifi' in sys.argv
    
    # Create topology
    topology = IoTXSSTopology(use_wifi=use_wifi)
    
    try:
        print("Creating network topology...")
        topology.create_topology()
        
        print("Network created successfully!")
        print("\\nAvailable commands:")
        print("- test: Run XSS attack test scenario")
        print("- server: Start vulnerable server")
        print("- attack: Launch XSS attacks")
        print("- traffic: Generate normal traffic")
        print("- quit: Exit")
        
        # Check if automatic test is requested
        if '--test' in sys.argv:
            topology.run_test_scenario()
        
        # Start CLI
        print("\\nStarting network CLI...")
        print("Use 'py topology.run_test_scenario()' to run automated tests")
        topology.start_cli()
        
    except KeyboardInterrupt:
        print("\\nShutting down...")
    finally:
        topology.cleanup()

if __name__ == '__main__':
    main()