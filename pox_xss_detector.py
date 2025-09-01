#!/usr/bin/env python3
"""
POX Controller XSS Detection Module
Integrates with POX SDN controller to detect XSS attacks in real-time
Bachelor's Final Year Project
"""

from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin
import logging
import time
import json
from xss_detector import XSSDetector

log = core.getLogger()

class XSSDetectorController(EventMixin):
    """POX Controller component for XSS detection"""
    
    def __init__(self):
        self.listenTo(core.openflow)
        self.xss_detector = XSSDetector()
        self.connections = {}
        self.http_sessions = {}
        
        # Statistics
        self.packets_analyzed = 0
        self.xss_detected = 0
        
        log.info("XSS Detector Controller initialized")
    
    def _handle_ConnectionUp(self, event):
        """Handle new switch connection"""
        self.connections[event.dpid] = event.connection
        log.info(f"Switch {dpidToStr(event.dpid)} connected")
        
        # Install flow to redirect HTTP traffic to controller
        self._install_http_flow(event.connection)
    
    def _handle_ConnectionDown(self, event):
        """Handle switch disconnection"""
        if event.dpid in self.connections:
            del self.connections[event.dpid]
        log.info(f"Switch {dpidToStr(event.dpid)} disconnected")
    
    def _install_http_flow(self, connection):
        """Install flow rules to capture HTTP traffic"""
        # Capture HTTP traffic (port 80)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_proto = 6      # TCP
        msg.match.tp_dst = 80       # HTTP port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        connection.send(msg)
        
        # Capture HTTPS traffic (port 443) - limited analysis
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_proto = 6      # TCP
        msg.match.tp_dst = 443      # HTTPS port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        connection.send(msg)
        
        # Capture traffic from IoT devices (common ports)
        for port in [8080, 8000, 3000, 5000]:  # Common IoT web ports
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x0800
            msg.match.nw_proto = 6
            msg.match.tp_dst = port
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            connection.send(msg)
        
        log.info("HTTP flow rules installed")
    
    def _handle_PacketIn(self, event):
        """Handle incoming packets"""
        packet = event.parsed
        
        if not packet.parsed:
            return
        
        if packet.type != ethernet.IP_TYPE:
            return
        
        ip_packet = packet.payload
        if ip_packet.protocol != ipv4.TCP_PROTOCOL:
            return
        
        tcp_packet = ip_packet.payload
        
        # Analyze HTTP traffic
        if tcp_packet.dstport in [80, 8080, 8000, 3000, 5000] or tcp_packet.srcport in [80, 8080, 8000, 3000, 5000]:
            self._analyze_http_packet(ip_packet, tcp_packet, event)
        
        self.packets_analyzed += 1
    
    def _analyze_http_packet(self, ip_packet, tcp_packet, event):
        """Analyze HTTP packet for XSS attacks"""
        try:
            payload = tcp_packet.payload
            if not payload:
                return
            
            # Convert payload to string
            try:
                http_data = str(payload)
            except:
                http_data = payload.decode('utf-8', errors='ignore')
            
            if not http_data or len(http_data) < 10:
                return
            
            # Check if it's an HTTP request
            if http_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                self._analyze_http_request(ip_packet, http_data, event)
            elif 'HTTP/' in http_data:
                self._analyze_http_response(ip_packet, http_data, event)
                
        except Exception as e:
            log.debug(f"Error analyzing packet: {e}")
    
    def _analyze_http_request(self, ip_packet, http_data, event):
        """Analyze HTTP request for XSS patterns"""
        lines = http_data.split('\\n')
        if not lines:
            return
        
        # Parse request line
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 3:
            return
        
        method = parts[0]
        url = parts[1]
        
        # Parse headers
        headers = {}
        body = ""
        body_start = False
        
        for line in lines[1:]:
            if body_start:
                body += line + "\\n"
            elif line.strip() == "":
                body_start = True
            elif ':' in line:
                header_parts = line.split(':', 1)
                if len(header_parts) == 2:
                    headers[header_parts[0].strip()] = header_parts[1].strip()
        
        source_ip = str(ip_packet.srcip)
        
        # Analyze request with XSS detector
        result = self.xss_detector.analyze_http_request(method, url, headers, body, source_ip)
        
        if result["detected"]:
            self.xss_detected += 1
            self._handle_xss_detection(source_ip, url, result, event)
    
    def _analyze_http_response(self, ip_packet, http_data, event):
        """Analyze HTTP response for XSS patterns"""
        # Check response body for XSS patterns
        body_start = http_data.find('\\r\\n\\r\\n')
        if body_start != -1:
            body = http_data[body_start + 4:]
            source_ip = str(ip_packet.dstip)  # Response goes to destination
            
            result = self.xss_detector.detect_xss(body, source_ip, "response")
            
            if result["detected"]:
                self.xss_detected += 1
                self._handle_xss_detection(source_ip, "HTTP Response", result, event)
    
    def _handle_xss_detection(self, source_ip, url, result, event):
        """Handle detected XSS attack"""
        log.warning(f"🚨 XSS ATTACK DETECTED!")
        log.warning(f"   Source IP: {source_ip}")
        log.warning(f"   URL/Location: {url}")
        log.warning(f"   Risk Level: {result.get('risk_level', 'unknown')}")
        log.warning(f"   Patterns Detected: {result.get('total_detections', len(result.get('results', [])))}")
        
        # Log to file for analysis
        attack_data = {
            "timestamp": time.time(),
            "source_ip": source_ip,
            "url": url,
            "result": result,
            "switch_id": dpidToStr(event.dpid),
            "port": event.port
        }
        
        self._log_attack_to_file(attack_data)
        
        # Optional: Block malicious traffic (uncomment to enable)
        # self._block_malicious_traffic(source_ip, event.connection)
    
    def _log_attack_to_file(self, attack_data):
        """Log attack data to JSON file"""
        try:
            filename = f"pox_xss_attacks_{int(time.time() // 3600)}.json"  # New file every hour
            with open(filename, 'a') as f:
                json.dump(attack_data, f)
                f.write('\\n')
        except Exception as e:
            log.error(f"Failed to log attack: {e}")
    
    def _block_malicious_traffic(self, source_ip, connection):
        """Block traffic from malicious IP (optional)"""
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = source_ip
        msg.priority = 65535  # Highest priority
        msg.hard_timeout = 300  # Block for 5 minutes
        # No actions = drop packet
        connection.send(msg)
        log.info(f"Blocked traffic from {source_ip} for 5 minutes")
    
    def get_statistics(self):
        """Get detection statistics"""
        detector_stats = self.xss_detector.get_statistics()
        
        return {
            "packets_analyzed": self.packets_analyzed,
            "xss_detected": self.xss_detected,
            "connected_switches": len(self.connections),
            "detector_stats": detector_stats,
            "detection_rate": (self.xss_detected / max(1, self.packets_analyzed)) * 100
        }
    
    def print_statistics(self):
        """Print current statistics"""
        stats = self.get_statistics()
        print("\\n" + "="*50)
        print("XSS DETECTION STATISTICS")
        print("="*50)
        print(f"Packets Analyzed: {stats['packets_analyzed']}")
        print(f"XSS Attacks Detected: {stats['xss_detected']}")
        print(f"Detection Rate: {stats['detection_rate']:.2f}%")
        print(f"Connected Switches: {stats['connected_switches']}")
        print(f"Total Patterns: {stats['detector_stats']['patterns_loaded']}")
        print("="*50)

class XSSMonitor(EventMixin):
    """Monitoring component for periodic statistics"""
    
    def __init__(self, controller):
        self.controller = controller
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start periodic monitoring"""
        core.call_delayed(30, self._periodic_stats)  # Every 30 seconds
    
    def _periodic_stats(self):
        """Print periodic statistics"""
        self.controller.print_statistics()
        core.call_delayed(30, self._periodic_stats)

def launch():
    """Launch the XSS detection controller"""
    controller = XSSDetectorController()
    monitor = XSSMonitor(controller)
    
    log.info("XSS Detection Controller launched successfully!")
    log.info("Monitoring HTTP traffic on ports: 80, 443, 8080, 8000, 3000, 5000")
    log.info("Use 'sudo python pox.py pox_xss_detector' to run this module")
    
    return controller