#!/usr/bin/env python3
"""
Environment Setup Script
Sets up the XSS detection environment with POX controller
Bachelor's Final Year Project
"""

import os
import sys
import subprocess
import urllib.request
import shutil
import time

class XSSDetectionSetup:
    """Setup class for XSS detection environment"""
    
    def __init__(self):
        self.pox_dir = "pox"
        self.requirements = [
            "scapy",
            "requests", 
            "urllib3",
            "netifaces"
        ]
    
    def check_python_version(self):
        """Check Python version compatibility"""
        print("Checking Python version...")
        
        if sys.version_info < (3, 6):
            print("❌ Python 3.6 or higher is required")
            return False
        
        print(f"✅ Python {sys.version.split()[0]} is compatible")
        return True
    
    def install_python_requirements(self):
        """Install required Python packages"""
        print("\\nInstalling Python requirements...")
        
        for package in self.requirements:
            try:
                print(f"Installing {package}...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✅ {package} installed successfully")
            except subprocess.CalledProcessError:
                print(f"❌ Failed to install {package}")
                return False
        
        return True
    
    def download_pox_controller(self):
        """Download and setup POX controller"""
        print("\\nSetting up POX controller...")
        
        if os.path.exists(self.pox_dir):
            print("POX directory already exists")
            return True
        
        try:
            print("Cloning POX repository...")
            subprocess.check_call([
                "git", "clone", 
                "https://github.com/noxrepo/pox.git"
            ])
            print("✅ POX controller downloaded successfully")
            return True
            
        except subprocess.CalledProcessError:
            print("❌ Failed to download POX controller")
            print("Please manually download POX from https://github.com/noxrepo/pox")
            return False
    
    def setup_pox_module(self):
        """Setup XSS detection module in POX"""
        print("\\nSetting up POX XSS detection module...")
        
        if not os.path.exists(self.pox_dir):
            print("❌ POX directory not found")
            return False
        
        # Create module directory
        module_dir = os.path.join(self.pox_dir, "ext")
        os.makedirs(module_dir, exist_ok=True)
        
        # Copy our XSS detection module
        try:
            # Copy the main detection files
            files_to_copy = [
                "pox_xss_detector.py",
                "xss_detector.py"
            ]
            
            for file in files_to_copy:
                if os.path.exists(file):
                    shutil.copy2(file, module_dir)
                    print(f"✅ Copied {file} to POX ext directory")
                else:
                    print(f"❌ {file} not found")
                    return False
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup POX module: {e}")
            return False
    
    def check_mininet_installation(self):
        """Check if Mininet is installed"""
        print("\\nChecking Mininet installation...")
        
        try:
            result = subprocess.run(["mn", "--version"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Mininet is installed")
                print(f"   Version: {result.stdout.strip()}")
                return True
            else:
                print("❌ Mininet not found")
                return False
        except FileNotFoundError:
            print("❌ Mininet not installed")
            print("   Please install Mininet: sudo apt-get install mininet")
            return False
    
    def check_mininet_wifi(self):
        """Check if Mininet-WiFi is available"""
        print("\\nChecking Mininet-WiFi installation...")
        
        try:
            import mn_wifi
            print("✅ Mininet-WiFi is available")
            return True
        except ImportError:
            print("⚠️  Mininet-WiFi not found (optional)")
            print("   Install with: sudo pip install mininet-wifi")
            return False
    
    def create_startup_scripts(self):
        """Create convenient startup scripts"""
        print("\\nCreating startup scripts...")
        
        # POX startup script
        pox_script = '''#!/bin/bash
echo "Starting POX Controller with XSS Detection..."
cd pox
python3 pox.py log.level --DEBUG ext.pox_xss_detector
'''
        
        with open("start_pox.sh", "w") as f:
            f.write(pox_script)
        os.chmod("start_pox.sh", 0o755)
        print("✅ Created start_pox.sh")
        
        # Mininet startup script
        mininet_script = '''#!/bin/bash
echo "Starting Mininet topology for XSS testing..."
sudo python3 mininet_topology.py --wifi --test
'''
        
        with open("start_mininet.sh", "w") as f:
            f.write(mininet_script)
        os.chmod("start_mininet.sh", 0o755)
        print("✅ Created start_mininet.sh")
        
        # Test script
        test_script = '''#!/bin/bash
echo "Running XSS detection tests..."
python3 test_xss_attacks.py all
'''
        
        with open("run_tests.sh", "w") as f:
            f.write(test_script)
        os.chmod("run_tests.sh", 0o755)
        print("✅ Created run_tests.sh")
    
    def create_usage_guide(self):
        """Create usage guide for the project"""
        print("\\nCreating usage guide...")
        
        guide = '''# XSS Attack Detection System - Usage Guide

## Bachelor's Final Year Project

### Overview
This system detects XSS attacks in IoT device networks using SDN (POX controller) and network simulation (Mininet-WiFi).

### Setup Complete!
All components have been set up successfully.

### Usage Instructions

#### 1. Start POX Controller
```bash
# Terminal 1: Start POX controller with XSS detection
./start_pox.sh

# Or manually:
cd pox
python3 pox.py log.level --DEBUG ext.pox_xss_detector
```

#### 2. Start Network Simulation
```bash
# Terminal 2: Start Mininet topology (requires sudo)
sudo ./start_mininet.sh

# Or manually:
sudo python3 mininet_topology.py --wifi --test
```

#### 3. Run Tests
```bash
# Terminal 3: Run XSS detection tests
./run_tests.sh

# Or run specific tests:
python3 test_xss_attacks.py accuracy      # Test detection accuracy
python3 test_xss_attacks.py performance   # Test performance
python3 test_xss_attacks.py web          # Test web server attacks
python3 test_xss_attacks.py traffic 60   # Generate traffic for 60 seconds
```

### Project Components

1. **xss_detector.py** - Core XSS detection engine
2. **pox_xss_detector.py** - POX controller integration
3. **mininet_topology.py** - Network topology simulation
4. **test_xss_attacks.py** - Attack testing and validation

### Workflow

1. POX controller monitors network traffic
2. XSS detection engine analyzes HTTP packets
3. Attacks are detected and logged in real-time
4. Results are displayed in POX console

### Testing Scenarios

The system includes:
- 30+ XSS attack patterns
- Realistic IoT device simulation
- Vulnerable web server for testing
- Automated attack generation
- Performance benchmarking

### Expected Results

- Detection accuracy: >90%
- Real-time processing: <100ms per packet
- Low false positive rate: <5%
- Comprehensive logging and alerts

### Troubleshooting

1. **POX not starting**: Check Python version and module installation
2. **Mininet errors**: Ensure sudo privileges and network cleanup
3. **Detection issues**: Check attack patterns and network traffic
4. **Permission errors**: Use sudo for network-related operations

### Project Demonstration

For your bachelor's project demonstration:

1. Start POX controller (show logs)
2. Launch Mininet topology (show network)
3. Generate normal traffic (baseline)
4. Launch XSS attacks (show detection)
5. Display statistics and results

### Files Generated

- XSS detection logs: `xss_detection.log`
- Attack data: `pox_xss_attacks_*.json`
- Test results: Console output and log files

Good luck with your project! 🎓
'''
        
        with open("README.md", "w") as f:
            f.write(guide)
        print("✅ Created README.md with usage guide")
    
    def run_setup(self):
        """Run complete setup process"""
        print("XSS DETECTION SYSTEM SETUP")
        print("=" * 50)
        print("Bachelor's Final Year Project")
        print("=" * 50)
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Installing Python packages", self.install_python_requirements),
            ("Downloading POX controller", self.download_pox_controller),
            ("Setting up POX module", self.setup_pox_module),
            ("Checking Mininet", self.check_mininet_installation),
            ("Checking Mininet-WiFi", self.check_mininet_wifi),
            ("Creating startup scripts", self.create_startup_scripts),
            ("Creating usage guide", self.create_usage_guide)
        ]
        
        for step_name, step_func in steps:
            print(f"\\n📋 {step_name}...")
            if not step_func():
                print(f"❌ Setup failed at: {step_name}")
                return False
        
        print("\\n" + "=" * 50)
        print("🎉 SETUP COMPLETED SUCCESSFULLY!")
        print("=" * 50)
        print("\\nNext steps:")
        print("1. Read README.md for usage instructions")
        print("2. Start POX controller: ./start_pox.sh")
        print("3. Start network simulation: sudo ./start_mininet.sh")
        print("4. Run tests: ./run_tests.sh")
        print("\\nGood luck with your bachelor's project! 🎓")
        
        return True

def main():
    """Main setup function"""
    setup = XSSDetectionSetup()
    setup.run_setup()

if __name__ == "__main__":
    main()