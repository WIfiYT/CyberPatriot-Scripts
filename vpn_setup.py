import subprocess
import sys

class VPNManager:
    def __init__(self, config_file):
        self.config_file = config_file

    def start_vpn(self):
        print(f"Starting VPN using {self.config_file}")
        subprocess.run(['vpn_command', '-f', self.config_file])

    def stop_vpn(self):
        print("Stopping VPN")
        subprocess.run(['vpn_command', '-k'])

    def get_status(self):
        print("Checking VPN status...")
        result = subprocess.run(['vpn_command', '-s'], capture_output=True, text=True)
        print(result.stdout)

    def configure_vpn(self, new_config):
        print(f"Configuring VPN with new settings: {new_config}")
        with open(self.config_file, 'w') as f:
            f.write(new_config)

if __name__ == '__main__':
    manager = VPNManager('vpn_config.yml')

    if len(sys.argv) < 2:
        print("Usage: vpn_setup.py [start|stop|status|configure]")
        sys.exit(1)

    action = sys.argv[1]

    if action == 'start':
        manager.start_vpn()
    elif action == 'stop':
        manager.stop_vpn()
    elif action == 'status':
        manager.get_status()
    elif action == 'configure':
        if len(sys.argv) < 3:
            print("Please provide new configuration.")
            sys.exit(1)
        new_config = sys.argv[2]
        manager.configure_vpn(new_config)
    else:
        print(f"Unknown action: {action}")