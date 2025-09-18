import json
import sys
import logging
import socket


# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

def extract_ip():
    """
    Attempts to determine the local IP address of the machine.
    Falls back to localhost (127.0.0.1) if network detection fails.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This doesn't actually connect to the internet, just triggers routing
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class currentMode:
    """
    Represents the runtime environment configuration for the application.
    Loads environment-specific credentials and sets runtime properties.
    """
    def __init__(self, myenv):
        self.myenv = myenv
        self.debug = False

        # Load cryptographic key material from `keys.json`
        try:
            with open('keys.json') as f:
                keys = json.load(f)
        except Exception:
            logging.error('Unable to load keys.json — file missing or corrupted.')
            sys.exit(1)

        #self.talao_verifier = keys.get('talao_verifier') # did:web:talao.co#key-6)
        self.smtp_password = keys.get('smtp_password')
        self.QTSP = keys.get('QTSP')

        # Define runtime behavior depending on environment
        if self.myenv == 'aws':
            # Configuration for AWS environment
            #self.port = 4000
            self.sys_path = '/home/admin'
            self.server = 'https://wallet-connectors.com/'
            #self.IP = '13.37.102.193'
        elif self.myenv == 'local':
            # Configuration for local development
            self.sys_path = '/home/thierry'
            self.IP = extract_ip()
            self.server = f'http://{self.IP}:4000/'
            self.port = 4000
        else:
            logging.error('Invalid environment setting. Choose either "aws" or "local".')
            sys.exit(1)
            
    def debug_on(self):
        self.debug = True
        
    def debug_off(self):
        self.debug = False
