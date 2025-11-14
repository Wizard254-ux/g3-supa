import paramiko
import os
import logging
logging.getLogger("paramiko").setLevel(logging.WARNING)

class CommandExecutor:
    def __init__(self, private_key_path, host=None, username=None):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        # Use current container username if none provided
        self.username = username or os.environ.get('HOST_USER', 'root')
        self.private_key_path = private_key_path

    def connect(self):
        """Connect to the host machine"""
        try:
            self.client.connect(
                hostname=self.host,
                username=self.username,
                key_filename=self.private_key_path,
                timeout=10
            )
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False

    def execute_command(self, command):
        """Execute a system command on the host machine"""
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()

            return {
                'success': exit_code == 0,
                'stdout': stdout.read().decode('utf-8'),
                'stderr': stderr.read().decode('utf-8'),
                'exit_code': exit_code
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'exit_code': -1
            }

    def close(self):
        """Close the SSH connection"""
        self.client.close()