from scripts.command_executor import CommandExecutor

executor = CommandExecutor(private_key_path="/data/f2netvpnaccess/ssh/keys")

if executor.connect():
    print("✅ Connected to host.")

    # Content to write
    content = """
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
""".strip()

    # Bash command to write content using sudo + tee
    remote_command = f"echo '{content}' | sudo tee /etc/openvpn/test.conf > /dev/null"

    # Execute
    result = executor.execute_command(remote_command)

    if result['success']:
        print("✅ Config file created successfully.")
    else:
        print("❌ Error:", result['stderr'] or result['error'])

    executor.close()
else:
    print("❌ Failed to connect.")
