import os
import uuid

def generate_vault():
    vault_dir = "doomsday_vault"
    os.makedirs(vault_dir, exist_ok=True)
    print(f"[*] Building {vault_dir}...")

    # 1. The Minified Nightmare (Single Line, 2MB+)
    print("[*] Generating massive minified JS...")
    with open(f"{vault_dir}/1_massive_minified.js", "w") as f:
        f.write("const appData={")
        for i in range(100):
            f.write(f'trap{i}:"sk_live_12345678901234567890123",')
        for i in range(10000):
            f.write(f'id{i}:"{uuid.uuid4()}",')
        f.write('github_token:"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",')
        for i in range(10000):
            f.write(f'id_more{i}:"{uuid.uuid4()}",')
        f.write("};")

    # 2. The SQL Dump (10MB+)
    print("[*] Generating 10MB SQL Dump...")
    with open(f"{vault_dir}/2_db_dump.sql", "w") as f:
        for i in range(20000):
            f.write(f"INSERT INTO users (id, aws_key) VALUES ('{uuid.uuid4()}', 'AKIA1234567890EXAMP');\n")
        f.write("INSERT INTO secrets (id, b64_payload) VALUES ('99999', 'QUtJQUlPU0ZPRE5ON0VYQU1QTEU=');\n")
        for i in range(5000):
            f.write(f"INSERT INTO logs (id, data) VALUES ('{uuid.uuid4()}', 'routine_log_entry');\n")

    # 3. The Constants Bait (YML)
    print("[*] Generating Config with Regex Baits...")
    with open(f"{vault_dir}/3_app_config.yml", "w") as f:
        f.write("android_permissions:\n")
        f.write("  - REQUEST_IGNORE_BATTERY_OPTIMIZATIONS\n")
        f.write("variables:\n")
        f.write("  - sg.messageId\n")
        f.write("  - SG.DeviceManager\n")
        f.write("ssl_cert: |\n")
        f.write("  -----BEGIN RSA PRIVATE KEY-----\n")
        f.write("  MIIEpQIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjnXDFDSFDSFDSFDSFDSFDSFDSFDSFD\n")
        f.write("  -----END RSA PRIVATE KEY-----\n")

    print("[✔] Doomsday Vault Generated successfully.")

if __name__ == "__main__":
    generate_vault()
