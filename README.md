# Lightweight Remote Command (RC)

A lightweight, secure, encrypted remote command server and client written in Python. It provides a full interactive Windows shell (CMD) over TLS 1.2+ with firewall-bypassing capabilities via a relay server.

## Features

- **End-to-End Encryption**: Every connection uses TLS 1.2+
- **Secure Authentication**: PBKDF2-HMAC-SHA256 password hashing with brute-force protection
- **Interactive Shell**: Full streaming support for interactive command line tools (diskpart, python REPL, ftp, etc.)
- **Firewall Bypass**: Three connection strategies to handle any network topology:
  - **Direct**: Standard client-to-server connection
  - **Reverse**: Server connects out to the client (bypasses server inbound firewalls)
  - **Relay**: Both server and client connect to a public relay (bypasses firewalls on both sides)
- **Windows Service**: Server can install and run as a background Windows Service with SYSTEM privileges.

## Quick Start (Direct Mode)

### Automated Installation (Windows Server)

For the easiest setup on a Windows machine, run the installer as Administrator:
```cmd
install.bat
```
This will automatically:
1. Install Python dependencies
2. Generate TLS certificates (`server.crt`, `server.key`)
3. Prompt you to set a secure password
4. Install and start the server as a background Windows Service
5. Launch the watermark indicator

To cleanly uninstall everything later, run `uninstall.bat` as Administrator.

### Manual Setup (Cross-Platform / Debug)

1. Generate TLS certificates:
   ```cmd
   python gen_certs.py
   ```
2. Setup server password:
   ```cmd
   python setup_password.py
   ```
3. Start the server (runs in foreground):
   ```cmd
   python server.py run
   ```
4. Connect the client (from any machine):
   ```cmd
   python client.py --host 127.0.0.1 --cert server.crt
   ```
5. Test the connection:
   ```cmd
   python test.py
   ```

## Setting up Relay Mode on Google Cloud Platform (GCP)

Relay mode is useful when both the server and the client are behind strict firewalls and cannot accept incoming connections. 

💡 **Tip:** You can host the relay server completely for free using [Google Cloud's Free Tier](https://cloud.google.com/free), which provides an `e2-micro` VM instance perpetually for free.

### 1 — Open the firewall port on GCP

Go to **GCP Console → VPC network → Firewall → Create Firewall Rule**:

| Field | Value |
|---|---|
| Name | `rc-relay` |
| Direction | Ingress |
| Action | Allow |
| Targets | All instances in network |
| Source IP ranges | `0.0.0.0/0` |
| Protocols and ports | TCP `443` |

Click **Create**.

### 2 — SSH into your VM

In GCP Console, go to **Compute Engine → VM instances → SSH** (click the button).

### 3 — Register `relay.py` as a systemd service on GCP

SSH into your VM and run these commands one by one:

**1. Move relay.py to a permanent location**
```bash
sudo apt install -y python3
sudo mkdir -p /opt/rc-relay
```
*Upload `relay.py` (In the SSH window, click the **gear icon → Upload file**, and upload `relay.py`)*
```bash
sudo cp ~/relay.py /opt/rc-relay/relay.py
```

**2. Create the service file**
```bash
sudo nano /etc/systemd/system/rc-relay.service
```
Paste this into nano, then press `Ctrl+O` → `Enter` → `Ctrl+X` to save:
```ini
[Unit]
Description=Remote Command Relay Server
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/rc-relay/relay.py --port 443
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**3. Enable and start**
```bash
sudo systemctl daemon-reload
sudo systemctl enable rc-relay    # auto-start on boot
sudo systemctl start rc-relay     # start right now
```

**4. Verify it's running**
```bash
sudo systemctl status rc-relay
```
After this, the relay survives SSH disconnect, reboots automatically, and restarts itself if it crashes. You never need to SSH in again.

### 4 — Get the VM's external IP

On the **VM instances** page, the **External IP** column shows it. Copy that IP.

### 5 — Configure your Windows Server

Edit `config.json` on the server machine:
```json
{
  "mode": "relay",
  "relay_host": "PASTE-GCP-IP-HERE",
  "relay_port": 443,
  "relay_token": "session01"
}
```
*(Ensure you also have your certificates and password configured)*

### 6 — Connect from your Client PC

```cmd
python client.py --relay PASTE-GCP-IP-HERE:443 --relay-token session01 --cert server.crt
```

## Security Note
Keep your `server.key`, `config.json` (contains password hashes), and `blacklist.json` secure. The `server.crt` is safe to distribute to clients.
