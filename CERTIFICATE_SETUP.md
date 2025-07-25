# Certificate Setup Guide

Cookie Proxy requires a trusted Certificate Authority (CA) to generate HTTPS certificates dynamically. This guide covers setup for different platforms and browsers.

## Quick Start

**The proxy automatically uses your mkcert CA if available.** If you already have mkcert installed and working, just run:

```bash
./cookie-proxy -d your-domain.com --log-level debug
```

Skip to [Browser Setup](#browser-setup) below.

## Installing mkcert

[mkcert](https://github.com/FiloSottile/mkcert) is a tool for creating locally-trusted development certificates.

### macOS
```bash
# Using Homebrew
brew install mkcert

# Install the CA in system trust store
mkcert -install
```

### Windows
```bash
# Using Chocolatey
choco install mkcert

# Or using Scoop
scoop bucket add extras
scoop install mkcert

# Install the CA in system trust store
mkcert -install
```

### Linux
```bash
# Ubuntu/Debian
sudo apt install libnss3-tools
wget -O mkcert https://dl.filippo.io/mkcert/latest?for=linux/amd64
chmod +x mkcert
sudo mv mkcert /usr/local/bin/

# Install the CA in system trust store
mkcert -install
```

## Browser Setup

### Chrome, Safari, Edge (System Trust Store)
These browsers use the system certificate store. If you ran `mkcert -install`, **no additional setup needed**.

### Firefox (Manual Import Required)
Firefox uses its own certificate store and requires manual import:

#### macOS/Linux
1. **Find your mkcert CA:**
   ```bash
   mkcert -CAROOT
   # Example output: /Users/username/Library/Application Support/mkcert
   ```

2. **Firefox Settings** → **Privacy & Security**
3. Scroll to **Certificates** → click **View Certificates**
4. **Authorities** tab → click **Import...**
5. Navigate to the CA root directory and select `rootCA.pem`
6. Check **"Trust this CA to identify websites"**
7. Click **OK** and **restart Firefox**

#### Windows
1. **Find your mkcert CA:**
   ```cmd
   mkcert -CAROOT
   # Example output: C:\Users\username\AppData\Local\mkcert
   ```

2. Follow the same Firefox import steps above, selecting `rootCA.pem` from the CA root directory.

## Proxy Setup

### Default (Automatic mkcert Detection)
```bash
./cookie-proxy -d saas.example.com
```
The proxy automatically finds and uses your mkcert CA.

### Custom CA Certificate
```bash
./cookie-proxy -d saas.example.com \
  --ca-cert /path/to/your-ca.pem \
  --ca-key /path/to/your-ca-key.pem
```

### Multiple Domains
```bash
./cookie-proxy -d api.example.com,auth.example.com
```

## Browser Proxy Configuration

Configure your browser to use automatic proxy configuration:
```
http://localhost:8080/proxy.pac
```

**Firefox:**
1. **Settings** → **General** → **Network Settings** → **Settings**
2. Select **Automatic proxy configuration URL**
3. Enter: `http://localhost:8080/proxy.pac`
4. **OK** and **restart Firefox completely**

**Chrome/Safari:**
- Use system proxy settings or browser-specific proxy configuration
- Set automatic proxy URL to: `http://localhost:8080/proxy.pac`
- **Restart browser completely** after proxy configuration changes

**Important:** PAC configuration changes require a **full browser restart** to take effect. Simply reloading tabs is not sufficient.

## Verification

1. Start the proxy:
   ```bash
   ./cookie-proxy -d your-domain.com --log-level debug
   ```

2. You should see:
   ```
   INFO CA certificate loaded for dynamic cert generation
   INFO HTTPS MITM enabled with dynamic certificate generation
   INFO Starting HTTPS cookie proxy pac_url=http://127.0.0.1:8080/proxy.pac
   ```

3. Visit `https://your-domain.com` in your browser
4. You should see:
   ```
   DEBUG Generating certificate for domain domain=your-domain.com
   DEBUG Generated and cached certificate domain=your-domain.com
   ```

5. **No certificate warnings** should appear in your browser

## Troubleshooting

### "Unknown Certificate" Error
- **Chrome/Safari:** Run `mkcert -install` to add CA to system trust store
- **Firefox:** Manually import the CA certificate as described above
- **Custom CA:** Verify the CA certificate paths are correct

### "mkcert CA not found" Error
- Install mkcert: `brew install mkcert` (macOS) or equivalent for your platform
- Run `mkcert -install` to create the CA
- Or provide custom CA with `--ca-cert` and `--ca-key` flags

### Certificate Still Not Trusted
- **Restart your browser** after importing certificates
- **Check CA location:** Run `mkcert -CAROOT` to verify the CA location
- **Firefox:** Ensure you checked "Trust this CA to identify websites" during import

### WSL2 Setup

WSL2 requires special networking configuration for Windows browsers to access the proxy.

#### Certificate Setup
1. **Install mkcert inside WSL2:**
   ```bash
   # Ubuntu/Debian in WSL2
   sudo apt install libnss3-tools
   wget -O mkcert https://dl.filippo.io/mkcert/latest?for=linux/amd64
   chmod +x mkcert && sudo mv mkcert /usr/local/bin/
   mkcert -install
   ```

2. **Share CA certificate with Windows:**
   ```bash
   # Find WSL2 CA location
   mkcert -CAROOT
   # Copy to Windows accessible location
   cp $(mkcert -CAROOT)/rootCA.pem /mnt/c/temp/wsl2-rootCA.pem
   ```

3. **Import in Windows browsers:**
   - **Chrome/Edge:** Import `C:\temp\wsl2-rootCA.pem` into Windows certificate store
   - **Firefox:** Import the same file manually in Firefox certificate settings

#### Proxy Binding Methods

**Proper method (recommended):**
```bash
# Find WSL2 IP that Windows can reach
WSL_IP=$(hostname -I | awk '{print $1}')
echo "WSL2 IP: $WSL_IP"

# Start proxy bound to WSL2 IP
./cookie-proxy --domains api.example.com --bind-address $WSL_IP

# Configure Windows browser with: http://WSL_IP:8080/proxy.pac
```

**Easy method (security trade-off):**
```bash
# Bind to all interfaces (accessible from Windows)
./cookie-proxy --domains api.example.com --bind-address 0.0.0.0

# Configure Windows browser with: http://localhost:8080/proxy.pac
# WARNING: Proxy accessible to entire network
```

#### Verification
```bash
# From WSL2, test proxy is accessible from Windows
curl -I http://$WSL_IP:8080/proxy.pac
# Should return 200 OK with PAC content-type
```

## Local Development Server Setup

For testing the proxy with your frontend, you'll need an HTTPS development server using the same mkcert certificates.

### Using http-server with mkcert

```bash
# Generate certificates for your local domain
mkcert localhost 127.0.0.1 your-domain.local

# Install http-server globally if not already installed
npm install -g http-server

# Start HTTPS server with CORS enabled
npx http-server . -S -C localhost+2.pem -K localhost+2-key.pem -p 3000 --cors

# Alternative with specific domain
npx http-server . -S -C your-domain.local.pem -K your-domain.local-key.pem -p 3000 --cors
```

**Parameters explained:**
- `-S`: Enable HTTPS
- `-C`: Certificate file path
- `-K`: Private key file path  
- `-p 3000`: Port (adjust as needed)
- `--cors`: Enable CORS headers (crucial for cross-origin requests)

### Using Vite with mkcert

```bash
# Generate certificates
mkcert localhost

# Add to vite.config.js
import { defineConfig } from 'vite'
import fs from 'fs'

export default defineConfig({
  server: {
    https: {
      key: fs.readFileSync('./localhost-key.pem'),
      cert: fs.readFileSync('./localhost.pem'),
    },
    host: 'localhost',
    port: 3000,
    cors: true
  }
})
```

### Using webpack-dev-server

```bash
# Generate certificates  
mkcert localhost

# Start with HTTPS and CORS
npx webpack serve --https --https-key ./localhost-key.pem --https-cert ./localhost.pem --host localhost --port 3000
```

### Complete Development Setup

1. **Generate certificates for both proxy and dev server:**
   ```bash
   # For your API domain (proxy will intercept)
   mkcert api.yourdomain.com
   
   # For your local frontend
   mkcert localhost 127.0.0.1
   ```

2. **Start your frontend dev server:**
   ```bash
   npx http-server . -S -C localhost+2.pem -K localhost+2-key.pem -p 3000 --cors
   ```

3. **Start the cookie proxy:**
   ```bash
   ./cookie-proxy --domains api.yourdomain.com
   ```

4. **Configure browser proxy:** `http://localhost:8080/proxy.pac`

5. **Test the flow:**
   - Visit `https://localhost:3000` (your frontend)
   - Make requests to `https://api.yourdomain.com` (gets proxied)
   - Login flow captures cookies automatically

### Troubleshooting Development Setup

**CORS Issues:** Always use `--cors` flag with http-server or equivalent CORS configuration in your dev server.

**Mixed Content:** Ensure both your frontend and API endpoints use HTTPS to avoid mixed content warnings.

**Certificate Mismatch:** Use the exact same domain names in both mkcert certificate generation and your application URLs.

## Security Notes

- **Development use only:** Never use these certificates in production
- **CA security:** The CA private key can sign certificates for any domain
- **Firefox isolation:** Firefox's separate certificate store provides additional security isolation
- **Temporary certificates:** Generated certificates are cached in memory only and cleared on restart