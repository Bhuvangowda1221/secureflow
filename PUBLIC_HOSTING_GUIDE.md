# 🌐 SecureFlow Public Hosting Guide

## Current Status
✅ SecureFlow is running on: **http://localhost:5000**
✅ Local network access: **http://192.168.156.214:5000**

---

## Option 1: Using Ngrok (Easiest - 5 minutes)

### Step 1: Download Ngrok
1. Go to: https://ngrok.com/download
2. Download the Windows version
3. Extract the `ngrok.exe` file to your Desktop or SecureFlow folder

### Step 2: Get Free Account (Optional but Recommended)
1. Sign up at: https://dashboard.ngrok.com/signup
2. Copy your authtoken from: https://dashboard.ngrok.com/get-started/your-authtoken
3. Run in terminal: `ngrok config add-authtoken YOUR_TOKEN_HERE`

### Step 3: Start Ngrok Tunnel
Open a new PowerShell/CMD window and run:
```bash
cd C:\Users\bhuva\OneDrive\Desktop\secure_flow
ngrok http 5000
```

### Step 4: Get Your Public URL
Ngrok will show you a URL like:
```
Forwarding   https://xxxx-xxxx-xxxx.ngrok-free.app -> http://localhost:5000
```

**Share this URL with anyone** - they can access SecureFlow from anywhere in the world!

### Important Notes:
- Keep the ngrok window open while using the public URL
- Free ngrok URLs change each time you restart
- Paid ngrok ($8/month) gives you a permanent custom domain

---

## Option 2: Using Localhost.run (No Installation)

Just run this command in a new PowerShell:
```bash
ssh -R 80:localhost:5000 localhost.run
```

You'll get a public URL instantly! No sign-up required.

---

## Option 3: Cloud Deployment (Permanent Free Hosting)

### A) Render.com (Recommended - Free Forever)
1. Go to: https://render.com
2. Sign up for free account
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Deploy automatically

**Free tier includes:**
- Custom domain: `your-app.onrender.com`
- HTTPS included
- Auto-deploy on git push
- 750 hours/month free

### B) Railway.app (Easy Deploy)
1. Go to: https://railway.app
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Railway will auto-detect Flask and deploy

**Free tier:**
- $5 free credit monthly
- Custom domain
- HTTPS included

### C) Heroku (Classic Option)
```bash
# Install Heroku CLI first
heroku login
heroku create secureflow-yourname
git push heroku main
```

---

## Option 4: Your Own VPS (Advanced)

Deploy to DigitalOcean, AWS, Azure, or Google Cloud:

### Quick Deploy to DigitalOcean:
1. Create a Droplet (Ubuntu 22.04) - $6/month
2. SSH into server
3. Clone your repo
4. Run:
```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx -y
cd /var/www
git clone your-repo
cd secure_flow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

5. Configure nginx to proxy to port 5000
6. Get free SSL with Let's Encrypt

---

## Current Access URLs

| Location | URL | Status |
|----------|-----|--------|
| Your Computer | http://localhost:5000 | ✅ Running |
| Same Wi-Fi Network | http://192.168.156.214:5000 | ✅ Available |
| Public Internet | Setup ngrok or cloud | ⏳ Pending |

---

## Quick Commands

**Check if SecureFlow is running:**
```bash
curl http://localhost:5000/api/health
```

**Access from mobile on same Wi-Fi:**
```
Open browser: http://192.168.156.214:5000
```

**Login credentials:**
```
Email: admin@secureflow.local
Password: Admin@SecureFlow1
```

---

## Recommended Choice

For quick testing: **Ngrok** (5 minutes, free)
For permanent hosting: **Render.com** (free forever, custom domain)

Need help with any of these? Let me know!
