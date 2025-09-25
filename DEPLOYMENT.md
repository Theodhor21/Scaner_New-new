# Deployment Guide

## Quick Start

### Option 1: Using the Startup Script (Recommended)
```bash
chmod +x start.sh
./start.sh
```

### Option 2: Manual Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start application
python3 pentest_app.py
```

## Production Deployment

### Using Gunicorn (Recommended for Production)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 pentest_app:app
```

### Using Docker
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python3", "pentest_app.py"]
```

### Nginx Configuration
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Considerations

1. **Network Isolation**: Deploy in isolated network environment
2. **Access Control**: Implement authentication for web interface
3. **SSL/TLS**: Use HTTPS in production environments
4. **Firewall Rules**: Restrict access to necessary ports only
5. **Regular Updates**: Keep dependencies updated for security patches

## System Requirements

- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB free space minimum
- **Network**: Reliable internet connection for target testing
- **OS**: Linux, macOS, or Windows with Python 3.8+
