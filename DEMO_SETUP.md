# Demo Setup Guide

## Prerequisites
- Python 3.9+ installed
- Node.js 18+ installed
- Azure Subscription with appropriate permissions
- Azure credentials (Client ID, Client Secret, Tenant ID)

## Quick Demo Setup

### Step 1: Backend Setup
```bash
# Navigate to project root
cd "c:\Users\Gaurav Mishra\Downloads\Cloud Security Posture Scanner"

# Install Python dependencies
pip install -r requirements.txt

# Set up environment variables (copy .env.example to .env)
cp .env.example .env
# Edit .env with your Azure credentials

# Start backend server
cd src
uvicorn cspm_scanner.api:app --host 0.0.0.0 --port 8000 --reload
```

### Step 2: Frontend Setup
```bash
# Open new terminal
cd "c:\Users\Gaurav Mishra\Downloads\Cloud Security Posture Scanner\frontend"

# Install frontend dependencies
npm install

# Start frontend development server
npm start
```

### Step 3: Access the Application

1. **Backend API**: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

2. **Frontend App**: http://localhost:3000
   - Main dashboard interface
   - All pages accessible via navigation

### Step 4: Demo Workflow

1. **Configure Azure Credentials**
   - Edit `.env` file with your Azure Service Principal details:
   ```
   AZURE_CLIENT_ID=your-client-id
   AZURE_CLIENT_SECRET=your-client-secret
   AZURE_TENANT_ID=your-tenant-id
   ```

2. **Start Security Scan**
   - Navigate to "Scan" page in frontend
   - Select Azure subscription
   - Choose resource types to scan
   - Set severity threshold
   - Click "Start Scan"

3. **Monitor Progress**
   - Watch real-time scan progress
   - View scan logs and status updates
   - Navigate to "Activity" page for scan history

4. **Review Results**
   - Check "Dashboard" for risk overview
   - View detailed findings in "Reports" section
   - Download HTML/JSON reports

## Docker Demo (Alternative)

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access services
# Frontend: http://localhost:3000
# Backend: http://localhost:8000
# Nginx (reverse proxy): http://localhost:80
```

## Demo Features to Showcase

### 🔍 Security Scanning
- Multi-resource scanning (Storage, NSG, Key Vault, VMs, Databricks)
- Real-time scan progress tracking
- Configurable severity thresholds

### 📊 Risk Assessment
- Overall risk scoring (0-100 scale)
- Severity-based findings classification
- Interactive charts and visualizations

### 📈 Reporting
- HTML reports with interactive charts
- JSON reports for API integration
- Historical scan tracking

### 🎯 Key Demo Points

1. **Real-time Scanning**: Show live scan progress
2. **Risk Visualization**: Display risk scores and severity breakdowns
3. **Comprehensive Reporting**: Generate detailed security reports
4. **Multi-Subscription Support**: Scan multiple Azure subscriptions
5. **Responsive Design**: Works on desktop and mobile

## Troubleshooting

### Common Issues
1. **Azure Authentication**: Ensure Service Principal has Reader permissions
2. **Network Issues**: Check firewall settings for ports 8000/3000
3. **Missing Dependencies**: Run `pip install -r requirements.txt` and `npm install`

### Logs Location
- Backend logs: Console output or `logs/` directory
- Frontend logs: Browser developer console

## Production Demo
For production deployment:
```bash
# Build and deploy
docker-compose -f docker-compose.yml up -d
```

This setup provides a complete demonstration of the Cloud Security Posture Scanner's capabilities.
