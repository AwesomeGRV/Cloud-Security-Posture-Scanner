# Cloud Security Posture Scanner (CSPM)

A comprehensive Azure security scanner that identifies misconfigurations and provides risk assessments across multiple Azure services.

## Features

### Core Security Scanning
- Multi-Resource Support: Scan Storage Accounts, Network Security Groups, Key Vaults, Virtual Machines, and Databricks Workspaces
- Risk Assessment: Advanced risk scoring with severity-based prioritization
- Real-time Monitoring: Live scan progress tracking and status updates
- Comprehensive Reporting: Export findings in JSON and HTML formats

### Security Checks
- Storage Accounts: Public access detection, encryption verification, network access rules
- Network Security Groups: Overly permissive rules, RDP/SSH from internet, port range analysis
- Key Vaults: Firewall configuration, soft delete protection, purge protection
- Compute Resources: Disk encryption, public IP detection, security extensions
- Databricks: Public access controls, secure connectivity, workspace isolation

### User Interface
- Modern Dashboard: React-based web interface with real-time updates
- Interactive Charts: Risk visualization with severity breakdowns
- Report Management: Download, filter, and organize security reports
- Settings Configuration: Customizable scan parameters and preferences

## Architecture

### Backend
- FastAPI: High-performance async REST API
- Azure SDK: Official Azure management clients
- Risk Engine: Advanced scoring algorithms
- Report Generation: Dynamic HTML and JSON reports

### Frontend
- React 18: Modern component-based UI
- TypeScript: Type-safe development
- Tailwind CSS: Responsive design system
- Recharts: Interactive data visualization

### DevOps
- Docker: Containerized deployment
- GitHub Actions: CI/CD pipeline with testing
- Multi-Environment: Staging and production deployments
- Security Scanning: Automated vulnerability detection

## Installation

### Prerequisites
- Python 3.9+
- Node.js 18+
- Azure Subscription with appropriate permissions
- Docker (optional)

### Quick Start

#### Using Docker (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd cloud-security-posture-scanner

# Set up environment
cp .env.example .env
# Edit .env with your Azure credentials

# Run with Docker Compose
docker-compose up -d
```

#### Manual Installation
```bash
# Backend Setup
cd src
pip install -r requirements.txt
uvicorn cspm_scanner.api:app --host 0.0.0.0 --port 8000

# Frontend Setup
cd frontend
npm install
npm start
```

##  Configuration

### Environment Variables
```bash
# Azure Authentication
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id
USE_MANAGED_IDENTITY=false

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false

# Report Configuration
REPORT_OUTPUT_DIR=./reports
MAX_CONCURRENT_SCANS=10
```

### Azure Permissions
Required Azure permissions:
- Reader access on target subscriptions
- Microsoft.Storage/storageAccounts/read
- Microsoft.Network/networkSecurityGroups/read
- Microsoft.KeyVault/vaults/read
- Microsoft.Compute/virtualMachines/read
- Microsoft.Databricks/workspaces/read

##  Usage

### Command Line Interface
```bash
# Scan all subscriptions
cspm-scanner scan

# Scan specific subscription
cspm-scanner scan --subscription <subscription-id>

# List subscriptions
cspm-scanner list-subscriptions

# Generate reports
cspm-scanner scan --format both --output ./reports
```

### REST API
```bash
# Start a scan
curl -X POST "http://localhost:8000/scan/start" \
  -H "Content-Type: application/json" \
  -d '{"subscription_id": "your-subscription-id"}'

# Get scan status
curl "http://localhost:8000/scan/{scan_id}/status"

# Download report
curl "http://localhost:8000/scan/{scan_id}/report?format=html"
```

##  Reports

### Risk Scoring
- **Critical (80-100)**: Immediate attention required
- **High (60-79)**: High-priority remediation
- **Medium (40-59)**: Moderate security risk
- **Low (20-39)**: Low-risk issues
- **Info (0-19)**: Informational findings

### Report Formats
- **HTML**: Interactive dashboard with charts and detailed findings
- **JSON**: Machine-readable format for integration
- **Summary**: High-level overview with key metrics

### Compliance Mapping
Findings are mapped to:
- CIS Controls
- NIST Cybersecurity Framework
- ISO 27001
- SOC 2

##  Security Considerations

### Authentication
- Supports Azure Service Principal authentication
- Managed Identity support for Azure deployments
- Secure credential handling with environment variables

### Data Protection
- No sensitive data stored in application logs
- Encrypted communication with Azure APIs
- Configurable data retention policies

### Network Security
- HTTPS enforcement for API communication
- Network access controls for report downloads
- CORS configuration for web interface

##  Deployment

### Production Deployment
```bash
# Build and push images
docker-compose -f docker-compose.yml build
docker-compose -f docker-compose.yml push

# Deploy to production
docker-compose -f docker-compose.yml up -d
```

### Environment Configuration
- **Development**: Local development with hot reload
- **Staging**: Pre-production testing environment
- **Production**: Scalable deployment with load balancing

### Monitoring
- Application health checks
- Performance metrics collection
- Error tracking and alerting
- Security event logging

## Development

### Local Development Setup
```bash
# Backend Development
cd src
pip install -r requirements.txt
pip install -e .
uvicorn cspm_scanner.api:app --reload

# Frontend Development
cd frontend
npm install
npm start
```

### Testing
```bash
# Backend Tests
pytest src/ --cov=src/cspm_scanner

# Frontend Tests
cd frontend
npm test

# Integration Tests
pytest tests/integration/
```

### Code Quality
- **Type Checking**: Full TypeScript coverage
- **Linting**: ESLint and Pylint configuration
- **Formatting**: Prettier and Black code formatting
- **Pre-commit Hooks**: Automated quality checks

##  API Documentation

### Endpoints
- `GET /health` - Health check
- `GET /subscriptions` - List accessible subscriptions
- `POST /scan/start` - Initiate security scan
- `GET /scan/{id}/status` - Get scan progress
- `GET /scan/{id}/result` - Get scan results
- `GET /scan/{id}/report` - Download scan report
- `GET /reports` - List generated reports

### Response Formats
All API responses follow JSON format with consistent error handling and appropriate HTTP status codes.

## Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Guidelines
- Follow existing code style and patterns
- Add comprehensive tests for new features
- Update documentation for API changes
- Ensure security best practices

## Support

### Documentation
- [API Documentation](docs/api.md)
- [User Guide](docs/user-guide.md)
- [Deployment Guide](docs/deployment.md)

### Issues and Questions
- Create an issue for bug reports
- Check existing issues before creating new ones
- Provide detailed reproduction steps for bugs

### Community
- Join our Discord community
- Follow on Twitter for updates
- Star the repository if you find it useful

---

**Built with ❤️ for the Azure security community**
