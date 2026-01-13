from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import json
from datetime import datetime

app = FastAPI(title="CSPM Demo API", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Mock data models
class Subscription(BaseModel):
    id: str
    name: str
    display_name: str

class ScanRequest(BaseModel):
    subscription_id: Optional[str] = None
    resource_types: Optional[List[str]] = None
    severity_threshold: Optional[str] = "low"

class ScanStartResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class SecurityFinding(BaseModel):
    id: str
    title: str
    severity: str
    resource_type: str
    resource_id: str
    description: str
    recommendation: str

class ScanResult(BaseModel):
    subscription_id: str
    subscription_name: Optional[str] = None
    scan_timestamp: str
    total_resources_scanned: int
    total_findings: int
    findings_by_severity: dict
    findings: List[SecurityFinding]
    risk_score: int
    scan_duration_seconds: Optional[int] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    started_at: str
    completed_at: Optional[str] = None
    error_message: Optional[str] = None

class Report(BaseModel):
    id: str
    scan_id: str
    format: str
    created_at: str
    file_size: int

class ReportStatistics(BaseModel):
    total_reports: int
    total_size: int
    latest_report: str

# Mock data
mock_subscriptions = [
    {"id": "sub-001", "name": "Production", "display_name": "Production Subscription"},
    {"id": "sub-002", "name": "Development", "display_name": "Development Subscription"},
]

mock_findings = [
    {
        "id": "finding-001",
        "title": "Storage Account Public Access",
        "severity": "high",
        "resource_type": "storage",
        "resource_id": "/subscriptions/sub-001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
        "description": "Storage account allows public blob access",
        "recommendation": "Disable public blob access and use private endpoints"
    },
    {
        "id": "finding-002", 
        "title": "NSG Allows RDP from Internet",
        "severity": "medium",
        "resource_type": "network",
        "resource_id": "/subscriptions/sub-001/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
        "description": "Network Security Group allows RDP access from any IP",
        "recommendation": "Restrict RDP access to specific IP ranges"
    }
]

# API Endpoints
@app.options("/scan/start")
async def options_scan_start():
    return {"message": "OK"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/subscriptions", response_model=List[Subscription])
async def get_subscriptions():
    return mock_subscriptions

@app.post("/scan/start", response_model=ScanStartResponse)
async def start_scan(scan_request: ScanRequest):
    scan_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    return {
        "scan_id": scan_id,
        "status": "running",
        "message": "Scan started successfully"
    }

@app.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    return {
        "scan_id": scan_id,
        "status": "completed",
        "progress": 100,
        "started_at": "2024-01-01T00:00:00Z",
        "completed_at": "2024-01-01T00:30:00Z"
    }

@app.get("/scan/{scan_id}/result", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    findings_by_severity = {"high": 1, "medium": 1}
    return {
        "subscription_id": "sub-001",
        "subscription_name": "Production Subscription",
        "scan_timestamp": datetime.now().isoformat(),
        "total_resources_scanned": 25,
        "total_findings": len(mock_findings),
        "findings_by_severity": findings_by_severity,
        "risk_score": 75,
        "scan_duration_seconds": 180,
        "findings": mock_findings
    }

@app.get("/scans", response_model=List[ScanStatus])
async def list_scans():
    return [
        {
            "scan_id": "scan-20240101000000",
            "status": "completed",
            "progress": 100,
            "started_at": "2024-01-01T00:00:00Z",
            "completed_at": "2024-01-01T00:30:00Z"
        },
        {
            "scan_id": "scan-20240101120000",
            "status": "completed", 
            "progress": 100,
            "started_at": "2024-01-01T12:00:00Z",
            "completed_at": "2024-01-01T12:30:00Z"
        }
    ]

@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    return {"message": f"Scan {scan_id} deleted successfully"}

@app.get("/scan/{scan_id}/report")
async def download_scan_report(scan_id: str, format: str = 'json'):
    if format == 'html':
        return {"message": "HTML report download", "content": "<html><body>Sample Report</body></html>"}
    else:
        return {"message": "JSON report download", "data": mock_findings}

@app.get("/reports")
async def list_reports():
    return {
        "reports": [
            {
                "id": "report-001",
                "scan_id": "scan-20240101000000",
                "format": "html",
                "created_at": "2024-01-01T00:30:00Z",
                "file_size": 1024000
            },
            {
                "id": "report-002",
                "scan_id": "scan-20240101120000",
                "format": "json",
                "created_at": "2024-01-01T12:30:00Z",
                "file_size": 512000
            }
        ],
        "statistics": {
            "total_reports": 2,
            "total_size": 1536000,
            "latest_report": "2024-01-01T12:30:00Z"
        }
    }

@app.get("/reports/{filename}")
async def download_report(filename: str):
    return {"message": f"Report {filename} download started"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
