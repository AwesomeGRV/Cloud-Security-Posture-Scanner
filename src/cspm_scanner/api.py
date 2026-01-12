"""FastAPI REST API for CSPM Scanner."""

import asyncio
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .models import ScanRequest, ScanResult, ScanStatus, ResourceType, SeverityLevel
from .scanner_engine import scanner_engine
from .reports.report_generator import ReportGenerator
from .auth import auth_manager
from .config import settings


# FastAPI app instance
app = FastAPI(
    title="Cloud Security Posture Scanner API",
    description="Azure security scanner API for detecting misconfigurations",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global scan tracking
active_scans: Dict[str, ScanStatus] = {}
report_generator = ReportGenerator(settings.report_output_dir)


class ScanStartResponse(BaseModel):
    """Response for scan start request."""
    scan_id: str
    status: str
    message: str


class SubscriptionInfo(BaseModel):
    """Subscription information model."""
    id: str
    display_name: str
    tenant_id: str
    state: str


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint."""
    return {
        "message": "Cloud Security Posture Scanner API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/subscriptions", response_model=List[SubscriptionInfo])
async def list_subscriptions():
    """List all accessible Azure subscriptions."""
    try:
        subscriptions = auth_manager.list_subscriptions()
        return [
            SubscriptionInfo(**sub) for sub in subscriptions
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/start", response_model=ScanStartResponse)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Start a new security scan."""
    try:
        # Validate scan request
        validation = await scanner_engine.validate_scan_request(scan_request)
        if not validation["valid"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid scan request: {'; '.join(validation['errors'])}"
            )
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan status
        scan_status = ScanStatus(
            scan_id=scan_id,
            status="pending",
            progress=0
        )
        active_scans[scan_id] = scan_status
        
        # Start background scan
        background_tasks.add_task(
            run_background_scan,
            scan_id,
            scan_request
        )
        
        return ScanStartResponse(
            scan_id=scan_id,
            status="started",
            message="Scan started successfully"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get status of a running scan."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return active_scans[scan_id]


@app.get("/scan/{scan_id}/result", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    """Get result of a completed scan."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_status = active_scans[scan_id]
    
    if scan_status.status != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Scan not completed. Current status: {scan_status.status}"
        )
    
    # Return the stored result (would need to store results in practice)
    if not hasattr(scan_status, 'result'):
        raise HTTPException(status_code=404, detail="Scan result not available")
    
    return scan_status.result


@app.get("/scan/{scan_id}/report")
async def download_scan_report(
    scan_id: str, 
    format: str = Query("json", regex="^(json|html)$")
):
    """Download scan report in specified format."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_status = active_scans[scan_id]
    
    if scan_status.status != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Scan not completed. Current status: {scan_status.status}"
        )
    
    if not hasattr(scan_status, 'result'):
        raise HTTPException(status_code=404, detail="Scan result not available")
    
    try:
        # Generate report
        if format == "json":
            report_file = report_generator.generate_json_report(scan_status.result)
        elif format == "html":
            report_file = report_generator.generate_html_report(scan_status.result)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        return FileResponse(
            report_file,
            media_type="application/octet-stream",
            filename=f"scan_report_{scan_id}.{format}"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans", response_model=List[ScanStatus])
async def list_scans():
    """List all scans (active and recent)."""
    return list(active_scans.values())


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its results."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del active_scans[scan_id]
    return {"message": "Scan deleted successfully"}


@app.get("/reports")
async def list_reports():
    """List all generated reports."""
    try:
        reports = report_generator.list_reports()
        return {
            "reports": reports,
            "statistics": report_generator.get_report_statistics()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports/{filename}")
async def download_report(filename: str):
    """Download a specific report file."""
    try:
        file_path = f"{settings.report_output_dir}/{filename}"
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(
            file_path,
            media_type="application/octet-stream",
            filename=filename
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/reports/cleanup")
async def cleanup_old_reports(days_to_keep: int = Query(30, ge=1)):
    """Clean up old reports."""
    try:
        deleted_count = report_generator.cleanup_old_reports(days_to_keep)
        return {
            "message": f"Cleaned up {deleted_count} old reports",
            "deleted_count": deleted_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/resource-types", response_model=List[str])
async def get_supported_resource_types():
    """Get list of supported resource types for scanning."""
    return [rt.value for rt in scanner_engine.get_supported_resource_types()]


@app.get("/severity-levels", response_model=List[str])
async def get_severity_levels():
    """Get list of severity levels."""
    return [level.value for level in SeverityLevel]


async def run_background_scan(scan_id: str, scan_request: ScanRequest):
    """Run scan in background and update status."""
    try:
        # Update status to running
        active_scans[scan_id].status = "running"
        active_scans[scan_id].progress = 10
        
        # Determine subscription to scan
        subscription_id = scan_request.subscription_id
        if not subscription_id:
            # Scan all subscriptions if none specified
            scan_result = await scanner_engine.scan_all_subscriptions(scan_request)
        else:
            scan_result = await scanner_engine.scan_subscription(subscription_id, scan_request)
        
        # Update progress
        active_scans[scan_id].progress = 90
        
        # Store result
        active_scans[scan_id].result = scan_result
        
        # Mark as completed
        active_scans[scan_id].status = "completed"
        active_scans[scan_id].progress = 100
        active_scans[scan_id].completed_at = datetime.utcnow()
        
        # Generate reports automatically
        try:
            report_generator.generate_all_reports(scan_result)
        except Exception as e:
            print(f"Error generating reports: {str(e)}")
        
    except Exception as e:
        # Mark as failed
        active_scans[scan_id].status = "failed"
        active_scans[scan_id].error_message = str(e)
        active_scans[scan_id].completed_at = datetime.utcnow()


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    # Create reports directory
    import os
    os.makedirs(settings.report_output_dir, exist_ok=True)
    
    print(f"CSPM Scanner API started on {settings.api_host}:{settings.api_port}")
    print(f"Reports directory: {settings.report_output_dir}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("CSPM Scanner API shutting down...")


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "details": str(exc)
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "cspm_scanner.api:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
