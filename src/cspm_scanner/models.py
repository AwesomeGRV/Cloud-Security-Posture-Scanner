"""Data models for CSPM Scanner."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResourceType(str, Enum):
    """Azure resource types."""
    STORAGE_ACCOUNT = "Microsoft.Storage/storageAccounts"
    NETWORK_SECURITY_GROUP = "Microsoft.Network/networkSecurityGroups"
    KEY_VAULT = "Microsoft.KeyVault/vaults"
    VIRTUAL_MACHINE = "Microsoft.Compute/virtualMachines"
    DISK = "Microsoft.Compute/disks"
    DATABRICKS_WORKSPACE = "Microsoft.Databricks/workspaces"


class SecurityFinding(BaseModel):
    """Individual security finding."""
    id: str = Field(..., description="Unique finding identifier")
    resource_id: str = Field(..., description="Azure resource ID")
    resource_name: str = Field(..., description="Resource name")
    resource_type: ResourceType = Field(..., description="Resource type")
    subscription_id: str = Field(..., description="Azure subscription ID")
    resource_group: str = Field(..., description="Resource group name")
    location: str = Field(..., description="Azure region")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description")
    severity: SeverityLevel = Field(..., description="Finding severity")
    recommendation: str = Field(..., description="Remediation recommendation")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score (0-100)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanResult(BaseModel):
    """Complete scan result for a subscription."""
    subscription_id: str = Field(..., description="Scanned subscription ID")
    subscription_name: Optional[str] = Field(None, description="Subscription display name")
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    total_resources_scanned: int = Field(..., description="Total resources scanned")
    total_findings: int = Field(..., description="Total security findings")
    findings_by_severity: Dict[SeverityLevel, int] = Field(default_factory=dict)
    findings: List[SecurityFinding] = Field(default_factory=list)
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score")
    scan_duration_seconds: Optional[float] = Field(None, description="Scan duration in seconds")


class ScanRequest(BaseModel):
    """Scan request model."""
    subscription_id: Optional[str] = Field(None, description="Specific subscription to scan")
    resource_types: Optional[List[ResourceType]] = Field(None, description="Resource types to scan")
    severity_threshold: SeverityLevel = Field(SeverityLevel.LOW, description="Minimum severity to report")


class ScanStatus(BaseModel):
    """Scan status information."""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: str = Field(..., description="Scan status: pending, running, completed, failed")
    progress: int = Field(..., ge=0, le=100, description="Progress percentage")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(None)
    error_message: Optional[str] = Field(None)
