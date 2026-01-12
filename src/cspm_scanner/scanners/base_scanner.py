"""Base scanner class for all Azure resource scanners."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime
import uuid

from ..models import SecurityFinding, ResourceType, SeverityLevel


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""
    
    def __init__(self, subscription_id: str, resource_type: ResourceType):
        self.subscription_id = subscription_id
        self.resource_type = resource_type
    
    @abstractmethod
    async def scan(self) -> List[SecurityFinding]:
        """Scan resources and return security findings."""
        pass
    
    def create_finding(
        self,
        resource_id: str,
        resource_name: str,
        resource_group: str,
        location: str,
        title: str,
        description: str,
        severity: SeverityLevel,
        recommendation: str,
        risk_score: int,
        metadata: Dict[str, Any] = None
    ) -> SecurityFinding:
        """Create a security finding with common fields."""
        return SecurityFinding(
            id=str(uuid.uuid4()),
            resource_id=resource_id,
            resource_name=resource_name,
            resource_type=self.resource_type,
            subscription_id=self.subscription_id,
            resource_group=resource_group,
            location=location,
            title=title,
            description=description,
            severity=severity,
            recommendation=recommendation,
            risk_score=risk_score,
            metadata=metadata or {},
            timestamp=datetime.utcnow()
        )
    
    def calculate_risk_score(self, severity: SeverityLevel, base_score: int = 50) -> int:
        """Calculate risk score based on severity."""
        severity_multipliers = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2
        }
        
        multiplier = severity_multipliers.get(severity, 0.5)
        return min(100, int(base_score * multiplier))
    
    def get_resource_id_parts(self, resource_id: str) -> Dict[str, str]:
        """Extract parts from Azure resource ID."""
        parts = resource_id.split('/')
        return {
            'subscription_id': parts[2] if len(parts) > 2 else '',
            'resource_group': parts[4] if len(parts) > 4 else '',
            'provider': parts[6] if len(parts) > 6 else '',
            'resource_type': parts[7] if len(parts) > 7 else '',
            'resource_name': parts[8] if len(parts) > 8 else ''
        }
