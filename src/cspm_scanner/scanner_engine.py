"""Main scanning engine that coordinates all scanners."""

import asyncio
import time
from typing import List, Dict, Optional, Any
from datetime import datetime

from .models import ScanResult, ScanRequest, SecurityFinding, ResourceType, SeverityLevel
from .scanners import (
    StorageScanner,
    NetworkScanner,
    KeyVaultScanner,
    ComputeScanner,
    DatabricksScanner
)
from .risk_scoring import risk_engine
from .auth import auth_manager


class ScannerEngine:
    """Main scanning engine that orchestrates all security scanners."""
    
    def __init__(self):
        self.scanners = {
            ResourceType.STORAGE_ACCOUNT: StorageScanner,
            ResourceType.NETWORK_SECURITY_GROUP: NetworkScanner,
            ResourceType.KEY_VAULT: KeyVaultScanner,
            ResourceType.VIRTUAL_MACHINE: ComputeScanner,
            ResourceType.DATABRICKS_WORKSPACE: DatabricksScanner,
        }
    
    async def scan_subscription(
        self, 
        subscription_id: str, 
        scan_request: Optional[ScanRequest] = None
    ) -> ScanResult:
        """Perform a comprehensive security scan of a subscription."""
        start_time = time.time()
        
        try:
            # Validate access to subscription
            if not auth_manager.validate_access(subscription_id):
                raise Exception(f"No access to subscription {subscription_id}")
            
            # Get subscription details
            subscription_details = self._get_subscription_details(subscription_id)
            
            # Determine which scanners to run
            scanners_to_run = self._get_scanners_to_run(scan_request)
            
            # Run scanners concurrently
            all_findings = []
            total_resources_scanned = 0
            
            for resource_type, scanner_class in scanners_to_run.items():
                try:
                    scanner = scanner_class(subscription_id)
                    findings = await scanner.scan()
                    all_findings.extend(findings)
                    
                    # Count resources (simplified - in practice would track actual resource count)
                    resource_ids = set(finding.resource_id for finding in findings)
                    total_resources_scanned += len(resource_ids)
                    
                except Exception as e:
                    print(f"Error running {resource_type} scanner: {str(e)}")
                    continue
            
            # Filter findings by severity threshold
            if scan_request and scan_request.severity_threshold:
                all_findings = self._filter_findings_by_severity(
                    all_findings, 
                    scan_request.severity_threshold
                )
            
            # Calculate risk scores and statistics
            overall_risk_score = risk_engine.calculate_overall_risk_score(all_findings)
            findings_by_severity = risk_engine.get_findings_by_severity(all_findings)
            
            # Create scan result
            scan_duration = time.time() - start_time
            
            scan_result = ScanResult(
                subscription_id=subscription_id,
                subscription_name=subscription_details.get('display_name'),
                scan_timestamp=datetime.utcnow(),
                total_resources_scanned=total_resources_scanned,
                total_findings=len(all_findings),
                findings_by_severity=findings_by_severity,
                findings=all_findings,
                risk_score=overall_risk_score,
                scan_duration_seconds=scan_duration
            )
            
            return scan_result
            
        except Exception as e:
            # Return a scan result with error information
            return ScanResult(
                subscription_id=subscription_id,
                subscription_name=subscription_details.get('display_name') if 'subscription_details' in locals() else None,
                scan_timestamp=datetime.utcnow(),
                total_resources_scanned=0,
                total_findings=0,
                findings_by_severity={},
                findings=[],
                risk_score=0,
                scan_duration_seconds=time.time() - start_time
            )
    
    async def scan_multiple_subscriptions(
        self, 
        subscription_ids: List[str],
        scan_request: Optional[ScanRequest] = None
    ) -> List[ScanResult]:
        """Scan multiple subscriptions concurrently."""
        tasks = [
            self.scan_subscription(sub_id, scan_request) 
            for sub_id in subscription_ids
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return valid results
        scan_results = []
        for result in results:
            if isinstance(result, Exception):
                print(f"Scan failed: {str(result)}")
                continue
            if isinstance(result, ScanResult):
                scan_results.append(result)
        
        return scan_results
    
    async def scan_all_subscriptions(self, scan_request: Optional[ScanRequest] = None) -> List[ScanResult]:
        """Scan all accessible subscriptions."""
        try:
            subscriptions = auth_manager.list_subscriptions()
            subscription_ids = [sub['id'] for sub in subscriptions]
            
            return await self.scan_multiple_subscriptions(subscription_ids, scan_request)
            
        except Exception as e:
            print(f"Error scanning all subscriptions: {str(e)}")
            return []
    
    def _get_subscription_details(self, subscription_id: str) -> Dict[str, Any]:
        """Get subscription details."""
        try:
            subscriptions = auth_manager.list_subscriptions()
            for sub in subscriptions:
                if sub['id'] == subscription_id:
                    return sub
        except Exception:
            pass
        
        return {}
    
    def _get_scanners_to_run(self, scan_request: Optional[ScanRequest]) -> Dict[ResourceType, Any]:
        """Determine which scanners to run based on request."""
        if scan_request and scan_request.resource_types:
            return {
                resource_type: self.scanners[resource_type]
                for resource_type in scan_request.resource_types
                if resource_type in self.scanners
            }
        
        # Run all scanners by default
        return self.scanners
    
    def _filter_findings_by_severity(
        self, 
        findings: List[SecurityFinding], 
        min_severity: SeverityLevel
    ) -> List[SecurityFinding]:
        """Filter findings based on minimum severity level."""
        severity_order = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        
        min_level = severity_order.get(min_severity, 0)
        
        return [
            finding for finding in findings
            if severity_order.get(finding.severity, 0) >= min_level
        ]
    
    def get_supported_resource_types(self) -> List[ResourceType]:
        """Get list of supported resource types for scanning."""
        return list(self.scanners.keys())
    
    async def validate_scan_request(self, scan_request: ScanRequest) -> Dict[str, Any]:
        """Validate a scan request and return validation results."""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Validate subscription access
        if scan_request.subscription_id:
            if not auth_manager.validate_access(scan_request.subscription_id):
                validation_result["valid"] = False
                validation_result["errors"].append(
                    f"No access to subscription {scan_request.subscription_id}"
                )
        
        # Validate resource types
        if scan_request.resource_types:
            supported_types = self.get_supported_resource_types()
            for resource_type in scan_request.resource_types:
                if resource_type not in supported_types:
                    validation_result["warnings"].append(
                        f"Resource type {resource_type} is not supported"
                    )
        
        return validation_result


# Global scanner engine instance
scanner_engine = ScannerEngine()
