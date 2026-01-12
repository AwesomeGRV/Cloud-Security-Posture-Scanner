"""Databricks workspace security scanner."""

from typing import List
import asyncio

from azure.mgmt.databricks import DatabricksClient
from azure.core.exceptions import HttpResponseError

from .base_scanner import BaseScanner
from ..models import SecurityFinding, ResourceType, SeverityLevel
from ..auth import auth_manager


class DatabricksScanner(BaseScanner):
    """Scanner for Azure Databricks workspaces."""
    
    def __init__(self, subscription_id: str):
        super().__init__(subscription_id, ResourceType.DATABRICKS_WORKSPACE)
        self.client = auth_manager.get_databricks_client(subscription_id)
    
    async def scan(self) -> List[SecurityFinding]:
        """Scan all Databricks workspaces in the subscription."""
        findings = []
        
        try:
            workspaces = list(self.client.workspaces.list())
            
            # Process workspaces concurrently
            tasks = [self._scan_workspace(workspace) for workspace in workspaces]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            print(f"Error scanning Databricks workspaces: {str(e)}")
        
        return findings
    
    async def _scan_workspace(self, workspace) -> List[SecurityFinding]:
        """Scan a single Databricks workspace for security issues."""
        findings = []
        
        try:
            resource_group = workspace.id.split('/')[4]
            
            # Check for public network access
            if self._has_public_network_access(workspace):
                findings.append(self.create_finding(
                    resource_id=workspace.id,
                    resource_name=workspace.name,
                    resource_group=resource_group,
                    location=workspace.location,
                    title="Databricks Workspace Public Access Enabled",
                    description="Databricks workspace allows public network access",
                    severity=SeverityLevel.HIGH,
                    recommendation="Disable public network access and use private endpoints or VNet injection",
                    risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 80),
                    metadata={
                        "public_network_access": workspace.parameters.public_network_access.value if hasattr(workspace.parameters, 'public_network_access') else "Enabled"
                    }
                ))
            
            # Check for secure cluster connectivity
            if not self._has_secure_connectivity(workspace):
                findings.append(self.create_finding(
                    resource_id=workspace.id,
                    resource_name=workspace.name,
                    resource_group=resource_group,
                    location=workspace.location,
                    title="Insecure Cluster Connectivity",
                    description="Databricks workspace does not have secure cluster connectivity enabled",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Enable secure cluster connectivity for enhanced security",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 50),
                    metadata={
                        "secure_connectivity": False
                    }
                ))
            
            # Check for customer-managed keys
            if not self._uses_customer_managed_keys(workspace):
                findings.append(self.create_finding(
                    resource_id=workspace.id,
                    resource_name=workspace.name,
                    resource_group=resource_group,
                    location=workspace.location,
                    title="Not Using Customer-Managed Keys",
                    description="Databricks workspace is using platform-managed keys instead of customer-managed keys",
                    severity=SeverityLevel.LOW,
                    recommendation="Consider using customer-managed keys for enhanced data protection",
                    risk_score=self.calculate_risk_score(SeverityLevel.LOW, 30),
                    metadata={
                        "encryption_key_source": "Platform"  # Default assumption
                    }
                ))
            
            # Check for private endpoint configuration
            if not self._has_private_endpoints(workspace):
                findings.append(self.create_finding(
                    resource_id=workspace.id,
                    resource_name=workspace.name,
                    resource_group=resource_group,
                    location=workspace.location,
                    title="No Private Endpoints Configured",
                    description="Databricks workspace does not have private endpoints configured",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Configure private endpoints to eliminate public internet exposure",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 45),
                    metadata={
                        "private_endpoints": False
                    }
                ))
            
            # Check for workspace isolation
            if not self._has_workspace_isolation(workspace):
                findings.append(self.create_finding(
                    resource_id=workspace.id,
                    resource_name=workspace.name,
                    resource_group=resource_group,
                    location=workspace.location,
                    title="No Workspace Isolation",
                    description="Databricks workspace may not have proper network isolation",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Implement workspace isolation using VNet injection for enhanced security",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 55),
                    metadata={
                        "network_isolation": False
                    }
                ))
            
        except Exception as e:
            print(f"Error scanning Databricks workspace {workspace.name}: {str(e)}")
        
        return findings
    
    def _has_public_network_access(self, workspace) -> bool:
        """Check if workspace allows public network access."""
        # Default to True if not explicitly disabled
        if hasattr(workspace.parameters, 'public_network_access'):
            return workspace.parameters.public_network_access.value == "Enabled"
        return True
    
    def _has_secure_connectivity(self, workspace) -> bool:
        """Check if workspace has secure cluster connectivity."""
        # This is a simplified check - in practice, you'd check the workspace configuration
        # For now, assume it's not enabled unless we can verify otherwise
        return False
    
    def _uses_customer_managed_keys(self, workspace) -> bool:
        """Check if workspace uses customer-managed keys."""
        # Check if encryption parameters specify customer-managed keys
        if hasattr(workspace.parameters, 'encryption'):
            if workspace.parameters.encryption and hasattr(workspace.parameters.encryption, 'key_source'):
                return workspace.parameters.encryption.key_source.value == "Microsoft.Keyvault"
        return False
    
    def _has_private_endpoints(self, workspace) -> bool:
        """Check if workspace has private endpoints configured."""
        # This would require checking the workspace's network configuration
        # For now, return False as a conservative estimate
        return False
    
    def _has_workspace_isolation(self, workspace) -> bool:
        """Check if workspace has proper network isolation."""
        # Check if workspace is configured with VNet injection
        if hasattr(workspace.parameters, 'custom_parameters'):
            if workspace.parameters.custom_parameters and hasattr(workspace.parameters.custom_parameters, 'virtual_network_id'):
                return workspace.parameters.custom_parameters.virtual_network_id is not None
        return False
