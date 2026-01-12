"""Key Vault security scanner."""

from typing import List
import asyncio

from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.core.exceptions import HttpResponseError

from .base_scanner import BaseScanner
from ..models import SecurityFinding, ResourceType, SeverityLevel
from ..auth import auth_manager


class KeyVaultScanner(BaseScanner):
    """Scanner for Azure Key Vault resources."""
    
    def __init__(self, subscription_id: str):
        super().__init__(subscription_id, ResourceType.KEY_VAULT)
        self.client = auth_manager.get_keyvault_client(subscription_id)
    
    async def scan(self) -> List[SecurityFinding]:
        """Scan all key vaults in the subscription."""
        findings = []
        
        try:
            vaults = list(self.client.vaults.list())
            
            # Process vaults concurrently
            tasks = [self._scan_vault(vault) for vault in vaults]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            print(f"Error scanning key vaults: {str(e)}")
        
        return findings
    
    async def _scan_vault(self, vault) -> List[SecurityFinding]:
        """Scan a single key vault for security issues."""
        findings = []
        
        try:
            resource_group = vault.id.split('/')[4]
            
            # Check network access (firewall configuration)
            if self._has_public_network_access(vault):
                findings.append(self.create_finding(
                    resource_id=vault.id,
                    resource_name=vault.name,
                    resource_group=resource_group,
                    location=vault.location,
                    title="Key Vault Allows Public Network Access",
                    description="Key Vault is accessible from public networks without firewall restrictions",
                    severity=SeverityLevel.HIGH,
                    recommendation="Enable Key Vault firewall and restrict access to trusted networks",
                    risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 75),
                    metadata={
                        "public_network_access": vault.properties.network_acls.default_action.value if vault.properties.network_acls else "Allow",
                        "bypass": vault.properties.network_acls.bypass if vault.properties.network_acls else None
                    }
                ))
            
            # Check for soft delete protection
            if not self._has_soft_delete_enabled(vault):
                findings.append(self.create_finding(
                    resource_id=vault.id,
                    resource_name=vault.name,
                    resource_group=resource_group,
                    location=vault.location,
                    title="Soft Delete Not Enabled",
                    description="Key Vault does not have soft delete protection enabled",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Enable soft delete to protect against accidental deletion of secrets and keys",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 50),
                    metadata={
                        "soft_delete_enabled": vault.properties.enable_soft_delete if hasattr(vault.properties, 'enable_soft_delete') else False
                    }
                ))
            
            # Check for purge protection
            if not self._has_purge_protection(vault):
                findings.append(self.create_finding(
                    resource_id=vault.id,
                    resource_name=vault.name,
                    resource_group=resource_group,
                    location=vault.location,
                    title="Purge Protection Not Enabled",
                    description="Key Vault does not have purge protection enabled",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Enable purge protection to prevent permanent deletion of soft-deleted items",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 45),
                    metadata={
                        "purge_protection_enabled": vault.properties.enable_purge_protection if hasattr(vault.properties, 'enable_purge_protection') else False
                    }
                ))
            
            # Check for RBAC authorization
            if not self._uses_rbac_authorization(vault):
                findings.append(self.create_finding(
                    resource_id=vault.id,
                    resource_name=vault.name,
                    resource_group=resource_group,
                    location=vault.location,
                    title="Not Using RBAC Authorization",
                    description="Key Vault is using access policies instead of Azure RBAC for authorization",
                    severity=SeverityLevel.LOW,
                    recommendation="Consider using Azure RBAC for more granular and centralized access control",
                    risk_score=self.calculate_risk_score(SeverityLevel.LOW, 30),
                    metadata={
                        "enable_rbac_authorization": vault.properties.enable_rbac_authorization if hasattr(vault.properties, 'enable_rbac_authorization') else False
                    }
                ))
            
            # Check for allowed access patterns
            if vault.properties.network_acls and vault.properties.network_acls.bypass:
                bypass_services = [service.value for service in vault.properties.network_acls.bypass]
                if "AzureServices" in bypass_services:
                    findings.append(self.create_finding(
                        resource_id=vault.id,
                        resource_name=vault.name,
                        resource_group=resource_group,
                        location=vault.location,
                        title="Azure Services Bypass Enabled",
                        description="Key Vault allows Azure services to bypass network rules",
                        severity=SeverityLevel.LOW,
                        recommendation="Review if Azure services bypass is necessary for your security requirements",
                        risk_score=self.calculate_risk_score(SeverityLevel.LOW, 25),
                        metadata={
                            "bypass_services": bypass_services
                        }
                    ))
            
        except Exception as e:
            print(f"Error scanning key vault {vault.name}: {str(e)}")
        
        return findings
    
    def _has_public_network_access(self, vault) -> bool:
        """Check if key vault allows public network access."""
        if not vault.properties.network_acls:
            return True  # No network ACLs means public access
        
        # Check if default action is Allow
        if vault.properties.network_acls.default_action.value == "Allow":
            return True
        
        return False
    
    def _has_soft_delete_enabled(self, vault) -> bool:
        """Check if soft delete is enabled."""
        if hasattr(vault.properties, 'enable_soft_delete'):
            return vault.properties.enable_soft_delete
        return False
    
    def _has_purge_protection(self, vault) -> bool:
        """Check if purge protection is enabled."""
        if hasattr(vault.properties, 'enable_purge_protection'):
            return vault.properties.enable_purge_protection
        return False
    
    def _uses_rbac_authorization(self, vault) -> bool:
        """Check if key vault uses RBAC authorization."""
        if hasattr(vault.properties, 'enable_rbac_authorization'):
            return vault.properties.enable_rbac_authorization
        return False
