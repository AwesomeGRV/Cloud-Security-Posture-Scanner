"""Storage account security scanner."""

from typing import List
import asyncio

from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import HttpResponseError

from .base_scanner import BaseScanner
from ..models import SecurityFinding, ResourceType, SeverityLevel
from ..auth import auth_manager


class StorageScanner(BaseScanner):
    """Scanner for Azure Storage accounts."""
    
    def __init__(self, subscription_id: str):
        super().__init__(subscription_id, ResourceType.STORAGE_ACCOUNT)
        self.client = auth_manager.get_storage_client(subscription_id)
    
    async def scan(self) -> List[SecurityFinding]:
        """Scan all storage accounts in the subscription."""
        findings = []
        
        try:
            storage_accounts = list(self.client.storage_accounts.list())
            
            # Process storage accounts concurrently
            tasks = [self._scan_storage_account(account) for account in storage_accounts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            print(f"Error scanning storage accounts: {str(e)}")
        
        return findings
    
    async def _scan_storage_account(self, storage_account) -> List[SecurityFinding]:
        """Scan a single storage account for security issues."""
        findings = []
        
        try:
            # Get storage account properties
            account_props = self.client.storage_accounts.get_properties(
                storage_account.id.split('/')[4],  # resource group
                storage_account.name
            )
            
            # Check for public blob access
            if self._has_public_blob_access(account_props):
                findings.append(self.create_finding(
                    resource_id=storage_account.id,
                    resource_name=storage_account.name,
                    resource_group=storage_account.id.split('/')[4],
                    location=storage_account.location,
                    title="Public Blob Access Enabled",
                    description="Storage account allows public access to blob containers",
                    severity=SeverityLevel.HIGH,
                    recommendation="Disable public blob access and use private endpoints or SAS tokens",
                    risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 80),
                    metadata={
                        "allow_blob_public_access": account_props.allow_blob_public_access,
                        "network_rule_default_action": account_props.network_rule_set.default_action.value if account_props.network_rule_set else None
                    }
                ))
            
            # Check for secure transfer required
            if not account_props.enable_https_traffic_only:
                findings.append(self.create_finding(
                    resource_id=storage_account.id,
                    resource_name=storage_account.name,
                    resource_group=storage_account.id.split('/')[4],
                    location=storage_account.location,
                    title="Insecure Transfer Enabled",
                    description="Storage account allows unencrypted HTTP traffic",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Enable 'Secure transfer required' to enforce HTTPS",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 60),
                    metadata={
                        "enable_https_traffic_only": account_props.enable_https_traffic_only
                    }
                ))
            
            # Check for encryption settings
            if not account_props.encryption.services.blob.enabled or not account_props.encryption.services.file.enabled:
                findings.append(self.create_finding(
                    resource_id=storage_account.id,
                    resource_name=storage_account.name,
                    resource_group=storage_account.id.split('/')[4],
                    location=storage_account.location,
                    title="Storage Encryption Not Fully Enabled",
                    description="Some storage services have encryption disabled",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Enable encryption for all storage services (blob, file, queue, table)",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 50),
                    metadata={
                        "blob_encryption": account_props.encryption.services.blob.enabled,
                        "file_encryption": account_props.encryption.services.file.enabled,
                        "queue_encryption": account_props.encryption.services.queue.enabled,
                        "table_encryption": account_props.encryption.services.table.enabled
                    }
                ))
            
            # Check network access
            if account_props.network_rule_set and account_props.network_rule_set.default_action.value == "Allow":
                findings.append(self.create_finding(
                    resource_id=storage_account.id,
                    resource_name=storage_account.name,
                    resource_group=storage_account.id.split('/')[4],
                    location=storage_account.location,
                    title="Default Network Access Allowed",
                    description="Storage account allows public network access by default",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Configure network rules to restrict access to specific IP ranges or virtual networks",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 55),
                    metadata={
                        "default_action": account_props.network_rule_set.default_action.value,
                        "bypass": account_props.network_rule_set.bypass
                    }
                ))
            
        except Exception as e:
            print(f"Error scanning storage account {storage_account.name}: {str(e)}")
        
        return findings
    
    def _has_public_blob_access(self, account_props) -> bool:
        """Check if storage account allows public blob access."""
        # Check the allow_blob_public_access property
        if hasattr(account_props, 'allow_blob_public_access') and account_props.allow_blob_public_access:
            return True
        
        # Check network rule set
        if account_props.network_rule_set and account_props.network_rule_set.default_action.value == "Allow":
            return True
        
        return False
