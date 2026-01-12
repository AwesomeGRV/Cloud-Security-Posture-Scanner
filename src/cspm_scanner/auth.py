"""Azure authentication management."""

from typing import Optional
from azure.identity import DefaultAzureCredential, ClientSecretCredential, ManagedIdentityCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.databricks import DatabricksClient
from .config import settings


class AzureAuthManager:
    """Manages Azure authentication and client creation."""
    
    def __init__(self):
        self._credential = None
        self._subscription_client = None
    
    def get_credential(self):
        """Get Azure credential based on configuration."""
        if self._credential is None:
            if settings.use_managed_identity:
                self._credential = ManagedIdentityCredential()
            elif all([settings.azure_client_id, settings.azure_client_secret, settings.azure_tenant_id]):
                self._credential = ClientSecretCredential(
                    client_id=settings.azure_client_id,
                    client_secret=settings.azure_client_secret,
                    tenant_id=settings.azure_tenant_id
                )
            else:
                # Use DefaultAzureCredential for development
                self._credential = DefaultAzureCredential()
        
        return self._credential
    
    def get_subscription_client(self) -> SubscriptionClient:
        """Get subscription management client."""
        if self._subscription_client is None:
            self._subscription_client = SubscriptionClient(self.get_credential())
        return self._subscription_client
    
    def get_storage_client(self, subscription_id: str) -> StorageManagementClient:
        """Get storage management client."""
        return StorageManagementClient(self.get_credential(), subscription_id)
    
    def get_network_client(self, subscription_id: str) -> NetworkManagementClient:
        """Get network management client."""
        return NetworkManagementClient(self.get_credential(), subscription_id)
    
    def get_keyvault_client(self, subscription_id: str) -> KeyVaultManagementClient:
        """Get Key Vault management client."""
        return KeyVaultManagementClient(self.get_credential(), subscription_id)
    
    def get_compute_client(self, subscription_id: str) -> ComputeManagementClient:
        """Get compute management client."""
        return ComputeManagementClient(self.get_credential(), subscription_id)
    
    def get_databricks_client(self, subscription_id: str) -> DatabricksClient:
        """Get Databricks management client."""
        return DatabricksClient(self.get_credential(), subscription_id)
    
    def list_subscriptions(self) -> list:
        """List all accessible subscriptions."""
        try:
            client = self.get_subscription_client()
            subscriptions = []
            for sub in client.subscriptions.list():
                subscriptions.append({
                    'id': str(sub.subscription_id),
                    'display_name': sub.display_name,
                    'tenant_id': sub.tenant_id,
                    'state': sub.state
                })
            return subscriptions
        except Exception as e:
            raise Exception(f"Failed to list subscriptions: {str(e)}")
    
    def validate_access(self, subscription_id: str) -> bool:
        """Validate access to a specific subscription."""
        try:
            client = self.get_subscription_client()
            # Try to get subscription details
            sub = client.subscriptions.get(subscription_id)
            return sub is not None
        except Exception:
            return False


# Global auth manager instance
auth_manager = AzureAuthManager()
