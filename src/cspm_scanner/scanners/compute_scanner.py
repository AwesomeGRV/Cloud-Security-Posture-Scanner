"""Compute resources security scanner."""

from typing import List
import asyncio

from azure.mgmt.compute import ComputeManagementClient
from azure.core.exceptions import HttpResponseError

from .base_scanner import BaseScanner
from ..models import SecurityFinding, ResourceType, SeverityLevel
from ..auth import auth_manager


class ComputeScanner(BaseScanner):
    """Scanner for Azure Compute resources (VMs and Disks)."""
    
    def __init__(self, subscription_id: str):
        super().__init__(subscription_id, ResourceType.VIRTUAL_MACHINE)
        self.client = auth_manager.get_compute_client(subscription_id)
    
    async def scan(self) -> List[SecurityFinding]:
        """Scan all compute resources in the subscription."""
        findings = []
        
        try:
            # Scan virtual machines
            vm_findings = await self._scan_virtual_machines()
            findings.extend(vm_findings)
            
            # Scan disks
            disk_findings = await self._scan_disks()
            findings.extend(disk_findings)
                    
        except Exception as e:
            print(f"Error scanning compute resources: {str(e)}")
        
        return findings
    
    async def _scan_virtual_machines(self) -> List[SecurityFinding]:
        """Scan virtual machines for security issues."""
        findings = []
        
        try:
            vms = list(self.client.virtual_machines.list_all())
            
            # Process VMs concurrently
            tasks = [self._scan_vm(vm) for vm in vms]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            print(f"Error scanning virtual machines: {str(e)}")
        
        return findings
    
    async def _scan_disks(self) -> List[SecurityFinding]:
        """Scan managed disks for security issues."""
        findings = []
        
        try:
            disks = list(self.client.disks.list())
            
            # Process disks concurrently
            tasks = [self._scan_disk(disk) for disk in disks]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            print(f"Error scanning disks: {str(e)}")
        
        return findings
    
    async def _scan_vm(self, vm) -> List[SecurityFinding]:
        """Scan a single virtual machine for security issues."""
        findings = []
        
        try:
            resource_group = vm.id.split('/')[4]
            
            # Check for public IP addresses
            if self._has_public_ip(vm):
                findings.append(self.create_finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    resource_group=resource_group,
                    location=vm.location,
                    title="Virtual Machine with Public IP",
                    description="Virtual machine has a public IP address assigned",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Consider using VPN or Azure Bastion for access instead of public IP",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 60),
                    metadata={
                        "vm_size": vm.hardware_profile.vm_size,
                        "os_type": vm.storage_profile.os_disk.os_type.value if vm.storage_profile.os_disk.os_type else "Unknown"
                    }
                ))
            
            # Check for OS disk encryption
            if not self._is_os_disk_encrypted(vm):
                findings.append(self.create_finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    resource_group=resource_group,
                    location=vm.location,
                    title="Unencrypted OS Disk",
                    description="Virtual machine's OS disk is not encrypted",
                    severity=SeverityLevel.HIGH,
                    recommendation="Enable Azure Disk Encryption for the VM's OS disk",
                    risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 70),
                    metadata={
                        "os_type": vm.storage_profile.os_disk.os_type.value if vm.storage_profile.os_disk.os_type else "Unknown",
                        "os_disk_name": vm.storage_profile.os_disk.name
                    }
                ))
            
            # Check for security extensions
            if not self._has_security_extensions(vm):
                findings.append(self.create_finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    resource_group=resource_group,
                    location=vm.location,
                    title="Missing Security Extensions",
                    description="Virtual machine does not have security monitoring extensions installed",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Install security extensions like Azure Monitor, Microsoft Antimalware, or Log Analytics agent",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 40),
                    metadata={
                        "extensions_count": len(vm.resources) if vm.resources else 0
                    }
                ))
            
            # Check for managed identity
            if not self._has_managed_identity(vm):
                findings.append(self.create_finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    resource_group=resource_group,
                    location=vm.location,
                    title="No Managed Identity Assigned",
                    description="Virtual machine does not have a managed identity assigned",
                    severity=SeverityLevel.LOW,
                    recommendation="Enable managed identity for better security and access management",
                    risk_score=self.calculate_risk_score(SeverityLevel.LOW, 30),
                    metadata={
                        "identity_type": vm.identity.type.value if vm.identity and vm.identity.type else "None"
                    }
                ))
            
        except Exception as e:
            print(f"Error scanning VM {vm.name}: {str(e)}")
        
        return findings
    
    async def _scan_disk(self, disk) -> List[SecurityFinding]:
        """Scan a single managed disk for security issues."""
        findings = []
        
        try:
            resource_group = disk.id.split('/')[4]
            
            # Check disk encryption
            if not self._is_disk_encrypted(disk):
                findings.append(self.create_finding(
                    resource_id=disk.id,
                    resource_name=disk.name,
                    resource_group=resource_group,
                    location=disk.location,
                    title="Unencrypted Managed Disk",
                    description="Managed disk is not encrypted at rest",
                    severity=SeverityLevel.HIGH,
                    recommendation="Enable encryption at rest for the managed disk",
                    risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 65),
                    metadata={
                        "disk_type": disk.disk_state.value if disk.disk_state else "Unknown",
                        "disk_size_gb": disk.disk_size_gb,
                        "sku": disk.sku.name if disk.sku else "Unknown"
                    }
                ))
            
            # Check for public network access (for disk export)
            if hasattr(disk, 'network_access_policy') and disk.network_access_policy and disk.network_access_policy.value == "AllowAll":
                findings.append(self.create_finding(
                    resource_id=disk.id,
                    resource_name=disk.name,
                    resource_group=resource_group,
                    location=disk.location,
                    title="Disk Allows Public Network Access",
                    description="Managed disk allows export via public network",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Restrict network access policy to allow only private endpoints or deny all",
                    risk_score=self.calculate_risk_score(SeverityLevel.MEDIUM, 55),
                    metadata={
                        "network_access_policy": disk.network_access_policy.value
                    }
                ))
            
        except Exception as e:
            print(f"Error scanning disk {disk.name}: {str(e)}")
        
        return findings
    
    def _has_public_ip(self, vm) -> bool:
        """Check if VM has a public IP address."""
        if not vm.network_profile or not vm.network_profile.network_interfaces:
            return False
        
        # This is a simplified check - in practice, you'd need to check each NIC's public IP
        return len(vm.network_profile.network_interfaces) > 0
    
    def _is_os_disk_encrypted(self, vm) -> bool:
        """Check if VM's OS disk is encrypted."""
        # This is a simplified check - in practice, you'd check encryption settings
        # For now, we'll assume it's not encrypted unless we can verify otherwise
        return False
    
    def _has_security_extensions(self, vm) -> bool:
        """Check if VM has security-related extensions."""
        if not vm.resources:
            return False
        
        security_extensions = [
            "Microsoft.Azure.Security.Antimalware",
            "Microsoft.Azure.Monitor",
            "Microsoft.OMSAgent",
            "Microsoft.Azure.Extensions.CustomScript"
        ]
        
        for resource in vm.resources:
            if resource.id and any(ext in resource.id for ext in security_extensions):
                return True
        
        return False
    
    def _has_managed_identity(self, vm) -> bool:
        """Check if VM has managed identity enabled."""
        return vm.identity is not None and vm.identity.type is not None
    
    def _is_disk_encrypted(self, disk) -> bool:
        """Check if managed disk is encrypted."""
        # Check if encryption is enabled at rest
        if hasattr(disk, 'encryption') and disk.encryption:
            return True
        
        # Check if disk is using encryption at host
        if hasattr(disk, 'encryption_settings_collection') and disk.encryption_settings_collection:
            return True
        
        return False
