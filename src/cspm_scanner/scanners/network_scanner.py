"""Network security group scanner."""

from typing import List
import asyncio
import ipaddress

from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError

from .base_scanner import BaseScanner
from ..models import SecurityFinding, ResourceType, SeverityLevel
from ..auth import auth_manager


class NetworkScanner(BaseScanner):
    """Scanner for Azure Network Security Groups."""
    
    def __init__(self, subscription_id: str):
        super().__init__(subscription_id, ResourceType.NETWORK_SECURITY_GROUP)
        self.client = auth_manager.get_network_client(subscription_id)
    
    async def scan(self) -> List[SecurityFinding]:
        """Scan all network security groups in the subscription."""
        findings = []
        
        try:
            nsgs = list(self.client.network_security_groups.list_all())
            
            # Process NSGs concurrently
            tasks = [self._scan_nsg(nsg) for nsg in nsgs]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            print(f"Error scanning network security groups: {str(e)}")
        
        return findings
    
    async def _scan_nsg(self, nsg) -> List[SecurityFinding]:
        """Scan a single network security group for security issues."""
        findings = []
        
        try:
            if not nsg.security_rules:
                return findings
            
            resource_group = nsg.id.split('/')[4]
            
            for rule in nsg.security_rules:
                if rule.direction == "Inbound":
                    findings.extend(self._check_inbound_rule(nsg, rule, resource_group))
                    
        except Exception as e:
            print(f"Error scanning NSG {nsg.name}: {str(e)}")
        
        return findings
    
    def _check_inbound_rule(self, nsg, rule, resource_group: str) -> List[SecurityFinding]:
        """Check inbound security rules for misconfigurations."""
        findings = []
        
        # Skip deny rules
        if rule.access == "Deny":
            return findings
        
        # Check for overly permissive source addresses
        if self._is_overly_permissive_source(rule):
            severity = self._get_severity_for_port_range(rule.destination_port_range)
            
            findings.append(self.create_finding(
                resource_id=nsg.id,
                resource_name=nsg.name,
                resource_group=resource_group,
                location=nsg.location,
                title="Overly Permissive Inbound Rule",
                description=f"NSG rule '{rule.name}' allows inbound access from {rule.source_address_prefix} to port {rule.destination_port_range}",
                severity=severity,
                recommendation="Restrict source address to specific IP ranges or networks instead of allowing broad access",
                risk_score=self.calculate_risk_score(severity, 75),
                metadata={
                    "rule_name": rule.name,
                    "protocol": rule.protocol,
                    "source_address_prefix": rule.source_address_prefix,
                    "source_port_range": rule.source_port_range,
                    "destination_address_prefix": rule.destination_address_prefix,
                    "destination_port_range": rule.destination_port_range,
                    "access": rule.access,
                    "priority": rule.priority
                }
            ))
        
        # Check for RDP access from internet
        if self._is_rdp_from_internet(rule):
            findings.append(self.create_finding(
                resource_id=nsg.id,
                resource_name=nsg.name,
                resource_group=resource_group,
                location=nsg.location,
                title="RDP Access from Internet",
                description="NSG rule allows Remote Desktop Protocol (RDP) access from the internet",
                severity=SeverityLevel.HIGH,
                recommendation="Restrict RDP access to specific IP addresses or use VPN/Bastion",
                risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 85),
                metadata={
                    "rule_name": rule.name,
                    "protocol": rule.protocol,
                    "source_address_prefix": rule.source_address_prefix,
                    "destination_port_range": rule.destination_port_range,
                    "access": rule.access
                }
            ))
        
        # Check for SSH access from internet
        if self._is_ssh_from_internet(rule):
            findings.append(self.create_finding(
                resource_id=nsg.id,
                resource_name=nsg.name,
                resource_group=resource_group,
                location=nsg.location,
                title="SSH Access from Internet",
                description="NSG rule allows SSH access from the internet",
                severity=SeverityLevel.HIGH,
                recommendation="Restrict SSH access to specific IP addresses or use VPN/Bastion",
                risk_score=self.calculate_risk_score(SeverityLevel.HIGH, 80),
                metadata={
                    "rule_name": rule.name,
                    "protocol": rule.protocol,
                    "source_address_prefix": rule.source_address_prefix,
                    "destination_port_range": rule.destination_port_range,
                    "access": rule.access
                }
            ))
        
        return findings
    
    def _is_overly_permissive_source(self, rule) -> bool:
        """Check if rule allows access from overly broad source."""
        if not rule.source_address_prefix:
            return False
        
        # Check for internet access
        if rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
            return True
        
        # Check for very broad CIDR blocks
        try:
            if "/" in rule.source_address_prefix:
                network = ipaddress.ip_network(rule.source_address_prefix, strict=False)
                # Allow /24 or more specific, flag /16 or broader
                if network.prefixlen <= 16:
                    return True
        except ValueError:
            pass
        
        return False
    
    def _is_rdp_from_internet(self, rule) -> bool:
        """Check if rule allows RDP from internet."""
        if rule.access != "Allow":
            return False
        
        if rule.source_address_prefix not in ["*", "0.0.0.0/0", "Internet"]:
            return False
        
        # Check for RDP port (3389)
        if rule.destination_port_range == "3389":
            return True
        
        # Check for port ranges that include 3389
        if "-" in rule.destination_port_range:
            try:
                start, end = map(int, rule.destination_port_range.split("-"))
                if start <= 3389 <= end:
                    return True
            except ValueError:
                pass
        
        return False
    
    def _is_ssh_from_internet(self, rule) -> bool:
        """Check if rule allows SSH from internet."""
        if rule.access != "Allow":
            return False
        
        if rule.source_address_prefix not in ["*", "0.0.0.0/0", "Internet"]:
            return False
        
        # Check for SSH port (22)
        if rule.destination_port_range == "22":
            return True
        
        # Check for port ranges that include 22
        if "-" in rule.destination_port_range:
            try:
                start, end = map(int, rule.destination_port_range.split("-"))
                if start <= 22 <= end:
                    return True
            except ValueError:
                pass
        
        return False
    
    def _get_severity_for_port_range(self, port_range: str) -> SeverityLevel:
        """Determine severity based on port range."""
        if not port_range:
            return SeverityLevel.MEDIUM
        
        # High-risk ports
        high_risk_ports = ["22", "3389", "1433", "3306", "5432", "6379", "27017"]
        
        if port_range in high_risk_ports:
            return SeverityLevel.HIGH
        
        # Check if port range includes high-risk ports
        if "-" in port_range:
            try:
                start, end = map(int, port_range.split("-"))
                for port in high_risk_ports:
                    if start <= int(port) <= end:
                        return SeverityLevel.HIGH
            except ValueError:
                pass
        
        return SeverityLevel.MEDIUM
