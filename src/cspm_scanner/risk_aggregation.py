"""Risk aggregation and correlation across resource types and findings."""

from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import statistics
import math

from .models import SecurityFinding, SeverityLevel, ResourceType, ScanResult
from .risk_scoring import RiskScoringEngine


class CorrelationType(str, Enum):
    """Types of risk correlations."""
    RESOURCE_DEPENDENCY = "resource_dependency"
    NETWORK_CONNECTIVITY = "network_connectivity"
    DATA_FLOW = "data_flow"
    IDENTITY_RELATIONSHIP = "identity_relationship"
    CONFIGURATION_PATTERN = "configuration_pattern"
    TEMPORAL_PATTERN = "temporal_pattern"
    GEOGRAPHIC_PROXIMITY = "geographic_proximity"
    COMPLIANCE_SCOPE = "compliance_scope"


class AggregationLevel(str, Enum):
    """Risk aggregation levels."""
    RESOURCE = "resource"
    RESOURCE_GROUP = "resource_group"
    SUBSCRIPTION = "subscription"
    LOCATION = "location"
    ORGANIZATION = "organization"


@dataclass
class RiskCluster:
    """Cluster of related security findings."""
    cluster_id: str
    cluster_type: CorrelationType
    findings: List[SecurityFinding]
    risk_score: int
    confidence: float
    correlation_strength: float
    description: str
    affected_resources: List[str]
    potential_impact: str


@dataclass
class RiskCorrelation:
    """Correlation between security findings."""
    correlation_id: str
    correlation_type: CorrelationType
    primary_finding: SecurityFinding
    correlated_findings: List[SecurityFinding]
    correlation_strength: float
    description: str
    mitigation_implications: List[str]


@dataclass
class AggregatedRisk:
    """Aggregated risk at different levels."""
    aggregation_level: AggregationLevel
    aggregation_key: str
    total_findings: int
    risk_score: int
    risk_distribution: Dict[str, int]
    critical_findings: List[str]
    high_risk_areas: List[str]
    trend_data: Dict[str, float]


class RiskAggregationEngine:
    """Engine for risk aggregation and correlation analysis."""
    
    def __init__(self):
        self.risk_engine = RiskScoringEngine()
        self.correlation_weights = {
            CorrelationType.RESOURCE_DEPENDENCY: 0.9,
            CorrelationType.NETWORK_CONNECTIVITY: 0.8,
            CorrelationType.DATA_FLOW: 0.85,
            CorrelationType.IDENTITY_RELATIONSHIP: 0.75,
            CorrelationType.CONFIGURATION_PATTERN: 0.7,
            CorrelationType.TEMPORAL_PATTERN: 0.6,
            CorrelationType.GEOGRAPHIC_PROXIMITY: 0.5,
            CorrelationType.COMPLIANCE_SCOPE: 0.8
        }
        
        self.resource_dependencies = self._load_resource_dependencies()
        self.network_topology = self._load_network_topology()
        self.data_flow_patterns = self._load_data_flow_patterns()
    
    def _load_resource_dependencies(self) -> Dict[str, List[str]]:
        """Load resource dependency mappings."""
        return {
            # Storage dependencies
            "Microsoft.Storage/storageAccounts": [
                "Microsoft.Compute/virtualMachines",
                "Microsoft.Databricks/workspaces",
                "Microsoft.Network/networkSecurityGroups"
            ],
            
            # Network dependencies
            "Microsoft.Network/networkSecurityGroups": [
                "Microsoft.Compute/virtualMachines",
                "Microsoft.Storage/storageAccounts",
                "Microsoft.KeyVault/vaults"
            ],
            
            # Key Vault dependencies
            "Microsoft.KeyVault/vaults": [
                "Microsoft.Compute/virtualMachines",
                "Microsoft.Databricks/workspaces",
                "Microsoft.Storage/storageAccounts"
            ],
            
            # Compute dependencies
            "Microsoft.Compute/virtualMachines": [
                "Microsoft.Storage/storageAccounts",
                "Microsoft.Network/networkSecurityGroups",
                "Microsoft.KeyVault/vaults",
                "Microsoft.Compute/disks"
            ],
            
            # Databricks dependencies
            "Microsoft.Databricks/workspaces": [
                "Microsoft.Storage/storageAccounts",
                "Microsoft.Network/networkSecurityGroups",
                "Microsoft.KeyVault/vaults"
            ],
            
            # Disk dependencies
            "Microsoft.Compute/disks": [
                "Microsoft.Compute/virtualMachines"
            ]
        }
    
    def _load_network_topology(self) -> Dict[str, List[str]]:
        """Load network topology relationships."""
        return {
            "subnet_to_vnet": [],
            "vnet_peering": [],
            "nsg_associations": [],
            "firewall_rules": []
        }
    
    def _load_data_flow_patterns(self) -> Dict[str, List[str]]:
        """Load data flow patterns."""
        return {
            "data_ingress": [
                "Microsoft.Storage/storageAccounts",
                "Microsoft.Compute/virtualMachines"
            ],
            "data_egress": [
                "Microsoft.Storage/storageAccounts",
                "Microsoft.Compute/virtualMachines"
            ],
            "data_processing": [
                "Microsoft.Databricks/workspaces",
                "Microsoft.Compute/virtualMachines"
            ],
            "data_storage": [
                "Microsoft.Storage/storageAccounts",
                "Microsoft.Compute/disks"
            ]
        }
    
    def aggregate_risks(self, findings: List[SecurityFinding], 
                       aggregation_level: AggregationLevel = AggregationLevel.SUBSCRIPTION) -> Dict[str, AggregatedRisk]:
        """Aggregate risks at specified level."""
        aggregated_risks = {}
        
        # Group findings by aggregation key
        grouped_findings = self._group_findings_by_level(findings, aggregation_level)
        
        for key, group_findings in grouped_findings.items():
            aggregated_risk = self._calculate_aggregated_risk(
                aggregation_level, key, group_findings
            )
            aggregated_risks[key] = aggregated_risk
        
        return aggregated_risks
    
    def _group_findings_by_level(self, findings: List[SecurityFinding], 
                               level: AggregationLevel) -> Dict[str, List[SecurityFinding]]:
        """Group findings by aggregation level."""
        grouped = defaultdict(list)
        
        for finding in findings:
            if level == AggregationLevel.RESOURCE:
                key = finding.resource_id
            elif level == AggregationLevel.RESOURCE_GROUP:
                key = finding.resource_group
            elif level == AggregationLevel.SUBSCRIPTION:
                key = finding.subscription_id
            elif level == AggregationLevel.LOCATION:
                key = finding.location
            elif level == AggregationLevel.ORGANIZATION:
                key = "organization"  # All findings
            
            grouped[key].append(finding)
        
        return dict(grouped)
    
    def _calculate_aggregated_risk(self, level: AggregationLevel, key: str, 
                                  findings: List[SecurityFinding]) -> AggregatedRisk:
        """Calculate aggregated risk for a group of findings."""
        # Calculate overall risk score
        overall_risk_score = self.risk_engine.calculate_overall_risk_score(findings)
        
        # Risk distribution by severity
        risk_distribution = self.risk_engine.get_findings_by_severity(findings)
        risk_distribution_dict = {severity.value: count for severity, count in risk_distribution.items()}
        
        # Critical findings
        critical_findings = [
            finding.id for finding in findings 
            if finding.severity == SeverityLevel.CRITICAL
        ]
        
        # High risk areas (resource types with most findings)
        resource_type_counts = Counter(finding.resource_type.value for finding in findings)
        high_risk_areas = [
            f"{resource_type}: {count}" 
            for resource_type, count in resource_type_counts.most_common(3)
        ]
        
        # Trend data (placeholder - would need historical data)
        trend_data = {
            "trend": "stable",
            "change_percentage": 0.0,
            "period_days": 30
        }
        
        return AggregatedRisk(
            aggregation_level=level,
            aggregation_key=key,
            total_findings=len(findings),
            risk_score=overall_risk_score,
            risk_distribution=risk_distribution_dict,
            critical_findings=critical_findings,
            high_risk_areas=high_risk_areas,
            trend_data=trend_data
        )
    
    def correlate_risks(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Correlate risks across different findings."""
        correlations = []
        
        # Find correlations by type
        for correlation_type in CorrelationType:
            type_correlations = self._find_correlations_by_type(findings, correlation_type)
            correlations.extend(type_correlations)
        
        # Sort by correlation strength
        correlations.sort(key=lambda x: x.correlation_strength, reverse=True)
        
        return correlations
    
    def _find_correlations_by_type(self, findings: List[SecurityFinding], 
                                 correlation_type: CorrelationType) -> List[RiskCorrelation]:
        """Find correlations of a specific type."""
        correlations = []
        
        if correlation_type == CorrelationType.RESOURCE_DEPENDENCY:
            correlations = self._find_resource_dependency_correlations(findings)
        elif correlation_type == CorrelationType.NETWORK_CONNECTIVITY:
            correlations = self._find_network_correlations(findings)
        elif correlation_type == CorrelationType.DATA_FLOW:
            correlations = self._find_data_flow_correlations(findings)
        elif correlation_type == CorrelationType.IDENTITY_RELATIONSHIP:
            correlations = self._find_identity_correlations(findings)
        elif correlation_type == CorrelationType.CONFIGURATION_PATTERN:
            correlations = self._find_configuration_correlations(findings)
        elif correlation_type == CorrelationType.TEMPORAL_PATTERN:
            correlations = self._find_temporal_correlations(findings)
        elif correlation_type == CorrelationType.GEOGRAPHIC_PROXIMITY:
            correlations = self._find_geographic_correlations(findings)
        elif correlation_type == CorrelationType.COMPLIANCE_SCOPE:
            correlations = self._find_compliance_correlations(findings)
        
        return correlations
    
    def _find_resource_dependency_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on resource dependencies."""
        correlations = []
        
        # Group findings by resource type
        findings_by_type = defaultdict(list)
        for finding in findings:
            findings_by_type[finding.resource_type].append(finding)
        
        # Check for dependency relationships
        for resource_type, type_findings in findings_by_type.items():
            if resource_type.value in self.resource_dependencies:
                dependent_types = self.resource_dependencies[resource_type.value]
                
                for dependent_type in dependent_types:
                    if dependent_type in findings_by_type:
                        # Find correlations between resource types
                        for primary_finding in type_findings:
                            for dependent_finding in findings_by_type[dependent_type]:
                                correlation_strength = self._calculate_dependency_correlation_strength(
                                    primary_finding, dependent_finding
                                )
                                
                                if correlation_strength > 0.5:
                                    correlation = RiskCorrelation(
                                        correlation_id=f"dep_{primary_finding.id}_{dependent_finding.id}",
                                        correlation_type=CorrelationType.RESOURCE_DEPENDENCY,
                                        primary_finding=primary_finding,
                                        correlated_findings=[dependent_finding],
                                        correlation_strength=correlation_strength,
                                        description=f"Resource dependency: {resource_type.value} depends on {dependent_type}",
                                        mitigation_implications=[
                                            "Address primary resource issues first",
                                            "Consider dependent resource impact",
                                            "Coordinate remediation efforts"
                                        ]
                                    )
                                    correlations.append(correlation)
        
        return correlations
    
    def _find_network_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on network connectivity."""
        correlations = []
        
        # Group findings by resource group and location
        findings_by_group = defaultdict(list)
        for finding in findings:
            key = f"{finding.resource_group}:{finding.location}"
            findings_by_group[key].append(finding)
        
        # Find network-related correlations
        for group_key, group_findings in findings_by_group.items():
            network_findings = [
                f for f in group_findings 
                if "network" in f.title.lower() or "public" in f.title.lower() or "internet" in f.title.lower()
            ]
            
            if len(network_findings) > 1:
                # Correlate network findings
                for i, primary in enumerate(network_findings):
                    for secondary in network_findings[i+1:]:
                        correlation_strength = self._calculate_network_correlation_strength(primary, secondary)
                        
                        if correlation_strength > 0.6:
                            correlation = RiskCorrelation(
                                correlation_id=f"net_{primary.id}_{secondary.id}",
                                correlation_type=CorrelationType.NETWORK_CONNECTIVITY,
                                primary_finding=primary,
                                correlated_findings=[secondary],
                                correlation_strength=correlation_strength,
                                description=f"Network connectivity correlation in {group_key}",
                                mitigation_implications=[
                                    "Review network security group configurations",
                                    "Implement network segmentation",
                                    "Coordinate network security policies"
                                ]
                            )
                            correlations.append(correlation)
        
        return correlations
    
    def _find_data_flow_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on data flow patterns."""
        correlations = []
        
        # Group findings by data-related keywords
        data_findings = [
            f for f in findings 
            if any(keyword in f.title.lower() or keyword in f.description.lower() 
                   for keyword in ["data", "storage", "blob", "file", "encryption"])
        ]
        
        # Find correlations between data-related findings
        for i, primary in enumerate(data_findings):
            for secondary in data_findings[i+1:]:
                if primary.resource_id != secondary.resource_id:
                    correlation_strength = self._calculate_data_flow_correlation_strength(primary, secondary)
                    
                    if correlation_strength > 0.5:
                        correlation = RiskCorrelation(
                            correlation_id=f"data_{primary.id}_{secondary.id}",
                            correlation_type=CorrelationType.DATA_FLOW,
                            primary_finding=primary,
                            correlated_findings=[secondary],
                            correlation_strength=correlation_strength,
                            description="Data flow correlation between resources",
                            mitigation_implications=[
                                "Review data protection policies",
                                "Implement consistent encryption",
                                "Coordinate data security measures"
                            ]
                        )
                        correlations.append(correlation)
        
        return correlations
    
    def _find_identity_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on identity relationships."""
        correlations = []
        
        # Group findings by subscription
        findings_by_subscription = defaultdict(list)
        for finding in findings:
            findings_by_subscription[finding.subscription_id].append(finding)
        
        # Find identity-related correlations
        for subscription_id, sub_findings in findings_by_subscription.items():
            identity_findings = [
                f for f in sub_findings 
                if any(keyword in f.title.lower() or keyword in f.description.lower() 
                       for keyword in ["access", "authentication", "rbac", "authorization"])
            ]
            
            if len(identity_findings) > 1:
                for i, primary in enumerate(identity_findings):
                    for secondary in identity_findings[i+1:]:
                        correlation_strength = self._calculate_identity_correlation_strength(primary, secondary)
                        
                        if correlation_strength > 0.5:
                            correlation = RiskCorrelation(
                                correlation_id=f"id_{primary.id}_{secondary.id}",
                                correlation_type=CorrelationType.IDENTITY_RELATIONSHIP,
                                primary_finding=primary,
                                correlated_findings=[secondary],
                                correlation_strength=correlation_strength,
                                description=f"Identity relationship correlation in subscription {subscription_id}",
                                mitigation_implications=[
                                    "Review access control policies",
                                    "Implement consistent authentication",
                                    "Coordinate identity management"
                                ]
                            )
                            correlations.append(correlation)
        
        return correlations
    
    def _find_configuration_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on configuration patterns."""
        correlations = []
        
        # Group findings by configuration patterns
        config_patterns = defaultdict(list)
        for finding in findings:
            # Identify configuration patterns
            if "not enabled" in finding.title.lower():
                config_patterns["disabled_feature"].append(finding)
            elif "public" in finding.title.lower():
                config_patterns["public_access"].append(finding)
            elif "insecure" in finding.title.lower():
                config_patterns["insecure_config"].append(finding)
            elif "default" in finding.title.lower():
                config_patterns["default_config"].append(finding)
        
        # Find correlations within patterns
        for pattern, pattern_findings in config_patterns.items():
            if len(pattern_findings) > 1:
                for i, primary in enumerate(pattern_findings):
                    for secondary in pattern_findings[i+1:]:
                        correlation_strength = self._calculate_configuration_correlation_strength(primary, secondary)
                        
                        if correlation_strength > 0.6:
                            correlation = RiskCorrelation(
                                correlation_id=f"config_{primary.id}_{secondary.id}",
                                correlation_type=CorrelationType.CONFIGURATION_PATTERN,
                                primary_finding=primary,
                                correlated_findings=[secondary],
                                correlation_strength=correlation_strength,
                                description=f"Configuration pattern correlation: {pattern}",
                                mitigation_implications=[
                                    "Review configuration standards",
                                    "Implement configuration management",
                                    "Apply consistent security baselines"
                                ]
                            )
                            correlations.append(correlation)
        
        return correlations
    
    def _find_temporal_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on temporal patterns."""
        correlations = []
        
        # Sort findings by timestamp
        sorted_findings = sorted(findings, key=lambda f: f.timestamp)
        
        # Find findings within time windows
        time_window = timedelta(hours=24)  # 24-hour window
        
        for i, primary in enumerate(sorted_findings):
            # Find findings within time window
            window_findings = [
                f for f in sorted_findings[i+1:]
                if abs((f.timestamp - primary.timestamp).total_seconds()) <= time_window.total_seconds()
            ]
            
            for secondary in window_findings:
                correlation_strength = self._calculate_temporal_correlation_strength(primary, secondary)
                
                if correlation_strength > 0.4:
                    correlation = RiskCorrelation(
                        correlation_id=f"temp_{primary.id}_{secondary.id}",
                        correlation_type=CorrelationType.TEMPORAL_PATTERN,
                        primary_finding=primary,
                        correlated_findings=[secondary],
                        correlation_strength=correlation_strength,
                        description=f"Temporal pattern correlation within {time_window}",
                        mitigation_implications=[
                            "Review recent changes",
                            "Monitor for coordinated activities",
                            "Investigate temporal patterns"
                        ]
                    )
                    correlations.append(correlation)
        
        return correlations
    
    def _find_geographic_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on geographic proximity."""
        correlations = []
        
        # Group findings by location
        findings_by_location = defaultdict(list)
        for finding in findings:
            findings_by_location[finding.location].append(finding)
        
        # Find correlations within locations
        for location, location_findings in findings_by_location.items():
            if len(location_findings) > 1:
                for i, primary in enumerate(location_findings):
                    for secondary in location_findings[i+1:]:
                        correlation_strength = self._calculate_geographic_correlation_strength(primary, secondary)
                        
                        if correlation_strength > 0.3:
                            correlation = RiskCorrelation(
                                correlation_id=f"geo_{primary.id}_{secondary.id}",
                                correlation_type=CorrelationType.GEOGRAPHIC_PROXIMITY,
                                primary_finding=primary,
                                correlated_findings=[secondary],
                                correlation_strength=correlation_strength,
                                description=f"Geographic correlation in {location}",
                                mitigation_implications=[
                                    "Review regional security policies",
                                    "Implement consistent regional controls",
                                    "Coordinate regional security efforts"
                                ]
                            )
                            correlations.append(correlation)
        
        return correlations
    
    def _find_compliance_correlations(self, findings: List[SecurityFinding]) -> List[RiskCorrelation]:
        """Find correlations based on compliance scope."""
        correlations = []
        
        # Group findings by compliance keywords
        compliance_findings = [
            f for f in findings 
            if any(keyword in f.title.lower() or keyword in f.description.lower() 
                   for keyword in ["compliance", "audit", "logging", "policy", "standard"])
        ]
        
        if len(compliance_findings) > 1:
            for i, primary in enumerate(compliance_findings):
                for secondary in compliance_findings[i+1:]:
                    correlation_strength = self._calculate_compliance_correlation_strength(primary, secondary)
                    
                    if correlation_strength > 0.5:
                        correlation = RiskCorrelation(
                            correlation_id=f"comp_{primary.id}_{secondary.id}",
                            correlation_type=CorrelationType.COMPLIANCE_SCOPE,
                            primary_finding=primary,
                            correlated_findings=[secondary],
                            correlation_strength=correlation_strength,
                            description="Compliance scope correlation",
                            mitigation_implications=[
                                "Review compliance requirements",
                                "Implement consistent controls",
                                "Coordinate compliance efforts"
                            ]
                        )
                        correlations.append(correlation)
        
        return correlations
    
    def _calculate_dependency_correlation_strength(self, primary: SecurityFinding, 
                                                   secondary: SecurityFinding) -> float:
        """Calculate correlation strength for resource dependencies."""
        base_strength = 0.7
        
        # Adjust based on severity
        if primary.severity == SeverityLevel.CRITICAL and secondary.severity == SeverityLevel.CRITICAL:
            base_strength += 0.2
        elif primary.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] or \
             secondary.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            base_strength += 0.1
        
        # Adjust based on resource types
        if primary.resource_type == ResourceType.STORAGE_ACCOUNT and \
           secondary.resource_type == ResourceType.VIRTUAL_MACHINE:
            base_strength += 0.1
        
        return min(1.0, base_strength)
    
    def _calculate_network_correlation_strength(self, primary: SecurityFinding, 
                                               secondary: SecurityFinding) -> float:
        """Calculate correlation strength for network connectivity."""
        base_strength = 0.6
        
        # Check for similar network issues
        primary_keywords = set(primary.title.lower().split())
        secondary_keywords = set(secondary.title.lower().split())
        
        common_keywords = primary_keywords.intersection(secondary_keywords)
        if common_keywords:
            base_strength += len(common_keywords) * 0.1
        
        # Adjust based on severity
        if primary.severity == secondary.severity:
            base_strength += 0.1
        
        return min(1.0, base_strength)
    
    def _calculate_data_flow_correlation_strength(self, primary: SecurityFinding, 
                                                  secondary: SecurityFinding) -> float:
        """Calculate correlation strength for data flow patterns."""
        base_strength = 0.5
        
        # Check for data-related keywords
        data_keywords = ["data", "storage", "blob", "file", "encryption", "transfer"]
        
        primary_data_keywords = sum(1 for keyword in data_keywords 
                                   if keyword in primary.title.lower())
        secondary_data_keywords = sum(1 for keyword in data_keywords 
                                     if keyword in secondary.title.lower())
        
        if primary_data_keywords > 0 and secondary_data_keywords > 0:
            base_strength += 0.2
        
        return min(1.0, base_strength)
    
    def _calculate_identity_correlation_strength(self, primary: SecurityFinding, 
                                               secondary: SecurityFinding) -> float:
        """Calculate correlation strength for identity relationships."""
        base_strength = 0.5
        
        # Check for identity-related keywords
        identity_keywords = ["access", "authentication", "rbac", "authorization", "identity"]
        
        primary_identity_keywords = sum(1 for keyword in identity_keywords 
                                       if keyword in primary.title.lower())
        secondary_identity_keywords = sum(1 for keyword in identity_keywords 
                                         if keyword in secondary.title.lower())
        
        if primary_identity_keywords > 0 and secondary_identity_keywords > 0:
            base_strength += 0.2
        
        return min(1.0, base_strength)
    
    def _calculate_configuration_correlation_strength(self, primary: SecurityFinding, 
                                                      secondary: SecurityFinding) -> float:
        """Calculate correlation strength for configuration patterns."""
        base_strength = 0.6
        
        # Check for similar configuration patterns
        if "not enabled" in primary.title.lower() and "not enabled" in secondary.title.lower():
            base_strength += 0.2
        elif "public" in primary.title.lower() and "public" in secondary.title.lower():
            base_strength += 0.2
        
        return min(1.0, base_strength)
    
    def _calculate_temporal_correlation_strength(self, primary: SecurityFinding, 
                                                 secondary: SecurityFinding) -> float:
        """Calculate correlation strength for temporal patterns."""
        base_strength = 0.4
        
        # Calculate time difference
        time_diff = abs((secondary.timestamp - primary.timestamp).total_seconds())
        hours_diff = time_diff / 3600
        
        # Closer in time = stronger correlation
        if hours_diff < 1:
            base_strength += 0.3
        elif hours_diff < 6:
            base_strength += 0.2
        elif hours_diff < 24:
            base_strength += 0.1
        
        return min(1.0, base_strength)
    
    def _calculate_geographic_correlation_strength(self, primary: SecurityFinding, 
                                                   secondary: SecurityFinding) -> float:
        """Calculate correlation strength for geographic proximity."""
        base_strength = 0.3
        
        # Same location increases correlation
        if primary.location == secondary.location:
            base_strength += 0.3
        
        # Same resource group increases correlation
        if primary.resource_group == secondary.resource_group:
            base_strength += 0.2
        
        return min(1.0, base_strength)
    
    def _calculate_compliance_correlation_strength(self, primary: SecurityFinding, 
                                                   secondary: SecurityFinding) -> float:
        """Calculate correlation strength for compliance scope."""
        base_strength = 0.5
        
        # Check for compliance-related keywords
        compliance_keywords = ["compliance", "audit", "logging", "policy", "standard", "regulation"]
        
        primary_compliance_keywords = sum(1 for keyword in compliance_keywords 
                                         if keyword in primary.title.lower())
        secondary_compliance_keywords = sum(1 for keyword in compliance_keywords 
                                           if keyword in secondary.title.lower())
        
        if primary_compliance_keywords > 0 and secondary_compliance_keywords > 0:
            base_strength += 0.2
        
        return min(1.0, base_strength)
    
    def identify_risk_clusters(self, findings: List[SecurityFinding]) -> List[RiskCluster]:
        """Identify clusters of related security findings."""
        clusters = []
        
        # Get correlations
        correlations = self.correlate_risks(findings)
        
        # Group findings into clusters based on correlations
        finding_to_cluster = {}
        cluster_id = 0
        
        for correlation in correlations:
            primary_id = correlation.primary_finding.id
            correlated_ids = [f.id for f in correlation.correlated_findings]
            
            # Check if primary finding is already in a cluster
            if primary_id in finding_to_cluster:
                cluster = finding_to_cluster[primary_id]
            else:
                cluster = f"cluster_{cluster_id}"
                cluster_id += 1
                finding_to_cluster[primary_id] = cluster
            
            # Add correlated findings to the same cluster
            for correlated_id in correlated_ids:
                if correlated_id not in finding_to_cluster:
                    finding_to_cluster[correlated_id] = cluster
                elif finding_to_cluster[correlated_id] != cluster:
                    # Merge clusters if they overlap
                    old_cluster = finding_to_cluster[correlated_id]
                    for fid, cid in finding_to_cluster.items():
                        if cid == old_cluster:
                            finding_to_cluster[fid] = cluster
        
        # Create cluster objects
        cluster_findings = defaultdict(list)
        for finding in findings:
            if finding.id in finding_to_cluster:
                cluster_findings[finding_to_cluster[finding.id]].append(finding)
        
        for cluster_key, cluster_finding_list in cluster_findings.items():
            if len(cluster_finding_list) > 1:  # Only include clusters with multiple findings
                cluster = self._create_risk_cluster(cluster_key, cluster_finding_list)
                clusters.append(cluster)
        
        # Sort by risk score
        clusters.sort(key=lambda x: x.risk_score, reverse=True)
        
        return clusters
    
    def _create_risk_cluster(self, cluster_id: str, findings: List[SecurityFinding]) -> RiskCluster:
        """Create a risk cluster from findings."""
        # Calculate cluster risk score
        cluster_risk_score = self.risk_engine.calculate_overall_risk_score(findings)
        
        # Determine cluster type based on correlations
        cluster_correlations = self.correlate_risks(findings)
        if cluster_correlations:
            cluster_type = cluster_correlations[0].correlation_type
        else:
            cluster_type = CorrelationType.CONFIGURATION_PATTERN
        
        # Calculate correlation strength
        avg_correlation_strength = 0.0
        if cluster_correlations:
            avg_correlation_strength = sum(c.correlation_strength for c in cluster_correlations) / len(cluster_correlations)
        
        # Generate description
        resource_types = list(set(f.resource_type.value for f in findings))
        description = f"Cluster of {len(findings)} findings affecting {', '.join(resource_types)}"
        
        # Get affected resources
        affected_resources = list(set(f.resource_id for f in findings))
        
        # Determine potential impact
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        if critical_count > 0:
            potential_impact = "High - Critical security issues present"
        elif len(findings) > 5:
            potential_impact = "Medium - Multiple security issues"
        else:
            potential_impact = "Low - Limited security issues"
        
        return RiskCluster(
            cluster_id=cluster_id,
            cluster_type=cluster_type,
            findings=findings,
            risk_score=cluster_risk_score,
            confidence=avg_correlation_strength,
            correlation_strength=avg_correlation_strength,
            description=description,
            affected_resources=affected_resources,
            potential_impact=potential_impact
        )
    
    def generate_risk_aggregation_report(self, findings: List[SecurityFinding]) -> Dict:
        """Generate comprehensive risk aggregation and correlation report."""
        # Aggregate risks at different levels
        resource_aggregations = self.aggregate_risks(findings, AggregationLevel.RESOURCE)
        resource_group_aggregations = self.aggregate_risks(findings, AggregationLevel.RESOURCE_GROUP)
        subscription_aggregations = self.aggregate_risks(findings, AggregationLevel.SUBSCRIPTION)
        
        # Correlate risks
        correlations = self.correlate_risks(findings)
        
        # Identify risk clusters
        risk_clusters = self.identify_risk_clusters(findings)
        
        # Generate summary statistics
        summary = {
            "total_findings": len(findings),
            "total_correlations": len(correlations),
            "total_clusters": len(risk_clusters),
            "high_risk_clusters": len([c for c in risk_clusters if c.risk_score > 70]),
            "strong_correlations": len([c for c in correlations if c.correlation_strength > 0.8]),
            "resource_groups_analyzed": len(resource_group_aggregations),
            "subscriptions_analyzed": len(subscription_aggregations)
        }
        
        # Generate recommendations
        recommendations = self._generate_aggregation_recommendations(
            correlations, risk_clusters, resource_group_aggregations
        )
        
        return {
            "summary": summary,
            "aggregations": {
                "resource": {k: v.__dict__ for k, v in resource_aggregations.items()},
                "resource_group": {k: v.__dict__ for k, v in resource_group_aggregations.items()},
                "subscription": {k: v.__dict__ for k, v in subscription_aggregations.items()}
            },
            "correlations": [
                {
                    "correlation_id": c.correlation_id,
                    "correlation_type": c.correlation_type.value,
                    "primary_finding": c.primary_finding.title,
                    "correlated_findings": [f.title for f in c.correlated_findings],
                    "correlation_strength": c.correlation_strength,
                    "description": c.description,
                    "mitigation_implications": c.mitigation_implications
                }
                for c in correlations[:20]  # Top 20 correlations
            ],
            "risk_clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "cluster_type": c.cluster_type.value,
                    "risk_score": c.risk_score,
                    "confidence": c.confidence,
                    "correlation_strength": c.correlation_strength,
                    "description": c.description,
                    "affected_resources_count": len(c.affected_resources),
                    "potential_impact": c.potential_impact
                }
                for c in risk_clusters[:10]  # Top 10 clusters
            ],
            "recommendations": recommendations
        }
    
    def _generate_aggregation_recommendations(self, correlations: List[RiskCorrelation], 
                                            clusters: List[RiskCluster],
                                            resource_groups: Dict[str, AggregatedRisk]) -> List[str]:
        """Generate recommendations based on aggregation analysis."""
        recommendations = []
        
        # High-risk clusters
        high_risk_clusters = [c for c in clusters if c.risk_score > 70]
        if high_risk_clusters:
            recommendations.append(
                f"URGENT: Address {len(high_risk_clusters)} high-risk clusters. "
                f"These represent coordinated security issues that require comprehensive remediation."
            )
        
        # Strong correlations
        strong_correlations = [c for c in correlations if c.correlation_strength > 0.8]
        if strong_correlations:
            recommendations.append(
                f"High correlation strength detected in {len(strong_correlations)} relationships. "
                f"Review and coordinate remediation efforts across related resources."
            )
        
        # Resource group risks
        high_risk_groups = [
            group for group in resource_groups.values() 
            if group.risk_score > 60
        ]
        if high_risk_groups:
            recommendations.append(
                f"{len(high_risk_groups)} resource groups have elevated risk scores. "
                f"Implement targeted security improvements for these groups."
            )
        
        # Correlation type recommendations
        correlation_types = Counter(c.correlation_type for c in correlations)
        most_common_type = correlation_types.most_common(1)[0][0] if correlation_types else None
        
        if most_common_type:
            type_recommendations = {
                CorrelationType.RESOURCE_DEPENDENCY: "Review resource dependencies and implement defense-in-depth strategies.",
                CorrelationType.NETWORK_CONNECTIVITY: "Strengthen network security controls and segmentation.",
                CorrelationType.DATA_FLOW: "Implement comprehensive data protection and monitoring.",
                CorrelationType.IDENTITY_RELATIONSHIP: "Review and strengthen identity and access management.",
                CorrelationType.CONFIGURATION_PATTERN: "Implement configuration management and security baselines.",
                CorrelationType.TEMPORAL_PATTERN: "Monitor for coordinated activities and implement change management.",
                CorrelationType.GEOGRAPHIC_PROXIMITY: "Ensure consistent security controls across regions.",
                CorrelationType.COMPLIANCE_SCOPE: "Strengthen compliance monitoring and reporting."
            }
            
            if most_common_type in type_recommendations:
                recommendations.append(
                    f"Primary correlation type: {most_common_type.value}. "
                    f"{type_recommendations[most_common_type]}"
                )
        
        if not recommendations:
            recommendations.append(
                "Risk aggregation analysis shows good security posture. Continue monitoring for emerging patterns."
            )
        
        return recommendations


# Global risk aggregation engine instance
risk_aggregation_engine = RiskAggregationEngine()
