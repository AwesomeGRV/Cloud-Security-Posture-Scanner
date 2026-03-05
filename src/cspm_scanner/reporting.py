"""Comprehensive risk reporting and dashboard generation."""

from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import json

from .models import SecurityFinding, SeverityLevel, ResourceType, ScanResult
from .risk_scoring import RiskScoringEngine
from .compliance import ComplianceMapper
from .threat_modeling import ThreatModelingEngine
from .business_impact import BusinessImpactAssessment
from .mitre_attack import MITREAttackMapper
from .risk_aggregation import RiskAggregationEngine
from .risk_tolerance import RiskToleranceEngine
from .remediation_assessment import RemediationAssessmentEngine


class ReportType(str, Enum):
    """Types of security reports."""
    EXECUTIVE_SUMMARY = "executive_summary"
    DETAILED_ANALYSIS = "detailed_analysis"
    COMPLIANCE_REPORT = "compliance_report"
    THREAT_ASSESSMENT = "threat_assessment"
    BUSINESS_IMPACT = "business_impact"
    REMEDIATION_PLAN = "remediation_plan"
    TREND_ANALYSIS = "trend_analysis"
    DASHBOARD_DATA = "dashboard_data"


class ReportFormat(str, Enum):
    """Report output formats."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"


class TimeRange(str, Enum):
    """Time ranges for reporting."""
    LAST_24_HOURS = "last_24_hours"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    LAST_90_DAYS = "last_90_days"
    CUSTOM = "custom"


@dataclass
class ReportMetric:
    """Individual report metric."""
    name: str
    value: Any
    unit: str
    trend: str
    comparison_value: Optional[Any]
    comparison_period: str


@dataclass
class ReportSection:
    """Report section definition."""
    section_id: str
    title: str
    description: str
    metrics: List[ReportMetric]
    visualizations: List[Dict[str, Any]]
    recommendations: List[str]


@dataclass
class SecurityReport:
    """Complete security report."""
    report_id: str
    report_type: ReportType
    generated_at: datetime
    time_range: TimeRange
    subscription_id: str
    sections: List[ReportSection]
    summary: Dict[str, Any]
    metadata: Dict[str, Any]


class ReportingEngine:
    """Engine for generating comprehensive security reports and dashboards."""
    
    def __init__(self):
        self.risk_engine = RiskScoringEngine()
        self.compliance_mapper = ComplianceMapper()
        self.threat_engine = ThreatModelingEngine()
        self.business_impact_engine = BusinessImpactAssessment()
        self.mitre_attack_mapper = MITREAttackMapper()
        self.risk_aggregation_engine = RiskAggregationEngine()
        self.risk_tolerance_engine = RiskToleranceEngine()
        self.remediation_engine = RemediationAssessmentEngine()
        
        self.report_templates = self._load_report_templates()
        self.dashboard_configs = self._load_dashboard_configs()
    
    def _load_report_templates(self) -> Dict[ReportType, Dict]:
        """Load report templates."""
        return {
            ReportType.EXECUTIVE_SUMMARY: {
                "sections": [
                    "overall_risk_score",
                    "critical_findings",
                    "compliance_status",
                    "trending_analysis",
                    "key_recommendations"
                ],
                "audience": "executives",
                "detail_level": "high"
            },
            ReportType.DETAILED_ANALYSIS: {
                "sections": [
                    "risk_assessment",
                    "findings_analysis",
                    "resource_analysis",
                    "threat_landscape",
                    "mitre_attack_analysis",
                    "risk_correlations",
                    "detailed_recommendations"
                ],
                "audience": "security_teams",
                "detail_level": "comprehensive"
            },
            ReportType.COMPLIANCE_REPORT: {
                "sections": [
                    "compliance_overview",
                    "framework_assessments",
                    "violations_analysis",
                    "remediation_tracking",
                    "audit_trail"
                ],
                "audience": "compliance_officers",
                "detail_level": "detailed"
            },
            ReportType.THREAT_ASSESSMENT: {
                "sections": [
                    "threat_landscape",
                    "attack_surface_analysis",
                    "threat_intelligence",
                    "attack_patterns",
                    "defense_recommendations"
                ],
                "audience": "security_analysts",
                "detail_level": "technical"
            },
            ReportType.BUSINESS_IMPACT: {
                "sections": [
                    "business_risk_summary",
                    "impact_assessment",
                    "resource_prioritization",
                    "financial_exposure",
                    "business_recommendations"
                ],
                "audience": "business_stakeholders",
                "detail_level =": "business_focused"
            },
            ReportType.REMEDIATION_PLAN: {
                "sections": [
                    "remediation_priorities",
                    "automation_opportunities",
                    "resource_requirements",
                    "implementation_roadmap",
                    "success_metrics"
                ],
                "audience": "operations_teams",
                "detail_level": "actionable"
            },
            ReportType.TREND_ANALYSIS: {
                "sections": [
                    "risk_trends",
                    "finding_trends",
                    "compliance_trends",
                    "performance_metrics",
                    "forecasting"
                ],
                "audience": "management",
                "detail_level": "analytical"
            },
            ReportType.DASHBOARD_DATA: {
                "sections": [
                    "kpi_metrics",
                    "real_time_status",
                    "alert_summary",
                    "performance_indicators",
                    "drill_down_data"
                ],
                "audience": "all_users",
                "detail_level": "visual"
            }
        }
    
    def _load_dashboard_configs(self) -> Dict[str, Dict]:
        """Load dashboard configurations."""
        return {
            "executive_dashboard": {
                "widgets": [
                    "overall_risk_gauge",
                    "compliance_status_chart",
                    "critical_findings_counter",
                    "trend_chart",
                    "risk_heatmap"
                ],
                "refresh_interval": 300,  # 5 minutes
                "layout": "grid"
            },
            "security_dashboard": {
                "widgets": [
                    "findings_by_severity",
                    "findings_by_resource_type",
                    "mitre_attack_matrix",
                    "threat_intelligence",
                    "remediation_status"
                ],
                "refresh_interval": 60,  # 1 minute
                "layout": "detailed"
            },
            "compliance_dashboard": {
                "widgets": [
                    "compliance_scores",
                    "framework_breakdown",
                    "violation_tracking",
                    "audit_status",
                    "remediation_timeline"
                ],
                "refresh_interval": 600,  # 10 minutes
                "layout": "compliance"
            },
            "operations_dashboard": {
                "widgets": [
                    "remediation_queue",
                    "automation_metrics",
                    "resource_health",
                    "performance_indicators",
                    "alert_summary"
                ],
                "refresh_interval": 120,  # 2 minutes
                "layout": "operational"
            }
        }
    
    def generate_report(self, findings: List[SecurityFinding], 
                        report_type: ReportType,
                        time_range: TimeRange = TimeRange.LAST_30_DAYS,
                        subscription_id: Optional[str] = None,
                        context: Optional[Dict[str, Any]] = None,
                        historical_data: Optional[List[ScanResult]] = None) -> SecurityReport:
        """Generate a comprehensive security report."""
        context = context or {}
        
        # Get report template
        template = self.report_templates.get(report_type, {})
        
        # Generate report sections
        sections = []
        for section_name in template.get("sections", []):
            section = self._generate_report_section(
                section_name, findings, time_range, subscription_id, context, historical_data
            )
            if section:
                sections.append(section)
        
        # Generate summary
        summary = self._generate_report_summary(findings, sections, context)
        
        # Generate metadata
        metadata = self._generate_report_metadata(report_type, time_range, subscription_id, context)
        
        # Create report
        report = SecurityReport(
            report_id=f"{report_type.value}_{datetime.utcnow().timestamp()}",
            report_type=report_type,
            generated_at=datetime.utcnow(),
            time_range=time_range,
            subscription_id=subscription_id or "multiple",
            sections=sections,
            summary=summary,
            metadata=metadata
        )
        
        return report
    
    def _generate_report_section(self, section_name: str, 
                                findings: List[SecurityFinding],
                                time_range: TimeRange,
                                subscription_id: Optional[str],
                                context: Dict[str, Any],
                                historical_data: Optional[List[ScanResult]]) -> Optional[ReportSection]:
        """Generate a specific report section."""
        section_generators = {
            "overall_risk_score": self._generate_overall_risk_section,
            "critical_findings": self._generate_critical_findings_section,
            "compliance_status": self._generate_compliance_status_section,
            "trending_analysis": self._generate_trending_analysis_section,
            "key_recommendations": self._generate_key_recommendations_section,
            "risk_assessment": self._generate_risk_assessment_section,
            "findings_analysis": self._generate_findings_analysis_section,
            "resource_analysis": self._generate_resource_analysis_section,
            "threat_landscape": self._generate_threat_landscape_section,
            "mitre_attack_analysis": self._generate_mitre_attack_section,
            "risk_correlations": self._generate_risk_correlations_section,
            "detailed_recommendations": self._generate_detailed_recommendations_section,
            "compliance_overview": self._generate_compliance_overview_section,
            "framework_assessments": self._generate_framework_assessments_section,
            "violations_analysis": self._generate_violations_analysis_section,
            "remediation_tracking": self._generate_remediation_tracking_section,
            "audit_trail": self._generate_audit_trail_section,
            "attack_surface_analysis": self._generate_attack_surface_section,
            "threat_intelligence": self._generate_threat_intelligence_section,
            "attack_patterns": self._generate_attack_patterns_section,
            "defense_recommendations": self._generate_defense_recommendations_section,
            "business_risk_summary": self._generate_business_risk_summary_section,
            "impact_assessment": self._generate_impact_assessment_section,
            "resource_prioritization": self._generate_resource_prioritization_section,
            "financial_exposure": self._generate_financial_exposure_section,
            "business_recommendations": self._generate_business_recommendations_section,
            "remediation_priorities": self._generate_remediation_priorities_section,
            "automation_opportunities": self._generate_automation_opportunities_section,
            "resource_requirements": self._generate_resource_requirements_section,
            "implementation_roadmap": self._generate_implementation_roadmap_section,
            "success_metrics": self._generate_success_metrics_section,
            "risk_trends": self._generate_risk_trends_section,
            "finding_trends": self._generate_finding_trends_section,
            "compliance_trends": self._generate_compliance_trends_section,
            "performance_metrics": self._generate_performance_metrics_section,
            "forecasting": self._generate_forecasting_section,
            "kpi_metrics": self._generate_kpi_metrics_section,
            "real_time_status": self._generate_real_time_status_section,
            "alert_summary": self._generate_alert_summary_section,
            "performance_indicators": self._generate_performance_indicators_section,
            "drill_down_data": self._generate_drill_down_data_section
        }
        
        generator = section_generators.get(section_name)
        if generator:
            return generator(findings, time_range, subscription_id, context, historical_data)
        
        return None
    
    def _generate_overall_risk_section(self, findings: List[SecurityFinding],
                                     time_range: TimeRange,
                                     subscription_id: Optional[str],
                                     context: Dict[str, Any],
                                     historical_data: Optional[List[ScanResult]]) -> ReportSection:
        """Generate overall risk score section."""
        # Calculate risk scores
        overall_risk_score = self.risk_engine.calculate_overall_risk_score(findings, context)
        risk_level = self.risk_engine.get_risk_level(overall_risk_score)
        
        # Calculate trend
        trend_data = self._calculate_risk_trend(historical_data)
        
        # Create metrics
        metrics = [
            ReportMetric(
                name="Overall Risk Score",
                value=overall_risk_score,
                unit="score",
                trend=trend_data["trend"],
                comparison_value=trend_data["previous_score"],
                comparison_period="Previous period"
            ),
            ReportMetric(
                name="Risk Level",
                value=risk_level,
                unit="level",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="Total Findings",
                value=len(findings),
                unit="count",
                trend=trend_data["findings_trend"],
                comparison_value=trend_data["previous_findings"],
                comparison_period="Previous period"
            ),
            ReportMetric(
                name="Critical Findings",
                value=len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            )
        ]
        
        # Create visualizations
        visualizations = [
            {
                "type": "gauge",
                "title": "Overall Risk Score",
                "data": {
                    "value": overall_risk_score,
                    "max": 100,
                    "thresholds": [20, 40, 60, 80]
                }
            },
            {
                "type": "pie_chart",
                "title": "Findings by Severity",
                "data": self._get_severity_distribution(findings)
            },
            {
                "type": "line_chart",
                "title": "Risk Trend",
                "data": self._get_risk_trend_data(historical_data)
            }
        ]
        
        # Generate recommendations
        recommendations = self._generate_risk_recommendations(overall_risk_score, findings)
        
        return ReportSection(
            section_id="overall_risk_score",
            title="Overall Risk Assessment",
            description="Comprehensive overview of security risk posture",
            metrics=metrics,
            visualizations=visualizations,
            recommendations=recommendations
        )
    
    def _generate_critical_findings_section(self, findings: List[SecurityFinding],
                                          time_range: TimeRange,
                                          subscription_id: Optional[str],
                                          context: Dict[str, Any],
                                          historical_data: Optional[List[ScanResult]]) -> ReportSection:
        """Generate critical findings section."""
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        
        # Create metrics
        metrics = [
            ReportMetric(
                name="Critical Findings",
                value=len(critical_findings),
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="Affected Resources",
                value=len(set(f.resource_id for f in critical_findings)),
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="High Risk Resources",
                value=len([f for f in critical_findings if f.risk_score > 80]),
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            )
        ]
        
        # Create visualizations
        visualizations = [
            {
                "type": "table",
                "title": "Critical Findings",
                "data": [
                    {
                        "title": f.title,
                        "resource": f.resource_name,
                        "resource_type": f.resource_type.value,
                        "risk_score": f.risk_score,
                        "location": f.location
                    }
                    for f in critical_findings[:10]  # Top 10
                ]
            },
            {
                "type": "bar_chart",
                "title": "Critical Findings by Resource Type",
                "data": self._get_critical_findings_by_type(critical_findings)
            }
        ]
        
        # Generate recommendations
        recommendations = [
            "URGENT: Address all critical findings immediately",
            "Implement emergency response procedures for critical issues",
            "Consider isolating affected resources if necessary",
            "Document all critical findings for audit purposes"
        ]
        
        return ReportSection(
            section_id="critical_findings",
            title="Critical Security Findings",
            description="Analysis of critical security issues requiring immediate attention",
            metrics=metrics,
            visualizations=visualizations,
            recommendations=recommendations
        )
    
    def _generate_compliance_status_section(self, findings: List[SecurityFinding],
                                         time_range: TimeRange,
                                         subscription_id: Optional[str],
                                         context: Dict[str, Any],
                                         historical_data: Optional[List[ScanResult]]) -> ReportSection:
        """Generate compliance status section."""
        # Generate compliance report
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        
        # Calculate overall compliance score
        frameworks = compliance_report["summary"]["total_frameworks_assessed"]
        avg_score = compliance_report["summary"]["average_compliance_score"]
        
        # Create metrics
        metrics = [
            ReportMetric(
                name="Overall Compliance Score",
                value=avg_score,
                unit="percentage",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="Frameworks Assessed",
                value=frameworks,
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="Total Violations",
                value=compliance_report["summary"]["total_violations"],
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            )
        ]
        
        # Create visualizations
        visualizations = [
            {
                "type": "progress_bar",
                "title": "Compliance Score",
                "data": {
                    "value": avg_score,
                    "max": 100
                }
            },
            {
                "type": "bar_chart",
                "title": "Compliance by Framework",
                "data": [
                    {
                        "framework": framework,
                        "score": assessment["compliance_score"],
                        "violations": len(assessment["violations"])
                    }
                    for framework, assessment in compliance_report["framework_assessments"].items()
                ]
            }
        ]
        
        # Generate recommendations
        recommendations = compliance_report["recommendations"]
        
        return ReportSection(
            section_id="compliance_status",
            title="Compliance Status",
            description="Current compliance posture across regulatory frameworks",
            metrics=metrics,
            visualizations=visualizations,
            recommendations=recommendations
        )
    
    def _generate_trending_analysis_section(self, findings: List[SecurityFinding],
                                           time_range: TimeRange,
                                           subscription_id: Optional[str],
                                           context: Dict[str, Any],
                                           historical_data: Optional[List[ScanResult]]) -> ReportSection:
        """Generate trending analysis section."""
        # Calculate trends
        risk_trend = self._calculate_risk_trend(historical_data)
        findings_trend = self._calculate_findings_trend(historical_data)
        
        # Create metrics
        metrics = [
            ReportMetric(
                name="Risk Trend",
                value=risk_trend["trend"],
                unit="direction",
                trend=risk_trend["trend"],
                comparison_value=risk_trend["previous_score"],
                comparison_period="Previous period"
            ),
            ReportMetric(
                name="Findings Trend",
                value=findings_trend["trend"],
                unit="direction",
                trend=findings_trend["trend"],
                comparison_value=findings_trend["previous_count"],
                comparison_period="Previous period"
            ),
            ReportMetric(
                name="Risk Velocity",
                value=risk_trend.get("velocity", 0),
                unit="points/day",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            )
        ]
        
        # Create visualizations
        visualizations = [
            {
                "type": "line_chart",
                "title": "Risk Score Trend",
                "data": self._get_risk_trend_data(historical_data)
            },
            {
                "type": "line_chart",
                "title": "Findings Count Trend",
                "data": self._get_findings_trend_data(historical_data)
            }
        ]
        
        # Generate recommendations
        recommendations = self._generate_trend_recommendations(risk_trend, findings_trend)
        
        return ReportSection(
            section_id="trending_analysis",
            title="Trending Analysis",
            description="Historical analysis of security trends and patterns",
            metrics=metrics,
            visualizations=visualizations,
            recommendations=recommendations
        )
    
    def _generate_key_recommendations_section(self, findings: List[SecurityFinding],
                                            time_range: TimeRange,
                                            subscription_id: Optional[str],
                                            context: Dict[str, Any],
                                            historical_data: Optional[List[ScanResult]]) -> ReportSection:
        """Generate key recommendations section."""
        # Collect recommendations from all engines
        all_recommendations = []
        
        # Risk scoring recommendations
        risk_summary = self.risk_engine.generate_risk_summary(findings)
        all_recommendations.extend(risk_summary["recommendations"])
        
        # Compliance recommendations
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        all_recommendations.extend(compliance_report["recommendations"])
        
        # Threat modeling recommendations
        threat_report = self.threat_engine.generate_threat_model_report(findings)
        all_recommendations.extend(threat_report["recommendations"])
        
        # Business impact recommendations
        business_context = context.get("business_context", {})
        business_report = self.business_impact_engine.generate_business_impact_report(
            findings, business_context
        )
        all_recommendations.extend(business_report["detailed_assessment"]["recommendations"])
        
        # MITRE ATT&CK recommendations
        mitre_report = self.mitre_attack_mapper.generate_mitre_attack_report(findings)
        all_recommendations.extend(mitre_report["recommendations"])
        
        # Risk aggregation recommendations
        aggregation_report = self.risk_aggregation_engine.generate_risk_aggregation_report(findings)
        all_recommendations.extend(aggregation_report["recommendations"])
        
        # Remediation recommendations
        remediation_report = self.remediation_engine.generate_remediation_report(findings, context)
        all_recommendations.extend(remediation_report["recommendations"])
        
        # Deduplicate and prioritize recommendations
        unique_recommendations = list(set(all_recommendations))
        prioritized_recommendations = self._prioritize_recommendations(unique_recommendations, findings)
        
        # Create metrics
        metrics = [
            ReportMetric(
                name="Total Recommendations",
                value=len(prioritized_recommendations),
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="High Priority Actions",
                value=len([r for r in prioritized_recommendations if "URGENT" in r or "CRITICAL" in r]),
                unit="count",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            )
        ]
        
        # Create visualizations
        visualizations = [
            {
                "type": "list",
                "title": "Prioritized Recommendations",
                "data": [
                    {
                        "priority": self._get_recommendation_priority(rec),
                        "recommendation": rec,
                        "category": self._categorize_recommendation(rec)
                    }
                    for rec in prioritized_recommendations[:20]  # Top 20
                ]
            }
        ]
        
        return ReportSection(
            section_id="key_recommendations",
            title="Key Recommendations",
            description="Prioritized recommendations for improving security posture",
            metrics=metrics,
            visualizations=visualizations,
            recommendations=[]  # No additional recommendations needed
        )
    
    def _generate_dashboard_data(self, findings: List[SecurityFinding],
                                 dashboard_type: str = "executive_dashboard",
                                 context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate dashboard data."""
        context = context or {}
        dashboard_config = self.dashboard_configs.get(dashboard_type, {})
        
        dashboard_data = {
            "dashboard_type": dashboard_type,
            "generated_at": datetime.utcnow().isoformat(),
            "refresh_interval": dashboard_config.get("refresh_interval", 300),
            "widgets": []
        }
        
        # Generate widget data
        for widget_name in dashboard_config.get("widgets", []):
            widget_data = self._generate_widget_data(widget_name, findings, context)
            if widget_data:
                dashboard_data["widgets"].append(widget_data)
        
        return dashboard_data
    
    def _generate_widget_data(self, widget_name: str, 
                             findings: List[SecurityFinding],
                             context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate data for a specific widget."""
        widget_generators = {
            "overall_risk_gauge": self._generate_risk_gauge_widget,
            "compliance_status_chart": self._generate_compliance_chart_widget,
            "critical_findings_counter": self._generate_critical_findings_widget,
            "trend_chart": self._generate_trend_chart_widget,
            "risk_heatmap": self._generate_risk_heatmap_widget,
            "findings_by_severity": self._generate_findings_by_severity_widget,
            "findings_by_resource_type": self._generate_findings_by_resource_type_widget,
            "mitre_attack_matrix": self._generate_mitre_attack_matrix_widget,
            "threat_intelligence": self._generate_threat_intelligence_widget,
            "remediation_status": self._generate_remediation_status_widget,
            "compliance_scores": self._generate_compliance_scores_widget,
            "framework_breakdown": self._generate_framework_breakdown_widget,
            "violation_tracking": self._generate_violation_tracking_widget,
            "audit_status": self._generate_audit_status_widget,
            "remediation_timeline": self._generate_remediation_timeline_widget,
            "remediation_queue": self._generate_remediation_queue_widget,
            "automation_metrics": self._generate_automation_metrics_widget,
            "resource_health": self._generate_resource_health_widget,
            "performance_indicators": self._generate_performance_indicators_widget,
            "alert_summary": self._generate_alert_summary_widget,
            "kpi_metrics": self._generate_kpi_metrics_widget,
            "real_time_status": self._generate_real_time_status_widget,
            "drill_down_data": self._generate_drill_down_data_widget
        }
        
        generator = widget_generators.get(widget_name)
        if generator:
            return generator(findings, context)
        
        return None
    
    def _generate_risk_gauge_widget(self, findings: List[SecurityFinding], 
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall risk gauge widget."""
        risk_score = self.risk_engine.calculate_overall_risk_score(findings, context)
        risk_level = self.risk_engine.get_risk_level(risk_score)
        
        return {
            "widget_type": "gauge",
            "title": "Overall Risk Score",
            "data": {
                "value": risk_score,
                "max": 100,
                "thresholds": [20, 40, 60, 80],
                "levels": ["Minimal", "Low", "Medium", "High", "Critical"],
                "current_level": risk_level
            },
            "metadata": {
                "updated_at": datetime.utcnow().isoformat(),
                "total_findings": len(findings)
            }
        }
    
    def _generate_compliance_chart_widget(self, findings: List[SecurityFinding], 
                                         context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance status chart widget."""
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        
        return {
            "widget_type": "bar_chart",
            "title": "Compliance Status",
            "data": [
                {
                    "framework": framework,
                    "score": assessment["compliance_score"],
                    "violations": len(assessment["violations"])
                }
                for framework, assessment in compliance_report["framework_assessments"].items()
            ],
            "metadata": {
                "updated_at": datetime.utcnow().isoformat(),
                "average_score": compliance_report["summary"]["average_compliance_score"]
            }
        }
    
    def _generate_critical_findings_widget(self, findings: List[SecurityFinding], 
                                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate critical findings counter widget."""
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        
        return {
            "widget_type": "counter",
            "title": "Critical Findings",
            "data": {
                "count": critical_count,
                "total": len(findings),
                "percentage": round((critical_count / len(findings)) * 100, 1) if findings else 0
            },
            "metadata": {
                "updated_at": datetime.utcnow().isoformat(),
                "alert_threshold": 0  # Alert if any critical findings
            }
        }
    
    def _generate_trend_chart_widget(self, findings: List[SecurityFinding], 
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate trend chart widget."""
        # This would use historical data in a real implementation
        # For now, return mock trend data
        return {
            "widget_type": "line_chart",
            "title": "Risk Trend (30 Days)",
            "data": {
                "labels": [f"Day {i}" for i in range(1, 31)],
                "datasets": [
                    {
                        "label": "Risk Score",
                        "data": [45 + i * 0.5 for i in range(30)],  # Mock data
                        "borderColor": "#FF6384",
                        "fill": False
                    }
                ]
            },
            "metadata": {
                "updated_at": datetime.utcnow().isoformat(),
                "trend": "increasing"
            }
        }
    
    def _generate_risk_heatmap_widget(self, findings: List[SecurityFinding], 
                                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk heatmap widget."""
        heatmap_data = self.risk_engine.generate_risk_heatmap(findings)
        
        return {
            "widget_type": "heatmap",
            "title": "Risk Heatmap",
            "data": heatmap_data,
            "metadata": {
                "updated_at": datetime.utcnow().isoformat(),
                "resource_types": list(ResourceType)
            }
        }
    
    # Additional widget generators would be implemented here...
    
    def _calculate_risk_trend(self, historical_data: Optional[List[ScanResult]]) -> Dict[str, Any]:
        """Calculate risk trend from historical data."""
        if not historical_data or len(historical_data) < 2:
            return {
                "trend": "stable",
                "velocity": 0.0,
                "previous_score": 0,
                "findings_trend": "stable",
                "previous_findings": 0
            }
        
        # Sort by timestamp
        sorted_scans = sorted(historical_data, key=lambda x: x.scan_timestamp)
        
        # Get most recent and previous scans
        current = sorted_scans[-1]
        previous = sorted_scans[-2]
        
        # Calculate trend
        if current.risk_score > previous.risk_score:
            trend = "increasing"
        elif current.risk_score < previous.risk_score:
            trend = "decreasing"
        else:
            trend = "stable"
        
        # Calculate velocity (points per day)
        days_diff = (current.scan_timestamp - previous.scan_timestamp).days
        velocity = (current.risk_score - previous.risk_score) / days_diff if days_diff > 0 else 0
        
        # Calculate findings trend
        if current.total_findings > previous.total_findings:
            findings_trend = "increasing"
        elif current.total_findings < previous.total_findings:
            findings_trend = "decreasing"
        else:
            findings_trend = "stable"
        
        return {
            "trend": trend,
            "velocity": velocity,
            "previous_score": previous.risk_score,
            "findings_trend": findings_trend,
            "previous_findings": previous.total_findings
        }
    
    def _calculate_findings_trend(self, historical_data: Optional[List[ScanResult]]) -> Dict[str, Any]:
        """Calculate findings trend from historical data."""
        if not historical_data or len(historical_data) < 2:
            return {
                "trend": "stable",
                "previous_count": 0
            }
        
        sorted_scans = sorted(historical_data, key=lambda x: x.scan_timestamp)
        current = sorted_scans[-1]
        previous = sorted_scans[-2]
        
        if current.total_findings > previous.total_findings:
            trend = "increasing"
        elif current.total_findings < previous.total_findings:
            trend = "decreasing"
        else:
            trend = "stable"
        
        return {
            "trend": trend,
            "previous_count": previous.total_findings
        }
    
    def _get_severity_distribution(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Get severity distribution for visualization."""
        severity_counts = Counter(finding.severity.value for finding in findings)
        
        return {
            "labels": list(severity_counts.keys()),
            "datasets": [
                {
                    "data": list(severity_counts.values()),
                    "backgroundColor": [
                        "#FF6384",  # Critical - Red
                        "#FF9F40",  # High - Orange
                        "#FFCD56",  # Medium - Yellow
                        "#4BC0C0",  # Low - Teal
                        "#9966FF"   # Info - Purple
                    ]
                }
            ]
        }
    
    def _get_risk_trend_data(self, historical_data: Optional[List[ScanResult]]) -> Dict[str, Any]:
        """Get risk trend data for visualization."""
        if not historical_data:
            return {
                "labels": [],
                "datasets": []
            }
        
        sorted_scans = sorted(historical_data, key=lambda x: x.scan_timestamp)
        
        return {
            "labels": [scan.scan_timestamp.strftime("%Y-%m-%d") for scan in sorted_scans],
            "datasets": [
                {
                    "label": "Risk Score",
                    "data": [scan.risk_score for scan in sorted_scans],
                    "borderColor": "#FF6384",
                    "fill": False
                }
            ]
        }
    
    def _get_findings_trend_data(self, historical_data: Optional[List[ScanResult]]) -> Dict[str, Any]:
        """Get findings trend data for visualization."""
        if not historical_data:
            return {
                "labels": [],
                "datasets": []
            }
        
        sorted_scans = sorted(historical_data, key=lambda x: x.scan_timestamp)
        
        return {
            "labels": [scan.scan_timestamp.strftime("%Y-%m-%d") for scan in sorted_scans],
            "datasets": [
                {
                    "label": "Total Findings",
                    "data": [scan.total_findings for scan in sorted_scans],
                    "borderColor": "#36A2EB",
                    "fill": False
                }
            ]
        }
    
    def _get_critical_findings_by_type(self, critical_findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Get critical findings by resource type."""
        type_counts = Counter(finding.resource_type.value for finding in critical_findings)
        
        return {
            "labels": list(type_counts.keys()),
            "datasets": [
                {
                    "label": "Critical Findings",
                    "data": list(type_counts.values()),
                    "backgroundColor": "#FF6384"
                }
            ]
        }
    
    def _generate_risk_recommendations(self, risk_score: int, findings: List[SecurityFinding]) -> List[str]:
        """Generate risk-based recommendations."""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("CRITICAL: Immediate action required to reduce critical risk level")
        elif risk_score >= 60:
            recommendations.append("HIGH: Prioritize risk reduction activities")
        elif risk_score >= 40:
            recommendations.append("MEDIUM: Continue risk management efforts")
        else:
            recommendations.append("LOW: Maintain current security posture")
        
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical findings immediately")
        
        return recommendations
    
    def _generate_trend_recommendations(self, risk_trend: Dict[str, Any], 
                                       findings_trend: Dict[str, Any]) -> List[str]:
        """Generate trend-based recommendations."""
        recommendations = []
        
        if risk_trend["trend"] == "increasing":
            recommendations.append("Risk score is increasing - investigate and address root causes")
        elif risk_trend["trend"] == "decreasing":
            recommendations.append("Risk score is decreasing - continue current security efforts")
        
        if findings_trend["trend"] == "increasing":
            recommendations.append("Number of findings is increasing - review security controls")
        elif findings_trend["trend"] == "decreasing":
            recommendations.append("Number of findings is decreasing - security improvements effective")
        
        return recommendations
    
    def _prioritize_recommendations(self, recommendations: List[str], 
                                  findings: List[SecurityFinding]) -> List[str]:
        """Prioritize recommendations based on impact and urgency."""
        # Simple prioritization - in practice, this would be more sophisticated
        priority_keywords = {
            "urgent": ["URGENT", "CRITICAL", "IMMEDIATE"],
            "high": ["HIGH", "PRIORITY", "IMPORTANT"],
            "medium": ["MEDIUM", "CONSIDER", "REVIEW"],
            "low": ["LOW", "MONITOR", "CONTINUE"]
        }
        
        prioritized = []
        
        # Add urgent recommendations first
        for rec in recommendations:
            if any(keyword in rec for keyword in priority_keywords["urgent"]):
                prioritized.append(rec)
        
        # Add high priority recommendations
        for rec in recommendations:
            if any(keyword in rec for keyword in priority_keywords["high"]) and rec not in prioritized:
                prioritized.append(rec)
        
        # Add medium priority recommendations
        for rec in recommendations:
            if any(keyword in rec for keyword in priority_keywords["medium"]) and rec not in prioritized:
                prioritized.append(rec)
        
        # Add remaining recommendations
        for rec in recommendations:
            if rec not in prioritized:
                prioritized.append(rec)
        
        return prioritized
    
    def _get_recommendation_priority(self, recommendation: str) -> str:
        """Get priority level for a recommendation."""
        if any(keyword in recommendation for keyword in ["URGENT", "CRITICAL", "IMMEDIATE"]):
            return "urgent"
        elif any(keyword in recommendation for keyword in ["HIGH", "PRIORITY", "IMPORTANT"]):
            return "high"
        elif any(keyword in recommendation for keyword in ["MEDIUM", "CONSIDER", "REVIEW"]):
            return "medium"
        else:
            return "low"
    
    def _categorize_recommendation(self, recommendation: str) -> str:
        """Categorize a recommendation."""
        if any(keyword in recommendation for keyword in ["remediation", "fix", "address"]):
            return "remediation"
        elif any(keyword in recommendation for keyword in ["compliance", "audit", "policy"]):
            return "compliance"
        elif any(keyword in recommendation for keyword in ["monitor", "review", "assess"]):
            return "monitoring"
        elif any(keyword in recommendation for keyword in ["implement", "deploy", "configure"]):
            return "implementation"
        else:
            return "general"
    
    def _generate_report_summary(self, findings: List[SecurityFinding], 
                               sections: List[ReportSection],
                               context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report summary."""
        return {
            "total_findings": len(findings),
            "critical_findings": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high_findings": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "overall_risk_score": self.risk_engine.calculate_overall_risk_score(findings, context),
            "sections_generated": len(sections),
            "key_insights": self._extract_key_insights(findings, sections),
            "action_items": len([rec for section in sections for rec in section.recommendations])
        }
    
    def _generate_report_metadata(self, report_type: ReportType, 
                                 time_range: TimeRange,
                                 subscription_id: Optional[str],
                                 context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report metadata."""
        return {
            "report_type": report_type.value,
            "time_range": time_range.value,
            "subscription_id": subscription_id,
            "context_keys": list(context.keys()),
            "engines_used": [
                "risk_scoring",
                "compliance_mapping",
                "threat_modeling",
                "business_impact",
                "mitre_attack",
                "risk_aggregation",
                "risk_tolerance",
                "remediation_assessment"
            ],
            "version": "1.0.0"
        }
    
    def _extract_key_insights(self, findings: List[SecurityFinding], 
                            sections: List[ReportSection]) -> List[str]:
        """Extract key insights from report sections."""
        insights = []
        
        # Risk insights
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        if critical_count > 0:
            insights.append(f"{critical_count} critical findings require immediate attention")
        
        # Compliance insights
        compliance_section = next((s for s in sections if s.section_id == "compliance_status"), None)
        if compliance_section:
            avg_score = next((m.value for m in compliance_section.metrics if m.name == "Overall Compliance Score"), 0)
            if avg_score < 80:
                insights.append(f"Compliance score ({avg_score}%) below acceptable threshold")
        
        # Trend insights
        trend_section = next((s for s in sections if s.section_id == "trending_analysis"), None)
        if trend_section:
            risk_trend = next((m.value for m in trend_section.metrics if m.name == "Risk Trend"), "stable")
            if risk_trend == "increasing":
                insights.append("Risk score trending upward - investigation required")
        
        return insights
    
    # Additional section generators would be implemented here...
    # For brevity, I'm including a few key ones as examples
    
    def _generate_risk_assessment_section(self, findings: List[SecurityFinding],
                                         time_range: TimeRange,
                                         subscription_id: Optional[str],
                                         context: Dict[str, Any],
                                         historical_data: Optional[List[ScanResult]]) -> ReportSection:
        """Generate detailed risk assessment section."""
        # Calculate detailed risk metrics
        risk_summary = self.risk_engine.generate_risk_summary(findings)
        
        metrics = [
            ReportMetric(
                name="Overall Risk Score",
                value=risk_summary["overall_risk_score"],
                unit="score",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="Risk Level",
                value=risk_summary["risk_level"],
                unit="level",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            ),
            ReportMetric(
                name="Attack Surface Score",
                value=sum(self.risk_engine.calculate_attack_surface_score(findings).values()),
                unit="score",
                trend="stable",
                comparison_value=None,
                comparison_period=""
            )
        ]
        
        visualizations = [
            {
                "type": "heatmap",
                "title": "Risk Heatmap by Resource Type",
                "data": self.risk_engine.generate_risk_heatmap(findings)
            },
            {
                "type": "radar_chart",
                "title": "Attack Surface Analysis",
                "data": self.risk_engine.calculate_attack_surface_score(findings)
            }
        ]
        
        recommendations = risk_summary["recommendations"]
        
        return ReportSection(
            section_id="risk_assessment",
            title="Detailed Risk Assessment",
            description="Comprehensive risk analysis with advanced metrics",
            metrics=metrics,
            visualizations=visualizations,
            recommendations=recommendations
        )
    
    def export_report(self, report: SecurityReport, 
                      format: ReportFormat = ReportFormat.JSON) -> str:
        """Export report in specified format."""
        if format == ReportFormat.JSON:
            return self._export_to_json(report)
        elif format == ReportFormat.HTML:
            return self._export_to_html(report)
        elif format == ReportFormat.CSV:
            return self._export_to_csv(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_to_json(self, report: SecurityReport) -> str:
        """Export report to JSON format."""
        report_dict = {
            "report_id": report.report_id,
            "report_type": report.report_type.value,
            "generated_at": report.generated_at.isoformat(),
            "time_range": report.time_range.value,
            "subscription_id": report.subscription_id,
            "summary": report.summary,
            "metadata": report.metadata,
            "sections": []
        }
        
        for section in report.sections:
            section_dict = {
                "section_id": section.section_id,
                "title": section.title,
                "description": section.description,
                "metrics": [
                    {
                        "name": m.name,
                        "value": m.value,
                        "unit": m.unit,
                        "trend": m.trend,
                        "comparison_value": m.comparison_value,
                        "comparison_period": m.comparison_period
                    }
                    for m in section.metrics
                ],
                "visualizations": section.visualizations,
                "recommendations": section.recommendations
            }
            report_dict["sections"].append(section_dict)
        
        return json.dumps(report_dict, indent=2)
    
    def _export_to_html(self, report: SecurityReport) -> str:
        """Export report to HTML format."""
        # Simplified HTML export - in practice, this would use a proper templating engine
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report.report_type.value.replace('_', ' ').title()} Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .metric {{ margin: 10px 0; }}
                .recommendation {{ background-color: #e8f4fd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report.report_type.value.replace('_', ' ').title()} Report</h1>
                <p>Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Subscription: {report.subscription_id}</p>
                <p>Time Range: {report.time_range.value.replace('_', ' ').title()}</p>
            </div>
        """
        
        for section in report.sections:
            html += f"""
            <div class="section">
                <h2>{section.title}</h2>
                <p>{section.description}</p>
                <h3>Key Metrics</h3>
            """
            
            for metric in section.metrics:
                html += f"""
                <div class="metric">
                    <strong>{metric.name}:</strong> {metric.value} {metric.unit}
                    {f'(Trend: {metric.trend})' if metric.trend else ''}
                </div>
                """
            
            if section.recommendations:
                html += "<h3>Recommendations</h3>"
                for rec in section.recommendations:
                    html += f'<div class="recommendation">{rec}</div>'
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _export_to_csv(self, report: SecurityReport) -> str:
        """Export report to CSV format."""
        # Simplified CSV export - in practice, this would be more comprehensive
        csv_lines = ["Section,Metric,Value,Unit,Trend"]
        
        for section in report.sections:
            for metric in section.metrics:
                csv_lines.append(f'"{section.title}","{metric.name}","{metric.value}","{metric.unit}","{metric.trend}"')
        
        return "\n".join(csv_lines)


# Global reporting engine instance
reporting_engine = ReportingEngine()
