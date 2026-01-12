"""HTML report generation for CSPM Scanner."""

import os
from datetime import datetime
from typing import List, Dict, Any

from ..models import ScanResult, SecurityFinding, SeverityLevel
from ..risk_scoring import risk_engine


class HTMLReporter:
    """Generates HTML security reports with interactive charts."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, scan_result: ScanResult) -> str:
        """Generate a comprehensive HTML security report."""
        html_content = self._build_html_report(scan_result)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cspm_report_{scan_result.subscription_id}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _build_html_report(self, scan_result: ScanResult) -> str:
        """Build the complete HTML report."""
        risk_summary = risk_engine.generate_risk_summary(scan_result.findings)
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Security Posture Report - {scan_result.subscription_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._build_header(scan_result)}
        {self._build_executive_summary(scan_result, risk_summary)}
        {self._build_risk_analysis(risk_summary)}
        {self._build_findings_section(scan_result.findings)}
        {self._build_resource_analysis(scan_result.findings)}
        {self._build_recommendations(scan_result.findings)}
        {self._build_footer()}
    </div>
    
    <script>
        {self._get_chart_scripts(scan_result, risk_summary)}
    </script>
</body>
</html>
        """
        
        return html_template
    
    def _get_css_styles(self) -> str:
        """Return CSS styles for the report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .section {
            background: white;
            margin-bottom: 30px;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        .section h3 {
            color: #34495e;
            margin: 20px 0 15px 0;
            font-size: 1.3em;
        }
        
        .risk-score {
            text-align: center;
            margin: 30px 0;
        }
        
        .risk-score-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            color: white;
            margin: 0 auto;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        .risk-critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .risk-high { background: linear-gradient(135deg, #f39c12, #e67e22); }
        .risk-medium { background: linear-gradient(135deg, #f1c40f, #f39c12); }
        .risk-low { background: linear-gradient(135deg, #2ecc71, #27ae60); }
        .risk-minimal { background: linear-gradient(135deg, #3498db, #2980b9); }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .metric-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .metric-label {
            color: #7f8c8d;
            margin-top: 5px;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #f39c12; color: white; }
        .severity-medium { background: #f1c40f; color: #2c3e50; }
        .severity-low { background: #2ecc71; color: white; }
        .severity-info { background: #3498db; color: white; }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .findings-table th {
            background: #34495e;
            color: white;
            font-weight: bold;
        }
        
        .findings-table tr:hover {
            background: #f8f9fa;
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            margin: 30px 0;
        }
        
        .recommendations-list {
            list-style: none;
        }
        
        .recommendations-list li {
            background: #ecf0f1;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        
        .priority-high { border-left-color: #e74c3c; }
        .priority-medium { border-left-color: #f39c12; }
        .priority-low { border-left-color: #2ecc71; }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            border-top: 1px solid #ecf0f1;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .section {
                padding: 20px;
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .findings-table {
                font-size: 0.9em;
            }
        }
        """
    
    def _build_header(self, scan_result: ScanResult) -> str:
        """Build the report header."""
        return f"""
        <div class="header">
            <h1>Azure Security Posture Report</h1>
            <div class="subtitle">
                Subscription: {scan_result.subscription_name or scan_result.subscription_id}<br>
                Scan Date: {scan_result.scan_timestamp.strftime('%B %d, %Y at %I:%M %p')}<br>
                Duration: {scan_result.scan_duration_seconds:.2f} seconds
            </div>
        </div>
        """
    
    def _build_executive_summary(self, scan_result: ScanResult, risk_summary: Dict) -> str:
        """Build the executive summary section."""
        risk_level = risk_engine.get_risk_level(scan_result.risk_score)
        risk_class = f"risk-{risk_level.lower()}"
        
        return f"""
        <div class="section">
            <h2>Executive Summary</h2>
            
            <div class="risk-score">
                <div class="risk-score-circle {risk_class}">
                    {scan_result.risk_score}
                </div>
                <div style="margin-top: 20px;">
                    <h3>Overall Risk Level: {risk_level}</h3>
                    <p>Based on {scan_result.total_findings} security findings across {scan_result.total_resources_scanned} resources</p>
                </div>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">{scan_result.total_resources_scanned}</div>
                    <div class="metric-label">Resources Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{scan_result.total_findings}</div>
                    <div class="metric-label">Total Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{scan_result.findings_by_severity.get('critical', 0)}</div>
                    <div class="metric-label">Critical Issues</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{scan_result.findings_by_severity.get('high', 0)}</div>
                    <div class="metric-label">High Issues</div>
                </div>
            </div>
        </div>
        """
    
    def _build_risk_analysis(self, risk_summary: Dict) -> str:
        """Build the risk analysis section."""
        return f"""
        <div class="section">
            <h2>Risk Analysis</h2>
            
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            
            <div class="chart-container">
                <canvas id="resourceTypeChart"></canvas>
            </div>
            
            <h3>Top Security Risks</h3>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Resource</th>
                        <th>Severity</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    {self._build_top_risks_table(risk_summary.get('top_risks', []))}
                </tbody>
            </table>
        </div>
        """
    
    def _build_findings_section(self, findings: List[SecurityFinding]) -> str:
        """Build the detailed findings section."""
        findings_html = ""
        for finding in findings[:50]:  # Limit to first 50 findings
            severity_class = f"severity-{finding.severity}"
            
            findings_html += f"""
            <tr>
                <td><span class="severity-badge {severity_class}">{finding.severity}</span></td>
                <td>{finding.title}</td>
                <td>{finding.resource_name}</td>
                <td>{finding.resource_type}</td>
                <td>{finding.risk_score}</td>
                <td>{finding.recommendation}</td>
            </tr>
            """
        
        return f"""
        <div class="section">
            <h2>Security Findings</h2>
            <p>Showing {min(50, len(findings))} of {len(findings)} total findings</p>
            
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Issue</th>
                        <th>Resource</th>
                        <th>Type</th>
                        <th>Risk Score</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_html}
                </tbody>
            </table>
        </div>
        """
    
    def _build_resource_analysis(self, findings: List[SecurityFinding]) -> str:
        """Build the resource analysis section."""
        from collections import Counter
        
        resource_types = Counter(finding.resource_type for finding in findings)
        locations = Counter(finding.location for finding in findings)
        
        resource_types_html = "".join([
            f"<tr><td>{resource_type}</td><td>{count}</td></tr>"
            for resource_type, count in resource_types.most_common(10)
        ])
        
        locations_html = "".join([
            f"<tr><td>{location}</td><td>{count}</td></tr>"
            for location, count in locations.most_common(10)
        ])
        
        return f"""
        <div class="section">
            <h2>Resource Analysis</h2>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px;">
                <div>
                    <h3>Findings by Resource Type</h3>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Resource Type</th>
                                <th>Findings</th>
                            </tr>
                        </thead>
                        <tbody>
                            {resource_types_html}
                        </tbody>
                    </table>
                </div>
                
                <div>
                    <h3>Findings by Location</h3>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Location</th>
                                <th>Findings</th>
                            </tr>
                        </thead>
                        <tbody>
                            {locations_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def _build_recommendations(self, findings: List[SecurityFinding]) -> str:
        """Build the recommendations section."""
        prioritized_findings = risk_engine.prioritize_findings(findings)
        recommendations = risk_engine._generate_recommendations(findings)
        
        recommendations_html = "".join([
            f'<li class="recommendations-list">{rec}</li>'
            for rec in recommendations
        ])
        
        return f"""
        <div class="section">
            <h2>Recommendations</h2>
            
            <h3>Priority Actions</h3>
            <ul class="recommendations-list">
                {recommendations_html}
            </ul>
            
            <h3>Top 10 Findings to Address</h3>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Resource</th>
                        <th>Issue</th>
                        <th>Effort</th>
                    </tr>
                </thead>
                <tbody>
                    {self._build_priority_table(prioritized_findings[:10])}
                </tbody>
            </table>
        </div>
        """
    
    def _build_footer(self) -> str:
        """Build the report footer."""
        return f"""
        <div class="footer">
            <p>Generated by Cloud Security Posture Scanner v1.0.0</p>
            <p>Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        """
    
    def _build_top_risks_table(self, top_risks: List[Dict]) -> str:
        """Build the top risks table HTML."""
        rows = ""
        for risk in top_risks:
            severity_class = f"severity-{risk['severity']}"
            rows += f"""
            <tr>
                <td>{risk['title']}</td>
                <td>{risk['resource_name']}</td>
                <td><span class="severity-badge {severity_class}">{risk['severity']}</span></td>
                <td>{risk['risk_score']}</td>
            </tr>
            """
        return rows
    
    def _build_priority_table(self, prioritized_findings: List[SecurityFinding]) -> str:
        """Build the priority recommendations table."""
        rows = ""
        for i, finding in enumerate(prioritized_findings, 1):
            priority = "P1" if finding.severity in ["critical", "high"] else "P2"
            effort = self._estimate_remediation_effort(finding)
            
            rows += f"""
            <tr>
                <td>{priority}</td>
                <td>{finding.resource_name}</td>
                <td>{finding.title}</td>
                <td>{effort}</td>
            </tr>
            """
        return rows
    
    def _estimate_remediation_effort(self, finding: SecurityFinding) -> str:
        """Estimate remediation effort."""
        low_effort_keywords = ["enable", "disable", "configure", "set"]
        medium_effort_keywords = ["implement", "deploy", "create"]
        high_effort_keywords = ["redesign", "migrate", "restructure"]
        
        title_lower = finding.title.lower()
        
        if any(keyword in title_lower for keyword in low_effort_keywords):
            return "Low"
        elif any(keyword in title_lower for keyword in medium_effort_keywords):
            return "Medium"
        elif any(keyword in title_lower for keyword in high_effort_keywords):
            return "High"
        else:
            return "Medium"
    
    def _get_chart_scripts(self, scan_result: ScanResult, risk_summary: Dict) -> str:
        """Return JavaScript for charts."""
        severity_data = scan_result.findings_by_severity
        
        return f"""
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [
                        {severity_data.get('critical', 0)},
                        {severity_data.get('high', 0)},
                        {severity_data.get('medium', 0)},
                        {severity_data.get('low', 0)},
                        {severity_data.get('info', 0)}
                    ],
                    backgroundColor: [
                        '#e74c3c',
                        '#f39c12',
                        '#f1c40f',
                        '#2ecc71',
                        '#3498db'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Findings by Severity'
                    }}
                }}
            }}
        }});
        
        // Resource Type Chart
        const resourceTypeCtx = document.getElementById('resourceTypeChart').getContext('2d');
        new Chart(resourceTypeCtx, {{
            type: 'bar',
            data: {{
                labels: {list(risk_summary.get('findings_by_severity', {}).keys())},
                datasets: [{{
                    label: 'Number of Findings',
                    data: {list(risk_summary.get('findings_by_severity', {}).values())},
                    backgroundColor: '#3498db'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Findings by Resource Type'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        """
