"""Main report generator that coordinates all report formats."""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models import ScanResult, SecurityFinding
from .json_reporter import JSONReporter
from .html_reporter import HTMLReporter


class ReportGenerator:
    """Main report generator that supports multiple output formats."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.json_reporter = JSONReporter(output_dir)
        self.html_reporter = HTMLReporter(output_dir)
    
    def generate_all_reports(self, scan_result: ScanResult) -> Dict[str, str]:
        """Generate all supported report formats."""
        generated_files = {}
        
        try:
            # Generate JSON report
            json_file = self.json_reporter.generate_report(scan_result)
            generated_files['json'] = json_file
            
            # Generate HTML report
            html_file = self.html_reporter.generate_report(scan_result)
            generated_files['html'] = html_file
            
            # Generate summary JSON for quick overview
            summary_file = self._generate_quick_summary(scan_result)
            generated_files['summary'] = summary_file
            
        except Exception as e:
            print(f"Error generating reports: {str(e)}")
        
        return generated_files
    
    def generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate only JSON report."""
        return self.json_reporter.generate_report(scan_result)
    
    def generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate only HTML report."""
        return self.html_reporter.generate_report(scan_result)
    
    def generate_multi_subscription_report(self, scan_results: List[ScanResult]) -> str:
        """Generate a consolidated report for multiple subscriptions."""
        return self.json_reporter.generate_summary_report(scan_results)
    
    def export_findings(self, findings: List[SecurityFinding], format_type: str = "detailed") -> str:
        """Export findings in specified format."""
        return self.json_reporter.export_findings(findings, format_type)
    
    def _generate_quick_summary(self, scan_result: ScanResult) -> str:
        """Generate a quick summary JSON file."""
        summary_data = {
            "subscription_id": scan_result.subscription_id,
            "scan_timestamp": scan_result.scan_timestamp.isoformat(),
            "overall_risk_score": scan_result.risk_score,
            "total_findings": scan_result.total_findings,
            "findings_by_severity": scan_result.findings_by_severity,
            "critical_findings": [
                {
                    "title": finding.title,
                    "resource_name": finding.resource_name,
                    "risk_score": finding.risk_score
                }
                for finding in scan_result.findings
                if finding.severity == "critical"
            ]
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"quick_summary_{scan_result.subscription_id}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        import json
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def list_reports(self) -> List[Dict[str, Any]]:
        """List all generated reports."""
        reports = []
        
        if not os.path.exists(self.output_dir):
            return reports
        
        for filename in os.listdir(self.output_dir):
            filepath = os.path.join(self.output_dir, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                reports.append({
                    "filename": filename,
                    "filepath": filepath,
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "type": self._get_report_type(filename)
                })
        
        return sorted(reports, key=lambda x: x['created'], reverse=True)
    
    def _get_report_type(self, filename: str) -> str:
        """Determine report type from filename."""
        if filename.endswith('.html'):
            return 'HTML Report'
        elif filename.endswith('.json'):
            if 'summary' in filename.lower():
                return 'Summary Report'
            elif 'findings' in filename.lower():
                return 'Findings Export'
            else:
                return 'JSON Report'
        else:
            return 'Unknown'
    
    def cleanup_old_reports(self, days_to_keep: int = 30) -> int:
        """Clean up reports older than specified days."""
        import time
        
        if not os.path.exists(self.output_dir):
            return 0
        
        current_time = time.time()
        cutoff_time = current_time - (days_to_keep * 24 * 60 * 60)
        deleted_count = 0
        
        for filename in os.listdir(self.output_dir):
            filepath = os.path.join(self.output_dir, filename)
            if os.path.isfile(filepath):
                file_time = os.path.getmtime(filepath)
                if file_time < cutoff_time:
                    try:
                        os.remove(filepath)
                        deleted_count += 1
                    except Exception as e:
                        print(f"Error deleting {filename}: {str(e)}")
        
        return deleted_count
    
    def get_report_statistics(self) -> Dict[str, Any]:
        """Get statistics about generated reports."""
        reports = self.list_reports()
        
        if not reports:
            return {
                "total_reports": 0,
                "total_size": 0,
                "report_types": {},
                "latest_report": None
            }
        
        total_size = sum(report['size'] for report in reports)
        report_types = {}
        
        for report in reports:
            report_type = report['type']
            report_types[report_type] = report_types.get(report_type, 0) + 1
        
        return {
            "total_reports": len(reports),
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "report_types": report_types,
            "latest_report": reports[0] if reports else None,
            "oldest_report": reports[-1] if reports else None
        }
