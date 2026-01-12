"""Command-line interface for CSPM Scanner."""

import asyncio
import sys
from typing import Optional, List
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

from .models import ScanRequest, ResourceType, SeverityLevel
from .scanner_engine import scanner_engine
from .reports.report_generator import ReportGenerator
from .auth import auth_manager
from .config import settings

# CLI app
cli_app = typer.Typer(
    name="cspm-scanner",
    help="Cloud Security Posture Scanner - Azure security misconfiguration detector",
    no_args_is_help=True
)

# Console for rich output
console = Console()


@cli_app.command()
def scan(
    subscription_id: Optional[str] = typer.Option(
        None, 
        "--subscription", "-s", 
        help="Azure subscription ID to scan (scans all if not provided)"
    ),
    resource_types: Optional[List[str]] = typer.Option(
        None, 
        "--resource-type", "-r",
        help="Resource types to scan (can specify multiple)"
    ),
    min_severity: str = typer.Option(
        "low",
        "--severity", "-v",
        help="Minimum severity level to report (info, low, medium, high, critical)"
    ),
    output_format: str = typer.Option(
        "json",
        "--format", "-f",
        help="Output format (json, html, both)"
    ),
    output_dir: str = typer.Option(
        "./reports",
        "--output", "-o",
        help="Output directory for reports"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-V",
        help="Enable verbose output"
    )
):
    """Run security scan on Azure subscription(s)."""
    
    async def run_scan():
        try:
            # Parse severity level
            try:
                severity_level = SeverityLevel(min_severity.lower())
            except ValueError:
                console.print(f"[red]Invalid severity level: {min_severity}[/red]")
                console.print("Valid levels: info, low, medium, high, critical")
                raise typer.Exit(1)
            
            # Parse resource types
            parsed_resource_types = None
            if resource_types:
                parsed_resource_types = []
                for rt in resource_types:
                    try:
                        parsed_resource_types.append(ResourceType(rt))
                    except ValueError:
                        console.print(f"[red]Invalid resource type: {rt}[/red]")
                        console.print(f"Valid types: {[rt.value for rt in ResourceType]}")
                        raise typer.Exit(1)
            
            # Create scan request
            scan_request = ScanRequest(
                subscription_id=subscription_id,
                resource_types=parsed_resource_types,
                severity_threshold=severity_level
            )
            
            # Initialize report generator
            report_gen = ReportGenerator(output_dir)
            
            console.print(Panel.fit(
                "[bold blue]Cloud Security Posture Scanner[/bold blue]\n"
                "Starting security scan...",
                title="CSPM Scanner"
            ))
            
            # Run scan with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                if subscription_id:
                    task = progress.add_task(f"Scanning subscription {subscription_id}...", total=None)
                    scan_result = await scanner_engine.scan_subscription(subscription_id, scan_request)
                else:
                    task = progress.add_task("Scanning all subscriptions...", total=None)
                    scan_results = await scanner_engine.scan_all_subscriptions(scan_request)
                    # For multiple subscriptions, create a summary
                    if scan_results:
                        scan_result = scan_results[0]  # Use first result for report generation
                    else:
                        console.print("[red]No subscriptions found or accessible[/red]")
                        raise typer.Exit(1)
            
            # Display results
            _display_scan_results(scan_result, verbose)
            
            # Generate reports
            progress.update(task, description="Generating reports...")
            
            if output_format == "json":
                report_file = report_gen.generate_json_report(scan_result)
            elif output_format == "html":
                report_file = report_gen.generate_html_report(scan_result)
            elif output_format == "both":
                reports = report_gen.generate_all_reports(scan_result)
                report_file = f"Generated {len(reports)} reports"
            else:
                console.print(f"[red]Invalid output format: {output_format}[/red]")
                raise typer.Exit(1)
            
            progress.update(task, description="Scan completed!")
            
            console.print(f"\n[green]✓ Scan completed successfully![/green]")
            console.print(f"[blue]Report(s) generated: {report_file}[/blue]")
            
        except Exception as e:
            console.print(f"[red]Error during scan: {str(e)}[/red]")
            if verbose:
                import traceback
                console.print(traceback.format_exc())
            raise typer.Exit(1)
    
    # Run the async scan
    asyncio.run(run_scan())


@cli_app.command()
def list_subscriptions():
    """List all accessible Azure subscriptions."""
    
    try:
        console.print(Panel.fit(
            "[bold blue]Azure Subscriptions[/bold blue]",
            title="Available Subscriptions"
        ))
        
        subscriptions = auth_manager.list_subscriptions()
        
        if not subscriptions:
            console.print("[yellow]No subscriptions found or accessible[/yellow]")
            return
        
        table = Table(title="Subscriptions")
        table.add_column("Subscription ID", style="cyan")
        table.add_column("Display Name", style="magenta")
        table.add_column("Tenant ID", style="green")
        table.add_column("State", style="yellow")
        
        for sub in subscriptions:
            state_style = "green" if sub['state'] == "Enabled" else "red"
            table.add_row(
                sub['id'],
                sub['display_name'],
                sub['tenant_id'],
                f"[{state_style}]{sub['state']}[/{state_style}]"
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error listing subscriptions: {str(e)}[/red]")
        raise typer.Exit(1)


@cli_app.command()
def list_reports(
    output_dir: str = typer.Option(
        "./reports",
        "--output", "-o",
        help="Reports directory"
    )
):
    """List all generated reports."""
    
    try:
        report_gen = ReportGenerator(output_dir)
        reports = report_gen.list_reports()
        stats = report_gen.get_report_statistics()
        
        console.print(Panel.fit(
            "[bold blue]Generated Reports[/bold blue]",
            title="Report Summary"
        ))
        
        if not reports:
            console.print("[yellow]No reports found[/yellow]")
            return
        
        # Display statistics
        console.print(f"[bold]Total Reports:[/bold] {stats['total_reports']}")
        console.print(f"[bold]Total Size:[/bold] {stats['total_size_mb']} MB")
        
        if stats['report_types']:
            console.print("[bold]Report Types:[/bold]")
            for rt, count in stats['report_types'].items():
                console.print(f"  • {rt}: {count}")
        
        # Display reports table
        table = Table(title="Reports")
        table.add_column("Filename", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Size", style="green")
        table.add_column("Created", style="yellow")
        
        for report in reports[:20]:  # Show last 20 reports
            size_mb = report['size'] / (1024 * 1024)
            table.add_row(
                report['filename'],
                report['type'],
                f"{size_mb:.2f} MB",
                report['created'][:19]  # Remove microseconds
            )
        
        console.print(table)
        
        if len(reports) > 20:
            console.print(f"[dim]... and {len(reports) - 20} more reports[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error listing reports: {str(e)}[/red]")
        raise typer.Exit(1)


@cli_app.command()
def cleanup_reports(
    days: int = typer.Option(
        30,
        "--days", "-d",
        help="Delete reports older than this many days"
    ),
    output_dir: str = typer.Option(
        "./reports",
        "--output", "-o",
        help="Reports directory"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would be deleted without actually deleting"
    )
):
    """Clean up old reports."""
    
    try:
        report_gen = ReportGenerator(output_dir)
        
        if dry_run:
            # Just show what would be deleted
            reports = report_gen.list_reports()
            import time
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            
            old_reports = [
                r for r in reports 
                if time.mktime(time.strptime(r['created'][:19], "%Y-%m-%dT%H:%M:%S")) < cutoff_time
            ]
            
            console.print(f"[yellow]Dry run: {len(old_reports)} reports would be deleted[/yellow]")
            
            for report in old_reports[:10]:
                console.print(f"  • {report['filename']}")
            
            if len(old_reports) > 10:
                console.print(f"  ... and {len(old_reports) - 10} more")
        else:
            deleted_count = report_gen.cleanup_old_reports(days)
            console.print(f"[green]✓ Deleted {deleted_count} old reports[/green]")
        
    except Exception as e:
        console.print(f"[red]Error cleaning up reports: {str(e)}[/red]")
        raise typer.Exit(1)


@cli_app.command()
def version():
    """Show version information."""
    console.print(Panel.fit(
        "[bold blue]Cloud Security Posture Scanner[/bold blue]\n"
        f"Version: 1.0.0\n"
        f"Python: {sys.version.split()[0]}",
        title="Version Information"
    ))


def _display_scan_results(scan_result, verbose: bool = False):
    """Display scan results in a formatted table."""
    
    # Summary panel
    risk_level = _get_risk_level(scan_result.risk_score)
    risk_color = _get_risk_color(scan_result.risk_score)
    
    console.print(Panel.fit(
        f"[bold]Subscription:[/bold] {scan_result.subscription_name or scan_result.subscription_id}\n"
        f"[bold]Risk Score:[/bold] [{risk_color}]{scan_result.risk_score} ({risk_level})[/{risk_color}]\n"
        f"[bold]Resources Scanned:[/bold] {scan_result.total_resources_scanned}\n"
        f"[bold]Total Findings:[/bold] {scan_result.total_findings}\n"
        f"[bold]Duration:[/bold] {scan_result.scan_duration_seconds:.2f} seconds",
        title="Scan Summary"
    ))
    
    # Findings by severity
    if scan_result.findings_by_severity:
        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        for severity, count in scan_result.findings_by_severity.items():
            if count > 0:
                color = _get_severity_color(severity)
                table.add_row(f"[{color}]{severity.upper()}[/{color}]", str(count))
        
        console.print(table)
    
    # Top findings
    if scan_result.findings:
        console.print("\n[bold]Top Security Findings:[/bold]")
        
        for i, finding in enumerate(scan_result.findings[:10], 1):
            severity_color = _get_severity_color(finding.severity)
            console.print(f"\n{[cyan]}{i}. [{severity_color}]{finding.severity.upper()}[/{severity_color}] {finding.title}")
            console.print(f"   Resource: {finding.resource_name} ({finding.resource_type})")
            console.print(f"   Risk Score: {finding.risk_score}")
            
            if verbose:
                console.print(f"   Description: {finding.description}")
                console.print(f"   Recommendation: {finding.recommendation}")
        
        if len(scan_result.findings) > 10:
            console.print(f"\n[dim]... and {len(scan_result.findings) - 10} more findings[/dim]")


def _get_risk_level(score: int) -> str:
    """Get risk level description from score."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    else:
        return "Minimal"


def _get_risk_color(score: int) -> str:
    """Get color for risk score."""
    if score >= 80:
        return "red"
    elif score >= 60:
        return "yellow"
    elif score >= 40:
        return "blue"
    else:
        return "green"


def _get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "green",
        "info": "cyan"
    }
    return colors.get(severity.lower(), "white")


def main():
    """Main entry point for CLI."""
    cli_app()


if __name__ == "__main__":
    main()
