"""
SQL Injection TUI - Textual Interface
Version: 2.3.1
"""

import asyncio
from datetime import datetime
from typing import List, Dict, Optional

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Input, Button, Label, TextArea, 
    Select, Static, ProgressBar, DataTable, RichLog,
    TabbedContent, TabPane, Checkbox, LoadingIndicator,
    Digits, Switch
)
from textual.screen import Screen
from textual.reactive import reactive
from textual.binding import Binding
from textual.message import Message

from core import ScanOrchestrator, Vulnerability, PayloadUpdater


class DashboardScreen(Screen):
    """Main dashboard screen"""
    
    BINDINGS = [
        Binding("ctrl+n", "new_scan", "New Scan"),
        Binding("ctrl+s", "start_scan", "Start Scan"),
        Binding("ctrl+u", "update_payloads", "Update Payloads"),
        Binding("ctrl+q", "app.quit", "Quit"),
        Binding("f2", "show_results", "Results"),
        Binding("f3", "show_config", "Config"),
    ]
    
    def __init__(self, orchestrator: ScanOrchestrator):
        super().__init__()
        self.orchestrator = orchestrator
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="dashboard-container"):
            # Target section
            with Container(id="target-section"):
                yield Label("TARGET")
                yield Input(placeholder="http://target.com/page.php?id=1", id="url-input")
                with Horizontal():
                    yield Select([("GET", "GET"), ("POST", "POST")], prompt="Method", id="method-select")
                    yield Input(placeholder="id=1&user=admin", id="params-input")
                    yield Button("Edit Params", id="edit-params-btn")
            
            # Scan config
            with Container(id="config-section"):
                yield Label("SCAN CONFIG")
                with Horizontal():
                    yield Input(value="5", id="concurrency-input", placeholder="Concurrency")
                    yield Input(value="10", id="timeout-input", placeholder="Timeout (s)")
                    yield Input(value="0", id="delay-input", placeholder="Delay (ms)")
                with Horizontal():
                    yield Input(value="http://127.0.0.1:8080", id="proxy-input", placeholder="Proxy")
                    yield Checkbox(label="Use Cookies", id="use-cookies")
                with Horizontal():
                    yield Checkbox(label="Error", value=True, id="tech-error")
                    yield Checkbox(label="Time", value=True, id="tech-time")
                    yield Checkbox(label="Boolean", value=True, id="tech-boolean")
                    yield Checkbox(label="Union", value=True, id="tech-union")
            
            # Headers
            with Container(id="headers-section"):
                yield Label("HEADERS")
                yield Input(value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", id="user-agent")
                yield Input(placeholder="Cookie: PHPSESSID=abc123", id="cookie-input")
                yield Button("Add Custom Header", id="add-header-btn")
            
            # Actions
            with Horizontal(id="actions"):
                yield Button("START SCAN", variant="success", id="start-btn")
                yield Button("PAUSE", variant="warning", id="pause-btn", disabled=True)
                yield Button("STOP", variant="error", id="stop-btn", disabled=True)
                yield Button("UPDATE PAYLOADS", variant="primary", id="update-btn")
            
            # Status bar
            with Horizontal(id="status-bar"):
                yield Label("Payloads: v2026.07.28 | 847 signatures | Next update: 6 days", id="status-label")
        
        yield Footer()
    
    @on(Button.Pressed, "#start-btn")
    async def start_scan(self):
        """Start scan button handler"""
        url = self.query_one("#url-input", Input).value
        params_str = self.query_one("#params-input", Input).value
        
        if not url:
            self.query_one("#status-label", Label).update("ERROR: URL is required")
            return
        
        # Parse parameters
        params = self.orchestrator.parse_parameters(url, params_str)
        if not params:
            self.query_one("#status-label", Label).update("ERROR: No parameters found")
            return
        
        # Get techniques
        techniques = []
        if self.query_one("#tech-error", Checkbox).value:
            techniques.append("error")
        if self.query_one("#tech-time", Checkbox).value:
            techniques.append("time")
        if self.query_one("#tech-boolean", Checkbox).value:
            techniques.append("boolean")
        if self.query_one("#tech-union", Checkbox).value:
            techniques.append("union")
        
        if not techniques:
            self.query_one("#status-label", Label).update("ERROR: Select at least one technique")
            return
        
        # Update config
        try:
            concurrency = int(self.query_one("#concurrency-input", Input).value)
        except:
            concurrency = 5
        self.orchestrator.config['concurrency'] = concurrency
        
        # Disable buttons
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#pause-btn", Button).disabled = False
        self.query_one("#stop-btn", Button).disabled = False
        
        # Switch to scan view
        self.app.push_screen("scan", {
            "url": url,
            "params": params,
            "techniques": techniques
        })
    
    @on(Button.Pressed, "#update-btn")
    async def update_payloads(self):
        """Update payloads"""
        self.query_one("#status-label", Label).update("Updating payloads...")
        updater = PayloadUpdater()
        result = await updater.update()
        self.query_one("#status-label", Label).update(f"Update: {result['message']}")
    
    def action_new_scan(self):
        """Reset for new scan"""
        self.query_one("#url-input", Input).value = ""
        self.query_one("#params-input", Input).value = ""
        self.query_one("#status-label", Label).update("Ready")
    
    def action_show_results(self):
        """Show results screen"""
        self.app.push_screen("results")
    
    def action_show_config(self):
        """Show config screen"""
        self.app.push_screen("config")


class ScanScreen(Screen):
    """Live scanning screen"""
    
    BINDINGS = [
        Binding("p", "pause", "Pause"),
        Binding("r", "resume", "Resume"),
        Binding("s", "stop", "Stop"),
        Binding("v", "show_results", "View Results"),
        Binding("e", "export", "Export"),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]
    
    def __init__(self, orchestrator: ScanOrchestrator):
        super().__init__()
        self.orchestrator = orchestrator
        self.scan_task = None
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="scan-container"):
            # Header info
            with Horizontal(id="scan-header"):
                yield Label("SCANNING: ", id="scan-url-label")
                yield Label("", id="scan-url-value")
                yield Label("Elapsed: 00:00", id="scan-elapsed")
            
            # Progress
            with Horizontal(id="progress-container"):
                yield ProgressBar(total=100, id="scan-progress")
                yield Label("0%", id="progress-percent")
            
            # Log panel
            with Container(id="log-container"):
                yield Label("LIVE LOG")
                yield RichLog(id="scan-log", wrap=True)
            
            # Status
            with Horizontal(id="scan-status"):
                yield Label("Current: ", id="current-label")
                yield Label("Found: 0/0", id="found-label")
                yield Label("Speed: 0 req/sec", id="speed-label")
                yield Label("ETA: --:--", id="eta-label")
            
            # Vulnerabilities found
            with Container(id="vuln-container"):
                yield Label("VULNERABILITIES FOUND")
                with ScrollableContainer(id="vuln-scroll"):
                    yield DataTable(id="vuln-table")
            
            # Actions
            with Horizontal(id="scan-actions"):
                yield Button("Pause", variant="warning", id="scan-pause-btn")
                yield Button("Resume", variant="success", id="scan-resume-btn", disabled=True)
                yield Button("Stop", variant="error", id="scan-stop-btn")
                yield Button("View Results", variant="primary", id="scan-results-btn")
                yield Button("Export", variant="primary", id="scan-export-btn")
        
        yield Footer()
    
    def on_mount(self):
        """Start scan when screen mounts"""
        # Get scan data from app
        data = self.app._scan_data
        url = data.get("url", "")
        params = data.get("params", {})
        techniques = data.get("techniques", [])
        
        self.query_one("#scan-url-value", Label).update(url)
        
        # Start scan task
        self.scan_task = asyncio.create_task(self._run_scan(url, params, techniques))
    
    async def _run_scan(self, url: str, params: Dict, techniques: List[str]):
        """Run scan and update UI"""
        log = self.query_one("#scan-log", RichLog)
        progress = self.query_one("#scan-progress", ProgressBar)
        percent_label = self.query_one("#progress-percent", Label)
        vuln_table = self.query_one("#vuln-table", DataTable)
        
        # Initialize table
        vuln_table.clear()
        vuln_table.add_columns("Param", "Technique", "DBMS", "Confidence", "Evidence")
        
        start_time = datetime.now()
        
        try:
            async for update in self.orchestrator.scan(url, params, techniques):
                if update.get("type") == "status":
                    log.write(f"[{datetime.now().strftime('%H:%M:%S')}] {update.get('message', '')}")
                    
                    # Update current label
                    current = update.get('current_param', '')
                    technique = update.get('technique', '')
                    self.query_one("#current-label", Label).update(f"Current: {current} ({technique})")
                
                elif update.get("type") == "progress":
                    prog = update.get('progress', 0) * 100
                    progress.progress = prog
                    percent_label.update(f"{prog:.0f}%")
                    
                    # Update ETA
                    elapsed = (datetime.now() - start_time).total_seconds()
                    processed = update.get('processed', 0)
                    total = update.get('total', 1)
                    if processed > 0:
                        eta = (elapsed / processed) * (total - processed)
                        minutes = int(eta // 60)
                        seconds = int(eta % 60)
                        self.query_one("#eta-label", Label).update(f"ETA: {minutes:02d}:{seconds:02d}")
                
                elif update.get("type") == "found":
                    vuln = update.get("vulnerability")
                    if vuln:
                        log.write(f"[{datetime.now().strftime('%H:%M:%S')}] FOUND: {vuln.parameter} - {vuln.technique}")
                        vuln_table.add_row(
                            vuln.parameter,
                            vuln.technique,
                            vuln.dbms,
                            vuln.confidence,
                            vuln.evidence[:30] + "..."
                        )
                        
                        # Update found count
                        found = len(self.orchestrator.get_results())
                        total_params = len(params)
                        self.query_one("#found-label", Label).update(f"Found: {found}/{total_params}")
                
                elif update.get("type") == "complete":
                    result = update.get("result")
                    log.write(f"[{datetime.now().strftime('%H:%M:%S')}] {update.get('message', '')}")
                    log.write(f"[{datetime.now().strftime('%H:%M:%S')}] Duration: {result.scan_duration:.2f}s")
                    log.write(f"[{datetime.now().strftime('%H:%M:%S')}] DBMS detected: {', '.join(result.dbms_detected) or 'None'}")
                    
                    # Reset buttons
                    self.query_one("#scan-pause-btn", Button).disabled = True
                    self.query_one("#scan-resume-btn", Button).disabled = True
                    self.query_one("#scan-stop-btn", Button).disabled = True
        
        except asyncio.CancelledError:
            log.write(f"[{datetime.now().strftime('%H:%M:%S')}] Scan stopped")
        except Exception as e:
            log.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {str(e)}")
    
    @on(Button.Pressed, "#scan-pause-btn")
    def pause_scan(self):
        """Pause scan"""
        self.orchestrator.pause()
        self.query_one("#scan-pause-btn", Button).disabled = True
        self.query_one("#scan-resume-btn", Button).disabled = False
    
    @on(Button.Pressed, "#scan-resume-btn")
    def resume_scan(self):
        """Resume scan"""
        self.orchestrator.resume()
        self.query_one("#scan-pause-btn", Button).disabled = False
        self.query_one("#scan-resume-btn", Button).disabled = True
    
    @on(Button.Pressed, "#scan-stop-btn")
    def stop_scan(self):
        """Stop scan"""
        self.orchestrator.stop()
        if self.scan_task:
            self.scan_task.cancel()
        
        self.query_one("#scan-pause-btn", Button).disabled = True
        self.query_one("#scan-resume-btn", Button).disabled = True
        self.query_one("#scan-stop-btn", Button).disabled = True
    
    def action_pause(self):
        self.pause_scan()
    
    def action_resume(self):
        self.resume_scan()
    
    def action_stop(self):
        self.stop_scan()
    
    def action_show_results(self):
        """Show results screen"""
        self.app.push_screen("results")
    
    def action_export(self):
        """Export results"""
        log = self.query_one("#scan-log", RichLog)
        results = self.orchestrator.get_results()
        if not results:
            log.write("[ERROR] No results to export")
            return
        
        # Simple export to file
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.write(f"SCAN RESULTS - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n\n")
                for vuln in results:
                    f.write(f"Parameter: {vuln.parameter}\n")
                    f.write(f"Technique: {vuln.technique}\n")
                    f.write(f"DBMS: {vuln.dbms}\n")
                    f.write(f"Confidence: {vuln.confidence}\n")
                    f.write(f"Payload: {vuln.payload}\n")
                    f.write(f"Evidence: {vuln.evidence}\n")
                    f.write("-" * 40 + "\n\n")
            
            log.write(f"[{datetime.now().strftime('%H:%M:%S')}] Exported to: {filename}")
        except Exception as e:
            log.write(f"[ERROR] Export failed: {str(e)}")


class ResultsScreen(Screen):
    """Results viewer screen"""
    
    BINDINGS = [
        Binding("f", "filter", "Filter"),
        Binding("e", "export", "Export"),
        Binding("escape", "app.pop_screen", "Back"),
    ]
    
    def __init__(self, orchestrator: ScanOrchestrator):
        super().__init__()
        self.orchestrator = orchestrator
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="results-container"):
            with Horizontal(id="results-header"):
                yield Label(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", id="results-title")
                with Horizontal():
                    yield Input(placeholder="Filter...", id="filter-input")
                    yield Select([("All", "all"), ("MySQL", "mysql"), ("PgSQL", "pgsql"), 
                                 ("MSSQL", "mssql"), ("SQLite", "sqlite")], 
                                prompt="Show", id="filter-select")
                    yield Button("Clear", id="clear-filter-btn")
            
            with Container(id="results-table-container"):
                yield DataTable(id="results-table")
            
            with Horizontal(id="results-actions"):
                yield Button("Export", variant="primary", id="export-results-btn")
                yield Button("Back", variant="default", id="back-btn")
        
        yield Footer()
    
    def on_mount(self):
        """Load results when screen mounts"""
        self._refresh_table()
    
    def _refresh_table(self, filter_text: str = "", filter_dbms: str = "all"):
        """Refresh results table"""
        table = self.query_one("#results-table", DataTable)
        table.clear()
        table.add_columns("#", "Parameter", "Technique", "DBMS", "Confidence", "Evidence")
        
        results = self.orchestrator.get_results()
        
        # Apply filters
        if filter_text:
            results = [r for r in results if filter_text.lower() in r.parameter.lower() or 
                      filter_text.lower() in r.evidence.lower()]
        if filter_dbms != "all":
            results = [r for r in results if r.dbms.lower() == filter_dbms.lower()]
        
        for idx, vuln in enumerate(results, 1):
            table.add_row(
                str(idx),
                vuln.parameter,
                vuln.technique,
                vuln.dbms,
                vuln.confidence,
                vuln.evidence[:50] + ("..." if len(vuln.evidence) > 50 else "")
            )
    
    @on(Input.Submitted, "#filter-input")
    def apply_filter(self):
        """Apply filter"""
        filter_text = self.query_one("#filter-input", Input).value
        filter_dbms = self.query_one("#filter-select", Select).value
        self._refresh_table(filter_text, filter_dbms)
    
    @on(Select.Changed, "#filter-select")
    def apply_select_filter(self):
        """Apply select filter"""
        filter_text = self.query_one("#filter-input", Input).value
        filter_dbms = self.query_one("#filter-select", Select).value
        self._refresh_table(filter_text, filter_dbms)
    
    @on(Button.Pressed, "#clear-filter-btn")
    def clear_filter(self):
        """Clear all filters"""
        self.query_one("#filter-input", Input).value = ""
        self.query_one("#filter-select", Select).value = "all"
        self._refresh_table("", "all")
    
    @on(Button.Pressed, "#export-results-btn")
    def export_results(self):
        """Export results to file"""
        results = self.orchestrator.get_results()
        if not results:
            self.query_one("#results-title", Label).update("No results to export")
            return
        
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.write(f"EXPORT - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n\n")
                for vuln in results:
                    f.write(f"Parameter: {vuln.parameter}\n")
                    f.write(f"Technique: {vuln.technique}\n")
                    f.write(f"DBMS: {vuln.dbms}\n")
                    f.write(f"Confidence: {vuln.confidence}\n")
                    f.write(f"Payload: {vuln.payload}\n")
                    f.write(f"Evidence: {vuln.evidence}\n")
                    f.write("-" * 40 + "\n\n")
            
            self.query_one("#results-title", Label).update(f"Exported to: {filename}")
        except Exception as e:
            self.query_one("#results-title", Label).update(f"Export failed: {str(e)}")
    
    @on(Button.Pressed, "#back-btn")
    def go_back(self):
        """Go back to previous screen"""
        self.app.pop_screen()
    
    def action_filter(self):
        """Focus filter input"""
        self.query_one("#filter-input", Input).focus()


class ConfigScreen(Screen):
    """Configuration screen"""
    
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("ctrl+s", "save_config", "Save"),
    ]
    
    def __init__(self, config: Dict):
        super().__init__()
        self.config = config
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="config-container"):
            yield Label("CONFIGURATION")
            
            with Container(id="config-fields"):
                yield Label("HTTP Settings")
                yield Input(value=str(self.config.get('timeout', 10)), id="cfg-timeout", placeholder="Timeout (s)")
                yield Input(value=str(self.config.get('max_retries', 3)), id="cfg-retries", placeholder="Max Retries")
                yield Checkbox(label="Verify SSL", value=self.config.get('verify_ssl', False), id="cfg-ssl")
                yield Checkbox(label="Follow Redirects", value=self.config.get('follow_redirects', True), id="cfg-redirect")
                
                yield Label("Proxy Settings")
                yield Input(value=self.config.get('proxy', ''), id="cfg-proxy", placeholder="Proxy URL")
                
                yield Label("Scan Settings")
                yield Input(value=str(self.config.get('concurrency', 5)), id="cfg-concurrency", placeholder="Concurrency")
                yield Input(value=str(self.config.get('delay', 0)), id="cfg-delay", placeholder="Delay (ms)")
            
            with Horizontal(id="config-actions"):
                yield Button("Save", variant="success", id="cfg-save-btn")
                yield Button("Cancel", variant="default", id="cfg-cancel-btn")
        
        yield Footer()
    
    @on(Button.Pressed, "#cfg-save-btn")
    def save_config(self):
        """Save configuration"""
        try:
            self.config['timeout'] = int(self.query_one("#cfg-timeout", Input).value)
            self.config['max_retries'] = int(self.query_one("#cfg-retries", Input).value)
            self.config['verify_ssl'] = self.query_one("#cfg-ssl", Checkbox).value
            self.config['follow_redirects'] = self.query_one("#cfg-redirect", Checkbox).value
            self.config['proxy'] = self.query_one("#cfg-proxy", Input).value
            self.config['concurrency'] = int(self.query_one("#cfg-concurrency", Input).value)
            self.config['delay'] = int(self.query_one("#cfg-delay", Input).value)
            
            self.app.pop_screen()
        except ValueError as e:
            self.query_one("#config-container", Container).mount(
                Label(f"ERROR: Invalid value - {str(e)}", id="config-error")
            )
    
    @on(Button.Pressed, "#cfg-cancel-btn")
    def cancel_config(self):
        """Cancel configuration changes"""
        self.app.pop_screen()
    
    def action_save_config(self):
        self.save_config()


class SQLInjectionApp(App):
    """Main application"""
    
    CSS = """
    #dashboard-container {
        padding: 1;
        height: 100%;
    }
    
    #target-section, #config-section, #headers-section {
        border: solid rgb(100, 100, 100);
        margin: 1;
        padding: 1;
    }
    
    #scan-container {
        padding: 1;
        height: 100%;
    }
    
    #log-container {
        height: 40%;
        border: solid rgb(100, 100, 100);
        margin: 1;
        padding: 1;
    }
    
    #vuln-container {
        height: 30%;
        border: solid rgb(100, 100, 100);
        margin: 1;
        padding: 1;
    }
    
    #vuln-scroll {
        height: 100%;
    }
    
    #scan-status {
        margin: 1;
        padding: 1;
        background: rgb(30, 30, 30);
    }
    
    #scan-actions {
        margin: 1;
        padding: 1;
        align: center middle;
    }
    
    #actions {
        margin: 1;
        padding: 1;
        align: center middle;
    }
    
    #status-bar {
        margin: 1;
        padding: 1;
        background: rgb(20, 20, 20);
    }
    
    #results-container {
        padding: 1;
        height: 100%;
    }
    
    #results-table-container {
        height: 80%;
        border: solid rgb(100, 100, 100);
        margin: 1;
        padding: 1;
    }
    
    #config-container {
        padding: 2;
        height: 100%;
    }
    
    #config-fields {
        border: solid rgb(100, 100, 100);
        margin: 1;
        padding: 2;
    }
    
    #config-actions {
        margin: 1;
        padding: 1;
        align: center middle;
    }
    
    Horizontal {
        margin: 0;
        padding: 0;
    }
    
    Button {
        margin: 0 1;
    }
    
    Input {
        margin: 0 1;
    }
    
    Checkbox {
        margin: 0 2;
    }
    
    Label {
        margin: 0 1;
    }
    
    .error {
        color: red;
    }
    
    .success {
        color: green;
    }
    
    .warning {
        color: yellow;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
    ]
    
    def __init__(self, config: Dict):
        super().__init__()
        self.config = config
        self.orchestrator = ScanOrchestrator(config)
        self._scan_data = {}
    
    def on_mount(self):
        """Initialize application"""
        # Register screens
        self.install_screen(DashboardScreen(self.orchestrator), "dashboard")
        self.install_screen(ScanScreen(self.orchestrator), "scan")
        self.install_screen(ResultsScreen(self.orchestrator), "results")
        self.install_screen(ConfigScreen(self.config), "config")
        
        # Start with dashboard
        self.push_screen("dashboard")
    
    def on_unmount(self):
        """Clean up on exit"""
        asyncio.create_task(self.orchestrator.close())
    
    def action_quit(self):
        """Quit application"""
        self.exit()
