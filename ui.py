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
                with ScrollableContainer(id
