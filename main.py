#!/usr/bin/env python3
"""
SQL Injection TUI - Entry Point
Version: 2.3.1
"""

import sys
import asyncio
import argparse
from pathlib import Path
from typing import Dict

import yaml

from ui import SQLInjectionApp


def load_config(config_path: str = "config.yaml") -> Dict:
    """Load configuration from YAML file"""
    default_config = {
        "http": {
            "timeout": 10,
            "max_retries": 3,
            "verify_ssl": False,
            "follow_redirects": True,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        "scan": {
            "concurrency": 5,
            "delay": 0
        },
        "proxy": "",
        "headers": {},
        "cookies": {}
    }
    
    if Path(config_path).exists():
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                for section in user_config:
                    if section in default_config:
                        if isinstance(default_config[section], dict):
                            default_config[section].update(user_config[section])
                        else:
                            default_config[section] = user_config[section]
        except Exception as e:
            print(f"Warning: Failed to load config: {e}", file=sys.stderr)
    
    return default_config


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SQL Injection Testing Tool with Textual TUI"
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Configuration file path"
    )
    parser.add_argument(
        "--url",
        help="Target URL (optional, can be set in UI)"
    )
    parser.add_argument(
        "--params",
        help="Parameters string (optional, can be set in UI)"
    )
    parser.add_argument(
        "--export",
        help="Export results to file after scan"
    )
    parser.add_argument(
        "--update-payloads",
        action="store_true",
        help="Update payloads and exit"
    )
    return parser.parse_args()


async def update_payloads():
    """Update payloads and exit"""
    from core import PayloadUpdater
    updater = PayloadUpdater()
    print("Checking for updates...")
    result = await updater.update()
    print(f"Update result: {result['message']}")
    if result.get('updated', 0) > 0:
        print(f"Updated {result['updated']} payloads")
    sys.exit(0)


def main():
    """Main entry point"""
    args = parse_args()
    
    # Handle update-only mode
    if args.update_payloads:
        asyncio.run(update_payloads())
        return
    
    # Load configuration
    config = load_config(args.config)
    
    # Flatten config for orchestrator
    orchestrator_config = {
        **config.get('http', {}),
        **config.get('scan', {}),
        'proxy': config.get('proxy', ''),
        'headers': config.get('headers', {}),
        'cookies': config.get('cookies', {})
    }
    
    # Create and run app
    app = SQLInjectionApp(orchestrator_config)
    
    try:
        app.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Cleanup
        asyncio.run(app.orchestrator.close())


if __name__ == "__main__":
    main()
