from typing import List, Optional, Dict
from pydantic import BaseModel, Field, HttpUrl, field_validator
import re

# Regex helpers for strict input validation
IP_OR_FQDN_REGEX = re.compile(
    r"^(?:"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"  # FQDN
    r"|(?:\d{1,3}\.){3}\d{1,3}"                                            # IPv4
    r"|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}"                           # IPv6
    r")$"
)

# ----------------- Port Scanner Models -----------------

class PortScanOptions(BaseModel):
    scan_type: str = Field(default="SYN", description="Type of scan: SYN or Connect")
    timing_template: int = Field(default=4, ge=1, le=5, description="Timing template (T1 to T5)")
    detect_versions: bool = Field(default=True, description="Enable service version detection")

class PortScanRequest(BaseModel):
    target: str = Field(..., description="Target host to scan (IP or Domain)")
    ports: str = Field(default="1-1000", pattern=r"^(\d+-\d+|\d+(,\d+)*)$", description="Ports to scan")
    options: Optional[PortScanOptions] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, val: str) -> str:
        if not IP_OR_FQDN_REGEX.match(val):
            raise ValueError("Target must be a valid IP address or fully qualified domain name (FQDN).")
        return val

class OpenPortDetail(BaseModel):
    port: int
    protocol: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None

class PortScanStats(BaseModel):
    elapsed_seconds: float
    command_reference: Optional[str] = None

class PortScanResponse(BaseModel):
    target: str
    host_status: str
    total_scanned: int
    open_ports: List[OpenPortDetail]
    risky_ports: List[int]
    risk_label: str
    os_guess: Optional[str] = None
    scan_stats: PortScanStats

# ----------------- Subdomain Enumerator Models -----------------

class SubdomainEnumRequest(BaseModel):
    domain: str = Field(..., description="Base domain name (e.g. example.com)")
    enable_dns_brute: bool = Field(default=True)
    enable_certificate_transparency: bool = Field(default=True)
    concurrency_limit: int = Field(default=20, ge=1, le=50)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, val: str) -> str:
        # Match only FQDN domains
        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,63})+$", val):
            raise ValueError("Domain must be a valid FQDN domain string.")
        return val

class DnsBruteResult(BaseModel):
    subdomain: str
    ip_address: str
    http_status: Optional[int] = None

class CtLogResult(BaseModel):
    subdomain: str
    source_log: Optional[str] = None

class HighValueTarget(BaseModel):
    subdomain: str
    classification: str

class SubdomainEnumResponse(BaseModel):
    base_domain: str
    total_found: int
    dns_brute_results: List[DnsBruteResult]
    ct_log_results: List[CtLogResult]
    high_value_targets: List[HighValueTarget]

# ----------------- Directory Enumeration Models -----------------

class DirEnumRequest(BaseModel):
    base_url: HttpUrl = Field(..., description="Target base URL (HTTP/HTTPS)")
    wordlist_profile: str = Field(default="standard")
    concurrency_limit: int = Field(default=20, ge=1, le=30)
    timeout_seconds: int = Field(default=5, ge=1, le=30)

class FoundPathDetail(BaseModel):
    path: str
    status_code: int
    content_type: Optional[str] = None
    content_length: int
    category: str
    is_sensitive: bool
    is_interesting: bool

class DirEnumResponse(BaseModel):
    base_url: str
    total_scanned: int
    total_found: int
    risk_level: str
    found_paths: List[FoundPathDetail]

# ----------------- WAF Detection Models -----------------

class WafDetectRequest(BaseModel):
    target_url: HttpUrl = Field(...)

class WafDetectionRecord(BaseModel):
    vendor: str
    detection_method: str
    matched_signal: str

class WafDetectResponse(BaseModel):
    target_url: str
    waf_detected: bool
    primary_vendor: str
    confidence_score: int
    detections: List[WafDetectionRecord]
    suggested_bypass_concepts: List[str]
    risk: str = "INFO"

# ----------------- WHOIS & DNS Recon Models -----------------

class WhoisRequest(BaseModel):
    domain: str = Field(...)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, val: str) -> str:
        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,63})+$", val):
            raise ValueError("Domain must be a valid FQDN domain string.")
        return val

class WhoisResponse(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    days_to_expire: Optional[int] = None
    expiring_soon: bool
    name_servers: List[str]
    status: List[str]
    country: Optional[str] = None
    organization: Optional[str] = None
    emails: List[str]
    dnssec: Optional[str] = None

class DnsReconRequest(BaseModel):
    domain: str = Field(...)
    query_types: List[str] = Field(default=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"])

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, val: str) -> str:
        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,63})+$", val):
            raise ValueError("Domain must be a valid FQDN domain string.")
        return val

class EmailSecurityDetails(BaseModel):
    spf_configured: bool
    dmarc_configured: bool
    mx_records_exist: bool
    email_spoofing_risk: bool

class ZoneTransferDetails(BaseModel):
    tested_servers: List[str]
    vulnerable: bool
    exposed_records_count: int

class DnsReconResponse(BaseModel):
    domain: str
    records: Dict[str, List[str]]
    email_security: EmailSecurityDetails
    zone_transfer: ZoneTransferDetails
    risk_rating: str

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, IP, or URL for the pentest module")
    options: Optional[dict] = Field(default=None, description="Module-specific configuration flags and options")

    @field_validator("target")
    @classmethod
    def validate_target(cls, val: str) -> str:
        if not val or not val.strip():
            raise ValueError("Target cannot be empty or whitespace only.")
        return val.strip()
