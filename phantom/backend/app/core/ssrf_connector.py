import aiohttp
import socket
import ipaddress
from urllib.parse import urlparse

class SSRFProtectionException(Exception):
    pass

def _is_blocked_ip(addr: str) -> bool:
    """Check if an IP address falls into restricted ranges."""
    try:
        ip_obj = ipaddress.ip_address(addr)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        
        # Explicitly block 0.0.0.0 and :: (unspecified)
        if ip_obj.is_unspecified:
            return True

        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast:
            return True
        if ip_obj == ipaddress.ip_address('169.254.169.254'):
            return True
        return False
    except ValueError:
        return False

class SSRFConnector(aiohttp.TCPConnector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def _resolve_host(self, host: str, port: int, traces=None):
        # Resolve the host
        hosts = await super()._resolve_host(host, port, traces)
        
        for h in hosts:
            ip = h['host']
            if _is_blocked_ip(ip):
                raise SSRFProtectionException(f"SSRF Attempt blocked: {ip} is restricted")
        
        return hosts

def get_safe_client_session(**kwargs) -> aiohttp.ClientSession:
    """Returns an aiohttp ClientSession with SSRF protections enabled."""
    connector = SSRFConnector()
    return aiohttp.ClientSession(connector=connector, **kwargs)
