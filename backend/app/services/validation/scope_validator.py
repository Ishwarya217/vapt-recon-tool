import ipaddress
import urllib.parse
from typing import Tuple


class ScopeValidator:
    """Enforces target scope rules and SSRF protections."""

    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata & link-local
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    @classmethod
    def is_ip_allowed(cls, ip_str: str) -> bool:
        """Returns False if IP is loopback, private, or cloud metadata address."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast:
                return False
            for net in cls.BLOCKED_NETWORKS:
                if ip_obj in net:
                    return False
            return True
        except ValueError:
            return False

    @classmethod
    def is_valid_domain(cls, user_input: str) -> bool:
        valid, _, _ = cls.sanitize_target_domain(user_input)
        return valid

    @classmethod
    def is_in_scope(cls, candidate: str, target_domain: str) -> bool:
        return cls.is_hostname_in_scope(candidate, target_domain)

    @classmethod
    def is_hostname_in_scope(cls, candidate: str, target_domain: str) -> bool:
        """Ensures candidate hostname belongs to target domain."""
        cand_clean = candidate.lower().rstrip(".")
        target_clean = target_domain.lower().rstrip(".")

        if cand_clean == target_clean or cand_clean.endswith(f".{target_clean}"):
            return True
        return False

    @classmethod
    def sanitize_target_domain(cls, user_input: str) -> Tuple[bool, str, str]:
        """Normalizes target domain input and validates syntax."""
        cleaned = user_input.strip()

        # Handle full URLs passed by user
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            parsed = urllib.parse.urlparse(cleaned)
            cleaned = parsed.netloc.split(":")[0]

        cleaned = cleaned.split("/")[0].rstrip(".").lower()

        if not cleaned or "." not in cleaned:
            return False, cleaned, "Invalid domain format. Domain must contain a valid TLD (e.g. example.com)"

        # Check for invalid characters
        valid_chars = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
        if not set(cleaned).issubset(valid_chars):
            return False, cleaned, "Domain contains invalid characters"

        return True, cleaned, "Target domain valid and in scope"
