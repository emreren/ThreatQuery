# threatquery/modules/ioc_type_identifier.py file

import ipaddress
import re


def determine_ioc_type(ioc_value: str) -> str:
    # ipaddress accepts compressed IPv6 (2001:db8::1) and rejects out-of-range octets (999.1.1.1)
    try:
        return f"ipv{ipaddress.ip_address(ioc_value).version}"
    except ValueError:
        pass

    patterns = {
        # the TLD starts with a letter, so an invalid IP such as 999.1.1.1 is not taken for a domain
        "domain": r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z][a-zA-Z0-9-]*$",
        "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        "hash": r"^([A-Fa-f\d]{32}|[A-Fa-f\d]{40}|[A-Fa-f\d]{64})$"
    }

    for ioc_type, pattern in patterns.items():
        if re.match(pattern, ioc_value):
            return ioc_type

    return "unknown"
