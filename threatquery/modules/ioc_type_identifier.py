# threatquery/modules/ioc_type_identifier.py file

import re


def determine_ioc_type(ioc_value: str) -> str:
    patterns = {
        "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "ipv6": r"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$",
        "domain": r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$",
        "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        "hash": r"^([A-Fa-f\d]{32}|[A-Fa-f\d]{40}|[A-Fa-f\d]{64})$"
    }

    for ioc_type, pattern in patterns.items():
        if re.match(pattern, ioc_value):
            return ioc_type

    return "unknown"
