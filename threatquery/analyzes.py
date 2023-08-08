# threatquery/analyzes.py file


import asyncio
import logging

from threatquery.modules.ioc_type_identifier import determine_ioc_type
from threatquery.modules.analysis import alienvault_analysis, virustotal_analysis, googlesafebrowsing_analysis, whoisxmlapi_analysis

logger = logging.getLogger(__name__)


async def ioc_analyzes(ioc_value: str):
    ioc_type = determine_ioc_type(ioc_value)
    tasks = [
        alienvault_analysis(ioc_value, ioc_type),
        virustotal_analysis(ioc_value, ioc_type),
        googlesafebrowsing_analysis(ioc_value, ioc_type),
        whoisxmlapi_analysis(ioc_value, ioc_type),
    ]

    analysis_results = await asyncio.gather(*tasks)
    merged_results = {}

    for result in analysis_results:
        for key, value in result.items():
            if key in merged_results:
                if value is not None:
                    merged_results[key] = value
            else:
                merged_results[key] = value

    merged_results["type"] = ioc_type

    return merged_results




