# threatquery/modules/http_cache.py

import httpx


class CachingClient(httpx.AsyncClient):
    """
    AsyncClient that answers repeated identical requests from a shared in-memory cache.

    Each analyzer reads one field per method (malicious, blacklist, tags, ...) and every method
    used to fetch the same API object again: VirusTotal made 9 requests per indicator and the
    free VirusTotal API allows 4 a minute. Analyzers keep one cache per instance, and
    IOCAnalyzer creates new instances for every lookup, so nothing is reused across lookups.
    """

    def __init__(self, cache, **kwargs):
        super().__init__(**kwargs)
        self._cache = cache

    async def send(self, request, **kwargs):
        key = (request.method, str(request.url), request.content)
        if key not in self._cache:
            response = await super().send(request, **kwargs)
            await response.aread()
            self._cache[key] = response
        return self._cache[key]
