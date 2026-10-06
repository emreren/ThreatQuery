# tests/test_ioc_type_identifier.py

import pytest

from threatquery.modules.ioc_type_identifier import determine_ioc_type


@pytest.mark.parametrize("value, expected", [
    ("8.8.8.8", "ipv4"),
    ("2001:4860:4860::8888", "ipv6"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "ipv6"),
    ("example.com", "domain"),
    ("sub.example.co.uk", "domain"),
    ("xn--80ak6aa92e.com", "domain"),
    ("http://malware.testing.google.test/testing/malware/", "url"),
    ("https://example.com/path?q=1", "url"),
    ("44d88612fea8a8f36de82e1278abb02f", "hash"),
    ("3395856ce81f2b7382dee72602f798b642f14140", "hash"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash"),
    ("999.1.1.1", "unknown"),
    ("1.2.3", "unknown"),
    ("hello world", "unknown"),
    ("12345", "unknown"),
    ("", "unknown"),
])
def test_determine_ioc_type(value, expected):
    assert determine_ioc_type(value) == expected
