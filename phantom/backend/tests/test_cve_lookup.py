import pytest
from unittest.mock import patch, MagicMock
from cve_lookup import lookup_cve

@pytest.mark.asyncio
async def test_fetch_cve_details_success():
    with patch('cve_lookup.urlopen') as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"id": "CVE-2023-12345", "summary": "Test CVE"}'
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = await lookup_cve("CVE-2023-12345")
        assert result is not None
        assert result.get('id') == "CVE-2023-12345"
