"""Parsers for various HTTP observation formats.

This module provides parsers for different input formats including raw HTTP headers,
JSON observations, and HAR (HTTP Archive) files.
"""

import json
import logging
from typing import Any

from .models import HttpObservation

#: Maximum body bytes retained for analysis. Bodies are only ever pattern-matched,
#: so a bounded excerpt is enough, and the bound must be identical across parsers
#: or body-signal detection becomes format-dependent.
MAX_BODY_EXCERPT = 4096

logger = logging.getLogger(__name__)


def _add_header(headers: dict, key: str, value: str) -> None:
    """Record a header, preserving repeats instead of overwriting them.

    Repeated fields are legal and load-bearing: a response commonly sends several
    ``Set-Cookie`` lines, and overwriting kept only the last one, silently
    discarding cookie signals. ``Set-Cookie`` is joined with newlines because a
    comma is ambiguous inside cookie ``Expires`` dates; other fields use the
    comma form from RFC 7230 section 3.2.2.

    Matching is case-insensitive: HAR exports and proxy logs do not normalise
    header case, so ``Set-Cookie`` and ``set-cookie`` must land in one entry or
    the overwrite this function prevents simply reappears downstream.
    """
    for existing in headers:
        if existing.lower() == key.lower():
            sep = "\n" if key.lower() == "set-cookie" else ", "
            headers[existing] = headers[existing] + sep + value
            return
    headers[key] = value


def parse_raw_headers(text: str) -> HttpObservation:
    """Parse raw HTTP headers from curl -i output or RFC822-style header blocks.

    The header section ends at the first empty line, per RFC 7230 section 3. An
    earlier version stripped blank lines and guessed the boundary from the first
    line without a colon, which absorbed bodies containing CSS or quoted headers
    into the header map.

    Args:
        text: Raw text containing HTTP response headers and optional body

    Returns:
        HttpObservation object with parsed data

    Raises:
        ValueError: If the input text is empty or contains no usable content
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    lines = text.splitlines()
    status_code = 0
    headers: dict = {}
    body_lines: list = []
    in_headers = True

    for line in lines:
        if in_headers:
            if not line.strip():
                # Blank line terminates the header section, but skip leading
                # blanks before the status line has been seen.
                if headers or status_code:
                    in_headers = False
                continue
            stripped = line.rstrip("\r\n")
            if stripped.lower().startswith("http/"):
                for part in stripped.split():
                    if part.isdigit():
                        status_code = int(part)
                        break
                continue
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                _add_header(headers, k.strip(), v.strip())
                continue
            # A non-blank, colon-free line inside the header block is malformed;
            # treat everything from here as body rather than dropping it.
            in_headers = False
            body_lines.append(stripped)
        else:
            body_lines.append(line)

    if not headers and status_code == 0 and not body_lines:
        raise ValueError("No valid content found in input")

    body_excerpt = "\n".join(body_lines).strip() or None

    logger.debug(f"Parsed raw headers: status={status_code}, headers={len(headers)}")
    return HttpObservation(
        url="",
        method="GET",
        status_code=status_code,
        headers=headers,
        body_excerpt=body_excerpt[:MAX_BODY_EXCERPT] if body_excerpt else None,
    )


def parse_json_obs(text: str) -> HttpObservation:
    """Parse HTTP observation from JSON format.

    Args:
        text: JSON string containing observation data

    Returns:
        HttpObservation object with parsed data

    Raises:
        ValueError: If JSON is invalid or missing required fields
        json.JSONDecodeError: If the input is not valid JSON
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    # Validate and extract data with proper error handling
    try:
        status_code = int(data.get("status_code", 0))
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid status_code in JSON: {e}")
        status_code = 0

    headers = data.get("headers", {})
    if not isinstance(headers, dict):
        logger.warning("Headers field is not a dictionary, using empty dict")
        headers = {}

    body_excerpt = data.get("body_excerpt")
    if body_excerpt is not None and not isinstance(body_excerpt, str):
        logger.warning("body_excerpt is not a string, ignoring")
        body_excerpt = None
    if body_excerpt and len(body_excerpt) > MAX_BODY_EXCERPT:
        body_excerpt = body_excerpt[:MAX_BODY_EXCERPT]

    # Untrusted input: a non-string url would crash host grouping downstream.
    url = data.get("url", "")
    method = data.get("method", "GET")

    logger.debug(f"Parsed JSON observation: status={status_code}, headers={len(headers)}")
    return HttpObservation(
        url=url if isinstance(url, str) else "",
        method=method if isinstance(method, str) else "GET",
        status_code=status_code,
        headers=headers,
        body_excerpt=body_excerpt,
    )


def _load_har_entries(text: str) -> list:
    """Validate a HAR document and return its entries list."""
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    if not isinstance(data, dict) or not isinstance(data.get("log"), dict):
        raise ValueError("Invalid HAR format: missing 'log' field")

    entries = data["log"].get("entries", [])
    if not isinstance(entries, list) or not entries:
        raise ValueError("HAR file contains no entries")
    return entries


def _har_entry(entry: Any) -> HttpObservation:
    """Convert one HAR entry to an observation. Malformed fields degrade, not crash."""
    if not isinstance(entry, dict):
        return HttpObservation()
    res = entry.get("response")
    res = res if isinstance(res, dict) else {}
    req = entry.get("request")
    req = req if isinstance(req, dict) else {}

    try:
        status = int(res.get("status", 0))
    except (ValueError, TypeError):
        logger.warning("Invalid status code in HAR, using 0")
        status = 0

    # Parse headers safely
    headers: dict[str, str] = {}
    raw_headers = res.get("headers", [])
    for h in raw_headers if isinstance(raw_headers, list) else []:
        if isinstance(h, dict) and isinstance(h.get("name"), str) and "value" in h:
            _add_header(headers, h["name"], str(h["value"]))

    # Extract body excerpt with size limit
    body_excerpt = None
    content = res.get("content", {})
    if isinstance(content, dict) and isinstance(content.get("text"), str) and content["text"]:
        body_excerpt = content["text"][:MAX_BODY_EXCERPT]

    url = req.get("url", "")
    method = req.get("method", "GET")
    return HttpObservation(
        url=url if isinstance(url, str) else "",
        method=method if isinstance(method, str) else "GET",
        status_code=status,
        headers=headers,
        body_excerpt=body_excerpt,
    )


def parse_har(text: str) -> HttpObservation:
    """Parse the first entry of a HAR (HTTP Archive) document.

    Kept for callers that want a single observation. Use :func:`parse_har_all`
    to analyze every response in the archive, which is what the CLI does.

    Raises:
        ValueError: If HAR format is invalid or contains no entries
    """
    ob = _har_entry(_load_har_entries(text)[0])
    logger.debug(f"Parsed HAR entry: status={ob.status_code}, headers={len(ob.headers)}")
    return ob


def parse_har_all(text: str) -> list[HttpObservation]:
    """Parse every entry of a HAR document, in archive order.

    A HAR export is a capture of many responses, often across several hosts, and
    edge signals are rarely on all of them: a block page or a bot-management
    cookie typically appears on one request in fifty. Reading only the first
    entry, as ``parse_har`` does, misses exactly the evidence that matters.

    Raises:
        ValueError: If HAR format is invalid or contains no entries
    """
    obs = [_har_entry(e) for e in _load_har_entries(text)]
    logger.debug(f"Parsed HAR file: {len(obs)} entries")
    return obs
