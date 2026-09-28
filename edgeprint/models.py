"""Data models for edge-protection detection.

This module defines the core data structures used throughout edgeprint.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HttpObservation:
    """Represents an HTTP request/response observation for analysis.

    Attributes:
        url: The URL of the HTTP request
        method: HTTP method (GET, POST, etc.)
        status_code: HTTP response status code
        headers: Dictionary of HTTP response headers
        body_excerpt: Optional excerpt of the response body (limited length for safety)
    """

    url: str = ""
    method: str = "GET"
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: Optional[str] = None


@dataclass
class Indicator:
    """Represents a single detection indicator found during analysis.

    Attributes:
        source: Source of the indicator (e.g., 'header:server', 'cookie', 'body')
        key: The key/name of the indicator
        value: The value found for this indicator
        weight: Confidence weight (0.0-1.0) for this indicator
        note: Human-readable description of what this indicator means
    """

    source: str
    key: str
    value: str
    weight: float
    note: str


@dataclass
class DetectionReport:
    """Final detection report with all findings and confidence assessment.

    ``likely_waf`` and ``likely_edge`` are deliberately separate. A CDN is not a
    WAF: a Fastly- or CloudFront-fronted host shows strong edge signals while
    saying nothing about whether request filtering is in place.

    Attributes:
        likely_waf: Whether a WAF-layer control is likely present
        likely_edge: Whether any edge product (CDN, WAF, bot management) is likely
        confidence: Overall confidence that some edge product is present (0.0-1.0)
        layers: Per-layer confidence, e.g. {"cdn": 0.70, "waf": 0.35}
        indicators: All indicators found during analysis
        vendor_guesses: Potential vendors, ordered by likelihood
        rationale: Human-readable explanation of the detection decision
    """

    likely_waf: bool
    likely_edge: bool
    confidence: float
    layers: dict[str, float]
    indicators: list[Indicator]
    vendor_guesses: list[str]
    rationale: str
