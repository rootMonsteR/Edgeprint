"""Corpus-level analysis: many responses in, per-host edge posture out.

A single response answers "what was in front of this request". A capture - a HAR
export, a directory of ``curl -i`` dumps, a recon pipeline's output - answers
"what is in front of each host", and the answer is usually spread across
responses: the CDN shows on every one, while a block page or a bot-management
cookie shows on one in fifty. This module analyzes every response and folds the
results per host.

Folding rules, and why:

- **Per-layer confidence is the maximum across a host's responses, not the sum.**
  Fifty identical cached pages are one piece of evidence repeated, not fifty
  independent ones; summing would let request volume masquerade as certainty,
  the same failure the per-vendor cap prevents within one response.
- **A host is WAF-likely if any of its responses is.** One block page proves the
  filtering layer exists for that host, whatever the other responses show.
- **Vendors are counted by the number of responses naming them**, so a reader
  can tell a vendor seen on every response from one seen once.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from .analyzer import analyze
from .models import DetectionReport, HttpObservation

logger = logging.getLogger(__name__)


@dataclass
class ResponseResult:
    """One analyzed response and where it came from."""

    source: str
    url: str
    status_code: int
    has_headers: bool
    report: DetectionReport


@dataclass
class HostSummary:
    """Edge posture of one host, folded over all of its responses."""

    host: str
    responses: int = 0
    likely_waf: bool = False
    likely_edge: bool = False
    layers: dict[str, float] = field(default_factory=dict)
    vendors: dict[str, int] = field(default_factory=dict)


@dataclass
class CorpusReport:
    """Per-response results, per-host posture, and inputs that could not be read."""

    results: list[ResponseResult] = field(default_factory=list)
    hosts: list[HostSummary] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    @property
    def likely_waf(self) -> bool:
        return any(h.likely_waf for h in self.hosts)

    @property
    def likely_edge(self) -> bool:
        return any(h.likely_edge for h in self.hosts)

    @property
    def analyzable(self) -> bool:
        """Whether any response carried headers - the precondition for a negative."""
        return any(r.has_headers for r in self.results)


def host_key(url: str, source: str) -> str:
    """Group key for a response: its hostname, or its source when there is no URL.

    Raw ``curl -i`` dumps carry no URL, so responses from different files cannot
    be assumed to share a host; each file stands as its own group.
    """
    host: Optional[str] = None
    if url:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
    return host or f"[{source}]"


def _fold(summary: HostSummary, report: DetectionReport) -> None:
    summary.responses += 1
    summary.likely_waf = summary.likely_waf or report.likely_waf
    summary.likely_edge = summary.likely_edge or report.likely_edge
    for layer, conf in report.layers.items():
        summary.layers[layer] = max(summary.layers.get(layer, 0.0), conf)
    for vendor in report.vendor_guesses:
        summary.vendors[vendor] = summary.vendors.get(vendor, 0) + 1


def analyze_corpus(observations: list[tuple[str, HttpObservation]]) -> CorpusReport:
    """Analyze every observation and fold the results per host.

    Args:
        observations: (source, observation) pairs; ``source`` labels where the
            response came from, e.g. a file path or ``capture.har#12``.

    Returns:
        CorpusReport with hosts ordered WAF-likely first, then edge-only, then
        clean, and by response count within each group.
    """
    report = CorpusReport()
    by_host: dict[str, HostSummary] = {}
    for source, ob in observations:
        result = analyze(ob)
        report.results.append(
            ResponseResult(
                source=source,
                url=ob.url,
                status_code=ob.status_code,
                has_headers=bool(ob.headers),
                report=result,
            )
        )
        key = host_key(ob.url, source)
        _fold(by_host.setdefault(key, HostSummary(host=key)), result)

    report.hosts = sorted(
        by_host.values(),
        key=lambda h: (not h.likely_waf, not h.likely_edge, -h.responses, h.host),
    )
    logger.debug(f"Corpus: {len(report.results)} responses, {len(report.hosts)} hosts")
    return report
