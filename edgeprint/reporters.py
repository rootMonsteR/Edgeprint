"""Output formatters for detection reports."""

import json
from typing import Any

from .corpus import CorpusReport
from .models import DetectionReport


def _verdict(likely_waf: bool, likely_edge: bool) -> str:
    if likely_waf:
        return "WAF LIKELY PRESENT"
    if likely_edge:
        return "EDGE/CDN PRESENT, NO WAF EVIDENCE"
    return "NO EDGE PROTECTION DETECTED"


def to_text(report: DetectionReport) -> str:
    verdict = _verdict(report.likely_waf, report.likely_edge)
    lines = [f"Edge protection: {verdict} (confidence={report.confidence:.2f})"]
    if report.layers:
        by_conf = sorted(report.layers.items(), key=lambda kv: kv[1], reverse=True)
        lines.append("Layers: " + ", ".join(f"{name}={conf:.2f}" for name, conf in by_conf))
    if report.vendor_guesses:
        lines.append("Possible vendors: " + ", ".join(report.vendor_guesses))
    if report.rationale:
        lines.append("Rationale: " + report.rationale)
    if report.indicators:
        lines.append("Indicators:")
        for i in report.indicators:
            lines.append(f"  - [{i.weight:.2f}] {i.source} :: {i.key} :: {i.note}")
    return "\n".join(lines)


def _report_dict(report: DetectionReport) -> dict[str, Any]:
    return {
        "likely_waf": report.likely_waf,
        "likely_edge": report.likely_edge,
        "confidence": report.confidence,
        "layers": report.layers,
        "vendor_guesses": report.vendor_guesses,
        "rationale": report.rationale,
        "indicators": [
            {
                "source": i.source,
                "key": i.key,
                "value": i.value,
                "weight": i.weight,
                "note": i.note,
            }
            for i in report.indicators
        ],
    }


def to_json(report: DetectionReport) -> str:
    return json.dumps(_report_dict(report), indent=2)


def corpus_to_text(corpus: CorpusReport) -> str:
    waf = sum(1 for h in corpus.hosts if h.likely_waf)
    edge = sum(1 for h in corpus.hosts if h.likely_edge and not h.likely_waf)
    clean = len(corpus.hosts) - waf - edge
    lines = [
        f"Corpus: {len(corpus.results)} responses across {len(corpus.hosts)} hosts"
        + (f" ({len(corpus.skipped)} inputs skipped)" if corpus.skipped else ""),
        f"Posture: WAF likely on {waf}, edge/CDN only on {edge}, nothing detected on {clean}",
    ]
    for h in corpus.hosts:
        lines.append("")
        noun = "response" if h.responses == 1 else "responses"
        verdict = _verdict(h.likely_waf, h.likely_edge)
        lines.append(f"{h.host}  ({h.responses} {noun})  {verdict}")
        if h.layers:
            by_conf = sorted(h.layers.items(), key=lambda kv: kv[1], reverse=True)
            lines.append("  Layers: " + ", ".join(f"{n}={c:.2f}" for n, c in by_conf))
        if h.vendors:
            by_count = sorted(h.vendors.items(), key=lambda kv: (-kv[1], kv[0]))
            lines.append("  Vendors: " + ", ".join(f"{v} [{n}/{h.responses}]" for v, n in by_count))
    if corpus.skipped:
        lines.append("")
        lines.append("Skipped:")
        for source, reason in corpus.skipped:
            lines.append(f"  - {source}: {reason}")
    return "\n".join(lines)


def corpus_to_json(corpus: CorpusReport) -> str:
    return json.dumps(
        {
            "likely_waf": corpus.likely_waf,
            "likely_edge": corpus.likely_edge,
            "hosts": [
                {
                    "host": h.host,
                    "responses": h.responses,
                    "likely_waf": h.likely_waf,
                    "likely_edge": h.likely_edge,
                    "layers": h.layers,
                    "vendors": h.vendors,
                }
                for h in corpus.hosts
            ],
            "responses": [
                {
                    "source": r.source,
                    "url": r.url,
                    "status_code": r.status_code,
                    **_report_dict(r.report),
                }
                for r in corpus.results
            ],
            "skipped": [{"source": s, "reason": why} for s, why in corpus.skipped],
        },
        indent=2,
    )
