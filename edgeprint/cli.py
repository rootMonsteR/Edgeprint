"""Command-line interface for edgeprint.

``edgeprint analyze`` reads one or more captures - files or directories of them -
and reports the edge-protection posture they show. One response in gets the
detailed single-response report; anything larger gets the per-host corpus view.
"""

import argparse
import logging
import pathlib
import sys
from typing import Optional

from . import __version__
from .analyzer import analyze
from .corpus import CorpusReport, analyze_corpus
from .models import DetectionReport, HttpObservation
from .parsers import parse_har_all, parse_json_obs, parse_raw_headers
from .reporters import corpus_to_json, corpus_to_text, to_json, to_text

# Exit codes
EXIT_OK = 0
EXIT_INDETERMINATE = 1
EXIT_WAF_LIKELY = 2
EXIT_EDGE_ONLY = 3

# Configure logging
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def _auto_fmt(path: str) -> str:
    """Auto-detect file format based on extension.

    Args:
        path: File path to analyze

    Returns:
        Format string: 'har', 'json', or 'raw'
    """
    p = path.lower()
    if p.endswith(".har"):
        return "har"
    if p.endswith(".json"):
        return "json"
    return "raw"


def _expand(paths: list[str]) -> list[pathlib.Path]:
    """Expand directories into the files beneath them, skipping hidden entries.

    Files named explicitly are kept even if missing, so the caller reports them
    rather than having them vanish silently.
    """
    out: list[pathlib.Path] = []
    for raw in paths:
        path = pathlib.Path(raw)
        if path.is_dir():
            out.extend(
                p
                for p in sorted(path.rglob("*"))
                if p.is_file()
                and not any(part.startswith(".") for part in p.relative_to(path).parts)
            )
        else:
            out.append(path)
    return out


def _read(path: pathlib.Path, fmt: str) -> list[HttpObservation]:
    """Parse one capture file into its observations.

    Raises:
        ValueError: If the file is missing, unreadable or not in the given format
    """
    if not path.exists():
        raise ValueError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    fmt = fmt if fmt != "auto" else _auto_fmt(str(path))
    logger.info(f"Reading {path} as {fmt}")
    if fmt == "raw":
        return [parse_raw_headers(text)]
    if fmt == "json":
        return [parse_json_obs(text)]
    if fmt == "har":
        return parse_har_all(text)
    raise ValueError(f"Unknown format: {fmt}")


def _single_exit(report: DetectionReport, ob: HttpObservation) -> int:
    # A confident negative (headers parsed, nothing found) is EXIT_OK; only an
    # unusable observation is indeterminate. Edge presence without WAF evidence
    # gets its own code, because a CDN is not a WAF.
    if report.likely_waf:
        return EXIT_WAF_LIKELY
    if report.likely_edge:
        return EXIT_EDGE_ONLY
    if not ob.headers:
        return EXIT_INDETERMINATE
    return EXIT_OK


def _corpus_exit(corpus: CorpusReport) -> int:
    # The most severe finding on any host decides, so a pipeline gating on the
    # exit code cannot miss a WAF that shows on one host of many.
    if corpus.likely_waf:
        return EXIT_WAF_LIKELY
    if corpus.likely_edge:
        return EXIT_EDGE_ONLY
    if corpus.analyzable:
        return EXIT_OK
    return EXIT_INDETERMINATE


def main(argv: Optional[list] = None) -> int:
    """Main CLI entry point.

    Args:
        argv: Optional command-line arguments (defaults to sys.argv)

    Returns:
        Exit code: EXIT_OK (0), EXIT_INDETERMINATE (1), EXIT_WAF_LIKELY (2) or
        EXIT_EDGE_ONLY (3). For several responses, the most severe host decides.
    """
    ap = argparse.ArgumentParser(
        description="edgeprint - offline WAF/CDN edge fingerprinting (no network calls).",
        epilog=(
            "Exit codes: 0=nothing detected, 1=nothing analyzable, "
            "2=WAF likely present, 3=edge/CDN present but no WAF evidence. "
            "Across several responses, the most severe host decides."
        ),
    )
    ap.add_argument("--version", action="version", version=f"edgeprint {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    an = sub.add_parser("analyze", help="Analyze captured responses.")
    an.add_argument(
        "-i",
        "--input",
        required=True,
        nargs="+",
        action="extend",
        help="Capture file(s) or directories of them; repeatable",
    )
    an.add_argument(
        "--format",
        choices=["auto", "raw", "json", "har"],
        default="auto",
        help="Input format (auto-detected per file by default)",
    )
    an.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    an.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    args = ap.parse_args(argv)

    # Configure logging level
    if hasattr(args, "verbose") and args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    if args.cmd != "analyze":
        ap.print_help()
        return EXIT_INDETERMINATE

    try:
        paths = _expand(args.input)
        single_file = len(args.input) == 1 and not pathlib.Path(args.input[0]).is_dir()

        observations: list[tuple[str, HttpObservation]] = []
        skipped: list[tuple[str, str]] = []
        for path in paths:
            try:
                obs = _read(path, args.format)
            except ValueError as e:
                if single_file:
                    raise
                logger.warning(f"Skipping {path}: {e}")
                skipped.append((str(path), str(e)))
                continue
            if len(obs) == 1:
                observations.append((str(path), obs[0]))
            else:
                observations.extend((f"{path}#{n}", ob) for n, ob in enumerate(obs))

        # One response keeps the detailed single-response report.
        if single_file and len(observations) == 1:
            ob = observations[0][1]
            report = analyze(ob)
            print(to_json(report) if args.json else to_text(report))
            return _single_exit(report, ob)

        corpus = analyze_corpus(observations)
        corpus.skipped = skipped
        print(corpus_to_json(corpus) if args.json else corpus_to_text(corpus))
        return _corpus_exit(corpus)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INDETERMINATE
    except Exception as e:
        logger.exception("Unexpected error during analysis")
        print(f"Unexpected error: {e}", file=sys.stderr)
        return EXIT_INDETERMINATE


if __name__ == "__main__":
    raise SystemExit(main())
