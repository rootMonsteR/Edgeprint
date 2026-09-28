"""edgeprint - offline WAF/CDN edge fingerprinting.

Analyzes HTTP responses that have already been captured to identify WAF, CDN and
edge-protection products, without sending any network traffic of its own. Built for
corpus-scale passive analysis: HAR exports, proxy logs, recon pipeline output.

Analyze only traffic you are authorized to possess. This tool reads files you give
it and makes no requests of its own; that does not make the capture itself lawful.
"""

__all__ = ["analyzer", "corpus", "parsers", "reporters", "fingerprints", "models"]
__version__ = "0.4.0"
__author__ = "edgeprint contributors"
__license__ = "MIT AND Apache-2.0"  # engine MIT; fingerprint database Apache-2.0
