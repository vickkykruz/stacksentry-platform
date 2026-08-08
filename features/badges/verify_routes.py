"""
Verification HTTP routes.
 
The owner-facing endpoints that let someone prove they control a domain, so its
badge may show a real grade. Two steps:
 
  POST /verify/request   { "domain": "example.com" }
      → issues a token, returns the DNS record and file the owner must publish.
 
  POST /verify/confirm   { "domain": "example.com", "method": "auto" }
      → runs the real check; on success the domain becomes verified and its
        badge will start showing the grade (after the next scan).
 
  GET  /verify/status/<domain>
      → whether a domain is currently verified.
 
Design notes
------------
- These routes own only request/response handling. The real work is in
  core.verification_service (logic) and core.domain_verify (checks).
- The service's DNS lookup and HTTP fetch are injected at app startup (real on
  the VPS, absent or stubbed elsewhere). If they're not configured, confirm
  returns a clear message rather than crashing.
- We never leak internal detail. A blocked/SSRF target simply fails to verify.
"""
 
from __future__ import annotations
from flask import Blueprint, request, jsonify
 
verify_bp = Blueprint("verify", __name__)
 
_service = None   # injected VerificationService
 
 
def init_verify(service):
    """Inject the shared VerificationService at app startup."""
    global _service
    _service = service
 
 
def _no_service():
    return jsonify({
        "error": "verification is not enabled on this server",
    }), 503
 
 
@verify_bp.route("/verify/request", methods=["POST"])
def request_verification():
    if _service is None:
        return _no_service()
 
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "missing 'domain'"}), 400
 
    try:
        instr = _service.request_verification(domain)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
 
    return jsonify({
        "domain": instr.domain,
        "token": instr.token,
        "instructions": {
            "dns": {
                "type": "TXT",
                "name": instr.dns_record_name,
                "value": instr.dns_record_value,
            },
            "well_known": {
                "url": instr.well_known_url,
                "content": instr.well_known_content,
            },
        },
        "next": "Publish EITHER the DNS record OR the file, then POST /verify/confirm.",
    })
 
 
@verify_bp.route("/verify/confirm", methods=["POST"])
def confirm_verification():
    if _service is None:
        return _no_service()
 
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    method = data.get("method", "auto").strip().lower()
    if not domain:
        return jsonify({"error": "missing 'domain'"}), 400
    if method not in ("auto", "dns", "well_known"):
        return jsonify({"error": "method must be auto | dns | well_known"}), 400
 
    result = _service.confirm_verification(domain, method=method)
    status = 200 if result.verified else 422
    return jsonify({
        "domain": result.domain,
        "verified": result.verified,
        "method": result.method,
        "reason": result.reason,
    }), status
 
 
@verify_bp.route("/verify/status/<path:domain>", methods=["GET"])
def verification_status(domain: str):
    if _service is None:
        return _no_service()
    return jsonify({
        "domain": domain,
        "verified": _service.is_verified(domain),
    })
 