"""
VulnSeal Full Backend Service (Python)
Provides complete REST API endpoints for targets, scans, findings, remediation, ShadowFix, proofs, and agent activity.
Executable with Python 3 standard library (no pip dependencies required) or via ASGI/FastAPI.
"""
import os
import sys
import json

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any

from .db import db
from .scanner import scanner
from .ai_router import model_router
from .shadowfix import shadowfix_engine
from .demo_target import demo_target
from .supabase_client import supabase_client

class VulnSealAPIHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length).decode('utf-8')
            return json.loads(raw)
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Demo Target Sandbox
        if path.startswith('/demo-target'):
            res = demo_target.handle_request(path, 'GET', dict(self.headers))
            body = res["body"].encode('utf-8')
            self.send_response(res["status"])
            for k, v in res["headers"].items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Workspaces
        if path == '/api/workspaces':
            self._send_json(db.get_workspaces())
            return

        # Targets
        if path == '/api/targets':
            ws_id = query.get('workspace_id', ['ws_default_01'])[0]
            self._send_json(db.get_targets(ws_id))
            return

        # Scans
        if path == '/api/scans':
            ws_id = query.get('workspace_id', ['ws_default_01'])[0]
            self._send_json(db.get_scans(ws_id))
            return

        if path.startswith('/api/scans/'):
            scan_id = path.split('/')[3]
            scan = db.get_scan_by_id(scan_id)
            if scan:
                self._send_json(scan)
            else:
                self._send_json({'error': 'Scan not found'}, 404)
            return

        # Findings
        if path == '/api/findings':
            ws_id = query.get('workspace_id', ['ws_default_01'])[0]
            self._send_json(db.get_findings(ws_id))
            return

        # Proofs
        if path == '/api/proofs':
            ws_id = query.get('workspace_id', ['ws_default_01'])[0]
            self._send_json(db.get_proofs(ws_id))
            return

        # Agent Events
        if path == '/api/agents/events':
            self._send_json(db.get_agent_events())
            return

        # Audit Logs
        if path == '/api/audit-logs':
            self._send_json(db.get_audit_logs())
            return

        # AI Engine Status
        if path == '/api/ai/status':
            self._send_json(model_router.get_engine_status())
            return

        # Supabase Status
        if path == '/api/supabase/status':
            self._send_json({
                'configured': supabase_client.is_configured(),
                'url': supabase_client.url or 'Not Configured'
            })
            return

        self._send_json({'error': f'Route not found: {path}'}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json()

        # Demo Target Login
        if path == '/demo-target/login':
            res = demo_target.handle_request(path, 'POST', dict(self.headers))
            b_bytes = res["body"].encode('utf-8')
            self.send_response(res["status"])
            for k, v in res["headers"].items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(b_bytes)))
            self.end_headers()
            self.wfile.write(b_bytes)
            return

        # Create Target
        if path == '/api/targets':
            if not body.get('url') or not body.get('name'):
                self._send_json({'error': 'URL and target name are required.'}, 400)
                return
            tgt = db.create_target(body)
            self._send_json({'target': tgt})
            return

        # Trigger Scan
        if path == '/api/scans':
            target_id = body.get('target_id')
            if not target_id:
                self._send_json({'error': 'target_id is required.'}, 400)
                return
            try:
                scan_res = scanner.run_scan(target_id)
                self._send_json(scan_res)
            except Exception as e:
                self._send_json({'error': str(e)}, 500)
            return

        # Generate Remediation (RootCauseMapper & AI Router)
        if path == '/api/remediations/generate':
            finding_id = body.get('finding_id')
            finding = db.get_finding_by_id(finding_id)
            if not finding:
                self._send_json({'error': 'Finding not found.'}, 404)
                return

            db.record_agent_event({
                'workspace_id': finding.get('workspace_id', 'ws_default_01'),
                'finding_id': finding_id,
                'agent': 'RootCauseMapper',
                'event_type': 'start',
                'status': 'in_progress',
                'message': f"Analyzing root cause for finding '{finding.get('title')}'..."
            })

            remediation = model_router.analyze_vulnerability(finding)
            root_cause = remediation['rootCause']
            patch = remediation['patch']

            finding['root_cause'] = root_cause
            finding['patch'] = patch
            finding['status'] = 'waiting_approval'
            db.update_finding(finding_id, finding)

            db.record_agent_event({
                'workspace_id': finding.get('workspace_id', 'ws_default_01'),
                'finding_id': finding_id,
                'agent': 'RemediationEngineer',
                'event_type': 'complete',
                'status': 'success',
                'message': f"Synthesized patch diff for '{finding.get('title')}'. Awaiting human approval."
            })

            self._send_json(finding)
            return

        # Approve Patch
        if path == '/api/remediations/approve':
            finding_id = body.get('finding_id')
            approver_email = body.get('approved_by_email', 'engineer@vulnseal.security')
            finding = db.get_finding_by_id(finding_id)
            if not finding or not finding.get('patch'):
                self._send_json({'error': 'Finding or patch candidate not found.'}, 404)
                return

            finding['approval'] = {
                'approved_by_email': approver_email,
                'status': 'approved',
                'approved_at': 'now'
            }
            finding['status'] = 'approved'
            db.update_finding(finding_id, finding)

            db.record_audit_log({
                'workspace_id': finding.get('workspace_id', 'ws_default_01'),
                'action': 'PATCH_APPROVED',
                'actor': approver_email,
                'resource_type': 'finding',
                'resource_id': finding_id,
                'decision': 'APPROVED',
                'details': {'finding_title': finding.get('title')}
            })

            self._send_json(finding)
            return

        # Reject Patch
        if path == '/api/remediations/reject':
            finding_id = body.get('finding_id')
            reason = body.get('rejection_reason', 'Rejected by operator.')
            finding = db.get_finding_by_id(finding_id)
            if not finding:
                self._send_json({'error': 'Finding not found.'}, 404)
                return

            finding['status'] = 'dismissed'
            db.update_finding(finding_id, finding)
            self._send_json(finding)
            return

        # Run ShadowFix Verification
        if path == '/api/shadowfix/run':
            finding_id = body.get('finding_id')
            approver_email = body.get('approved_by_email', 'engineer@vulnseal.security')
            finding = db.get_finding_by_id(finding_id)
            if not finding or not finding.get('patch'):
                self._send_json({'error': 'Approved finding and patch required.'}, 400)
                return

            sfx_res = shadowfix_engine.run_sandbox_verification(finding, finding['patch'], approver_email)
            proof = sfx_res['proof']

            db.create_proof(proof)
            finding['proof'] = proof
            finding['status'] = 'verified'
            db.update_finding(finding_id, finding)

            # Update target statistics
            tgt = db.get_target_by_id(finding.get('target_id', ''))
            if tgt:
                tgt['verified_fixes_count'] = tgt.get('verified_fixes_count', 0) + 1
                tgt['open_findings_count'] = max(0, tgt.get('open_findings_count', 1) - 1)
                tgt['security_score'] = min(100, (tgt.get('security_score') or 50) + 20)

            self._send_json({
                'run_id': sfx_res['run_id'],
                'steps': sfx_res['steps'],
                'proof': proof,
                'finding': finding
            })
            return

        # Reset Demo
        if path == '/api/demo/reset':
            demo_target.reset_config()
            self._send_json({'success': True, 'message': 'Demo target sandbox reset to default vulnerable state.'})
            return

        # Supabase Test
        if path == '/api/supabase/test':
            self._send_json(supabase_client.test_connection())
            return

        self._send_json({'error': f'Route not found: {path}'}, 404)

def run_server(port: int = 8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, VulnSealAPIHandler)
    print(f"==================================================")
    print(f"🛡️  VulnSeal Python Backend Service Online")
    print(f"📡  Listening at http://0.0.0.0:{port}")
    print(f"⚙️   Endpoints: /api/targets, /api/scans, /api/findings, /api/shadowfix/run, /demo-target")
    print(f"==================================================")
    httpd.serve_forever()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    run_server(port)
