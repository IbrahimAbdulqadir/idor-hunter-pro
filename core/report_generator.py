"""
IDOR Hunter Pro — Week 2
HackerOne Report Generator: HTML preview + PDF download
"""

import json
import os
from datetime import datetime
from dataclasses import asdict

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ── Color Palette ─────────────────────────────────────────────────────────────
C_BG        = HexColor('#0a0c10')
C_SURFACE   = HexColor('#0f1318')
C_ACCENT    = HexColor('#00c9a7')
C_RED       = HexColor('#ff4d6d')
C_YELLOW    = HexColor('#f5a623')
C_BLUE      = HexColor('#4a9eff')
C_TEXT      = HexColor('#c8d0dc')
C_DIM       = HexColor('#5a6478')
C_WHITE     = HexColor('#e8edf5')
C_BORDER    = HexColor('#1e2530')

SEVERITY_COLORS = {
    'critical': HexColor('#ff4d6d'),
    'high':     HexColor('#f5a623'),
    'medium':   HexColor('#4a9eff'),
    'low':      HexColor('#5a6478'),
}

SEVERITY_BG = {
    'critical': HexColor('#2a0a10'),
    'high':     HexColor('#2a1a0a'),
    'medium':   HexColor('#0a1a2a'),
    'low':      HexColor('#1a1e26'),
}


def cvss_severity(score: float) -> str:
    if score >= 9.0: return 'critical'
    if score >= 7.0: return 'high'
    if score >= 4.0: return 'medium'
    return 'low'


def severity_label(score: float) -> str:
    return cvss_severity(score).upper()


# ── HTML Report ───────────────────────────────────────────────────────────────

def generate_html_report(finding: dict, session: dict) -> str:
    ev = finding.get('evidence', {})
    param = finding.get('param', {})
    score = finding.get('cvss_score', 0)
    severity = cvss_severity(score)
    sev_colors = {
        'critical': ('#ff4d6d', '#2a0a10'),
        'high':     ('#f5a623', '#2a1a0a'),
        'medium':   ('#4a9eff', '#0a1a2a'),
        'low':      ('#5a6478', '#1a1e26'),
    }
    sev_color, sev_bg = sev_colors[severity]

    fields_exposed = ev.get('fields_exposed', [])
    orig_req = ev.get('original_request', {})
    exploit_req = ev.get('exploit_request', {})
    orig_resp = ev.get('original_response', {})
    exploit_resp = ev.get('exploit_response', {})

    orig_body = json.dumps(orig_resp.get('body', ''), indent=2) if orig_resp.get('body') else '(empty)'
    exploit_body = json.dumps(exploit_resp.get('body', ''), indent=2) if exploit_resp.get('body') else '(empty)'

    steps = f"""1. Log in to the application with a valid user account
2. Navigate to: {finding.get('endpoint', '')}
3. Intercept the request using a proxy tool (Burp Suite / IDOR Hunter Pro)
4. Identify the {param.get('param_type', 'numeric')} parameter: <code>{param.get('key', 'id')}</code> = <code>{param.get('original_value', '')}</code>
5. Replace the value with another user's ID: <code>{ev.get('injected_id', '')}</code>
6. Forward the modified request
7. Observe that the server returns data belonging to a different user"""

    impact_fields = ', '.join(fields_exposed) if fields_exposed else 'user data'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bug Report — IDOR — {finding.get('id', '')} — IDOR Hunter Pro</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0c10; --surface: #0f1318; --border: #1e2530;
    --text: #c8d0dc; --dim: #5a6478; --hi: #e8edf5;
    --accent: #00c9a7; --red: #ff4d6d;
    --mono: 'IBM Plex Mono', monospace;
    --sans: 'IBM Plex Sans', sans-serif;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--sans);
         font-size: 14px; line-height: 1.7; padding: 40px 20px; }}
  .wrap {{ max-width: 860px; margin: 0 auto; }}

  /* Header */
  .report-header {{
    border-left: 4px solid {sev_color};
    background: {sev_bg};
    border-radius: 6px;
    padding: 28px 28px;
    margin-bottom: 28px;
  }}
  .report-meta {{ font-family: var(--mono); font-size: 10px; color: var(--dim);
                 letter-spacing: .15em; text-transform: uppercase; margin-bottom: 10px; }}
  .report-title {{ font-size: 22px; font-weight: 600; color: var(--hi); margin-bottom: 8px; }}
  .badge-row {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }}
  .badge {{ display: inline-flex; align-items: center; padding: 3px 10px;
            border-radius: 3px; font-family: var(--mono); font-size: 11px;
            font-weight: 600; letter-spacing: .06em; text-transform: uppercase; }}
  .badge-sev {{ background: {sev_bg}; color: {sev_color}; border: 1px solid {sev_color}; }}
  .badge-method {{ background: #1a1e26; color: var(--text); border: 1px solid var(--border); }}
  .badge-status {{ background: #0a1a10; color: #4caf50; border: 1px solid #4caf50; }}

  /* Sections */
  .section {{ margin-bottom: 28px; }}
  .section-title {{
    font-family: var(--mono); font-size: 10px; letter-spacing: .15em;
    text-transform: uppercase; color: var(--dim);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px; margin-bottom: 16px;
  }}

  /* Info grid */
  .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
               background: var(--border); border: 1px solid var(--border);
               border-radius: 6px; overflow: hidden; }}
  .info-cell {{ background: var(--surface); padding: 12px 16px; }}
  .info-label {{ font-family: var(--mono); font-size: 10px; color: var(--dim);
                letter-spacing: .1em; text-transform: uppercase; margin-bottom: 4px; }}
  .info-value {{ font-family: var(--mono); font-size: 13px; color: var(--hi); }}
  .info-value.accent {{ color: var(--accent); }}
  .info-value.red {{ color: var(--red); }}

  /* Evidence */
  .evidence-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .req-box {{ background: #060809; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
  .req-box.exploit {{ border-color: var(--red); }}
  .req-header {{ padding: 8px 14px; border-bottom: 1px solid var(--border);
                font-family: var(--mono); font-size: 10px; letter-spacing: .1em;
                text-transform: uppercase; color: var(--dim); }}
  .req-header.exploit {{ color: var(--red); border-bottom-color: #3a1020; }}
  .req-body {{ padding: 14px; font-family: var(--mono); font-size: 11px;
              line-height: 1.8; overflow-x: auto; max-height: 300px; overflow-y: auto;
              white-space: pre-wrap; word-break: break-all; color: var(--text); }}
  .injected {{ color: var(--red); font-weight: 700;
               background: rgba(255,77,109,.12); padding: 0 3px; border-radius: 2px; }}

  /* Steps */
  .steps {{ background: var(--surface); border: 1px solid var(--border);
            border-radius: 6px; padding: 20px; }}
  .steps ol {{ padding-left: 20px; }}
  .steps li {{ margin-bottom: 8px; font-size: 13px; }}
  .steps code {{ font-family: var(--mono); font-size: 12px; color: var(--accent);
                background: rgba(0,201,167,.1); padding: 1px 5px; border-radius: 3px; }}

  /* Fields */
  .field-chip {{ display: inline-flex; align-items: center; gap: 6px;
                background: rgba(255,77,109,.1); border: 1px solid var(--red);
                color: var(--red); border-radius: 4px; padding: 4px 10px;
                font-family: var(--mono); font-size: 11px; margin: 4px; }}

  /* CVSS */
  .cvss-box {{ background: var(--surface); border: 1px solid var(--border);
               border-radius: 6px; padding: 20px; }}
  .cvss-score {{ font-family: var(--mono); font-size: 48px; font-weight: 700;
                color: {sev_color}; line-height: 1; }}
  .cvss-vector {{ font-family: var(--mono); font-size: 11px; color: var(--dim);
                 word-break: break-all; margin-top: 8px; }}
  .cvss-bar {{ background: var(--border); border-radius: 4px; height: 6px;
               margin: 12px 0; overflow: hidden; }}
  .cvss-fill {{ height: 100%; background: {sev_color}; border-radius: 4px;
                width: {min(score / 10 * 100, 100):.0f}%; }}

  /* Impact */
  .impact-box {{ background: rgba(255,77,109,.06); border: 1px solid rgba(255,77,109,.3);
                 border-left: 3px solid var(--red); border-radius: 6px; padding: 18px 20px; }}

  /* Fix */
  .fix-box {{ background: rgba(0,201,167,.06); border: 1px solid rgba(0,201,167,.3);
              border-left: 3px solid var(--accent); border-radius: 6px; padding: 18px 20px; }}

  /* Footer */
  .footer {{ text-align: center; font-family: var(--mono); font-size: 10px;
             color: var(--dim); margin-top: 48px; padding-top: 20px;
             border-top: 1px solid var(--border); }}

  /* Print */
  @media print {{
    body {{ background: white; color: #1a1a1a; }}
    .report-header {{ background: #f5f5f5 !important; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <div class="report-header">
    <div class="report-meta">IDOR Hunter Pro · Bug Report · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
    <div class="report-title">Insecure Direct Object Reference (IDOR) — Unauthorized Access to User Data via <code style="font-size:18px;color:{sev_color}">{param.get('key','id')}</code> Parameter</div>
    <div class="badge-row">
      <span class="badge badge-sev">{severity_label(score)} — CVSS {score:.1f}</span>
      <span class="badge badge-method">{finding.get('method','GET')}</span>
      <span class="badge badge-status">✓ {finding.get('status','confirmed').upper()}</span>
      <span class="badge" style="background:#1a1e26;color:var(--dim);border:1px solid var(--border)">
        {finding.get('hit_count',0)} independent confirmations
      </span>
    </div>
  </div>

  <!-- Vulnerability Info -->
  <div class="section">
    <div class="section-title">Vulnerability Details</div>
    <div class="info-grid">
      <div class="info-cell">
        <div class="info-label">Affected URL</div>
        <div class="info-value">{finding.get('endpoint','')}</div>
      </div>
      <div class="info-cell">
        <div class="info-label">HTTP Method</div>
        <div class="info-value">{finding.get('method','GET')}</div>
      </div>
      <div class="info-cell">
        <div class="info-label">Vulnerable Parameter</div>
        <div class="info-value accent">{param.get('key','id')} ({param.get('param_type','numeric')})</div>
      </div>
      <div class="info-cell">
        <div class="info-label">Injected ID (PoC)</div>
        <div class="info-value red">{ev.get('injected_id','')}</div>
      </div>
      <div class="info-cell">
        <div class="info-label">Your User ID (Baseline)</div>
        <div class="info-value">{param.get('original_value','')}</div>
      </div>
      <div class="info-cell">
        <div class="info-label">Finding ID</div>
        <div class="info-value" style="color:var(--dim)">{finding.get('id','')}</div>
      </div>
    </div>
  </div>

  <!-- Description -->
  <div class="section">
    <div class="section-title">Description</div>
    <div class="steps">
      <p>The application fails to verify that the authenticated user is authorized to access resources identified by the <code>{param.get('key','id')}</code> parameter at the endpoint <code>{finding.get('endpoint','')}</code>.</p>
      <br>
      <p>By modifying the <code>{param.get('key','id')}</code> parameter from the authenticated user's own value (<code>{param.get('original_value','')}</code>) to another user's value (<code>{ev.get('injected_id','')}</code>), an attacker can access private data belonging to other users without authorization. This was confirmed across <strong>{finding.get('hit_count',0)} independent probe iterations</strong> with a response diff score of <strong>{ev.get('diff_score',0):.3f}</strong>.</p>
    </div>
  </div>

  <!-- Steps to Reproduce -->
  <div class="section">
    <div class="section-title">Steps to Reproduce</div>
    <div class="steps">
      <ol>
        <li>Log in to the application with a valid user account</li>
        <li>Navigate to: <code>{finding.get('endpoint','')}</code></li>
        <li>Intercept the request using a proxy or IDOR Hunter Pro</li>
        <li>Identify the {param.get('param_type','numeric')} parameter: <code>{param.get('key','id')}</code> = <code>{param.get('original_value','')}</code></li>
        <li>Replace the value with another user's ID: <code>{ev.get('injected_id','')}</code></li>
        <li>Forward the modified <code>{finding.get('method','GET')}</code> request</li>
        <li>Observe that the server returns data belonging to a different user</li>
      </ol>
    </div>
  </div>

  <!-- Evidence -->
  <div class="section">
    <div class="section-title">Proof of Concept — Request / Response Evidence</div>
    <div class="evidence-grid">
      <div>
        <p style="font-family:var(--mono);font-size:10px;color:var(--dim);margin-bottom:8px;letter-spacing:.1em;text-transform:uppercase">Original Request (Your ID)</p>
        <div class="req-box">
          <div class="req-header">Request · {orig_resp.get('status_code','')} Response</div>
          <div class="req-body">{finding.get('method','GET')} {orig_req.get('url','')}

{chr(10).join(f"{k}: {str(v)[:80]}" for k,v in (orig_req.get('headers') or {{}}).items())}

{json.dumps(orig_req.get('body'), indent=2) if orig_req.get('body') else ''}
---
{orig_body[:600]}</div>
        </div>
      </div>
      <div>
        <p style="font-family:var(--mono);font-size:10px;color:var(--red);margin-bottom:8px;letter-spacing:.1em;text-transform:uppercase">Exploit Request (Injected ID: {ev.get('injected_id','')})</p>
        <div class="req-box exploit">
          <div class="req-header exploit">Request · {exploit_resp.get('status_code','')} Response</div>
          <div class="req-body">{finding.get('method','GET')} {exploit_req.get('url','').replace(str(ev.get('injected_id','')), f'[INJECTED:{ev.get("injected_id","")}]')}

{chr(10).join(f"{k}: {str(v)[:80]}" for k,v in (exploit_req.get('headers') or {{}}).items())}

{json.dumps(exploit_req.get('body'), indent=2) if exploit_req.get('body') else ''}
---
{exploit_body[:600]}</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Exposed Fields -->
  {'<div class="section"><div class="section-title">Sensitive Data Exposed</div><div>' + ''.join(f'<span class="field-chip">⚠ {f}</span>' for f in fields_exposed) + '</div></div>' if fields_exposed else ''}

  <!-- CVSS -->
  <div class="section">
    <div class="section-title">CVSS 3.1 Score</div>
    <div class="cvss-box">
      <div style="display:flex;align-items:flex-end;gap:20px">
        <div class="cvss-score">{score:.1f}</div>
        <div>
          <div style="font-family:var(--mono);font-size:14px;color:{sev_color};font-weight:600;text-transform:uppercase">{severity_label(score)}</div>
          <div style="font-size:12px;color:var(--dim);margin-top:2px">CVSS 3.1 Base Score</div>
        </div>
      </div>
      <div class="cvss-bar"><div class="cvss-fill"></div></div>
      <div class="cvss-vector">{finding.get('cvss_vector','')}</div>
    </div>
  </div>

  <!-- Impact -->
  <div class="section">
    <div class="section-title">Impact</div>
    <div class="impact-box">
      <p>An unauthenticated or low-privileged attacker can enumerate user IDs and access private data belonging to any user in the system, including: <strong>{impact_fields}</strong>. At scale, this exposes the entire user database to unauthorized access, violating user privacy and potentially breaching data protection regulations (GDPR, CCPA). Depending on the HTTP methods accepted by the endpoint, this may also enable unauthorized modification or deletion of user records.</p>
    </div>
  </div>

  <!-- Recommended Fix -->
  <div class="section">
    <div class="section-title">Recommended Fix</div>
    <div class="fix-box">
      <p><strong>Implement server-side authorization checks</strong> on every request that accesses user-owned resources. The server must verify that the authenticated session's user ID matches the resource being requested — not just that the user is authenticated.</p>
      <br>
      <p>Example fix (pseudocode):</p>
      <br>
      <code style="font-family:var(--mono);font-size:12px;color:var(--accent);display:block;background:rgba(0,201,167,.06);padding:12px;border-radius:4px;white-space:pre">if request.user.id != requested_resource.owner_id:
    return 403 Forbidden</code>
      <br>
      <p>Additionally, consider using indirect object references (e.g. mapping internal IDs to random tokens per session) to prevent enumeration entirely.</p>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    Generated by IDOR Hunter Pro · RedMind Suite · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · Finding {finding.get('id','')}
  </div>

</div>
</body>
</html>"""


# ── PDF Report ────────────────────────────────────────────────────────────────

def generate_pdf_report(finding: dict, output_path: str) -> str:
    ev = finding.get('evidence', {})
    param = finding.get('param', {})
    score = finding.get('cvss_score', 0)
    severity = cvss_severity(score)
    sev_color = SEVERITY_COLORS[severity]
    sev_bg = SEVERITY_BG[severity]
    fields_exposed = ev.get('fields_exposed', [])

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title=f"IDOR Bug Report — {finding.get('id','')}",
        author="IDOR Hunter Pro"
    )

    # Styles
    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    mono  = 'Courier'
    sans  = 'Helvetica'

    s_title   = S('title',   fontName='Helvetica-Bold', fontSize=16, textColor=C_WHITE, leading=22, spaceAfter=6)
    s_meta    = S('meta',    fontName=mono, fontSize=8,  textColor=C_DIM, leading=12, spaceAfter=4)
    s_h2      = S('h2',      fontName='Helvetica-Bold', fontSize=10, textColor=C_DIM, leading=14, spaceBefore=16, spaceAfter=6)
    s_body    = S('body',    fontName=sans, fontSize=10, textColor=C_TEXT, leading=15, spaceAfter=6)
    s_mono    = S('mono',    fontName=mono, fontSize=9,  textColor=C_TEXT, leading=13, spaceAfter=4)
    s_mono_sm = S('monosm', fontName=mono, fontSize=8,  textColor=C_DIM,  leading=12)
    s_code    = S('code',    fontName=mono, fontSize=8,  textColor=C_ACCENT, leading=12, backColor=HexColor('#0a1a10'), borderPadding=6)
    s_center  = S('center',  fontName=sans, fontSize=9,  textColor=C_DIM, alignment=TA_CENTER, leading=12)

    story = []

    def hr():
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8, spaceBefore=4))

    def section(title):
        story.append(Spacer(1, 4))
        story.append(Paragraph(title, s_h2))
        hr()

    def info_table(rows):
        data = [[Paragraph(f'<font color="#5a6478">{k}</font>', s_mono_sm),
                 Paragraph(f'<font color="#e8edf5">{v}</font>', s_mono)]
                for k, v in rows]
        t = Table(data, colWidths=[55*mm, 110*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_SURFACE),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [C_SURFACE, HexColor('#0d1116')]),
            ('GRID', (0,0), (-1,-1), 0.5, C_BORDER),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)

    # ── Cover ──
    story.append(Spacer(1, 6))

    # Title block
    cover_data = [[
        Paragraph(f'<font color="{sev_color.hexval()}">{severity_label(score)} SEVERITY</font>', s_meta),
    ]]
    story.append(Paragraph('Bug Report — Insecure Direct Object Reference (IDOR)', s_title))
    story.append(Paragraph(
        f'Unauthorized access via <font face="Courier" color="#00c9a7">{param.get("key","id")}</font> parameter manipulation',
        S('sub', fontName=sans, fontSize=11, textColor=C_TEXT, leading=16, spaceAfter=8)
    ))

    # Severity + meta row
    meta_data = [
        [Paragraph(f'<font color="{sev_color.hexval()}">● {severity_label(score)}</font>', s_mono),
         Paragraph(f'CVSS {score:.1f}', s_mono),
         Paragraph(finding.get('method','GET'), s_mono),
         Paragraph(finding.get('status','confirmed').upper(), s_mono),
         Paragraph(f'{finding.get("hit_count",0)} confirmations', s_mono)]
    ]
    mt = Table(meta_data, colWidths=[30*mm, 25*mm, 20*mm, 30*mm, 35*mm])
    mt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), sev_bg),
        ('BOX', (0,0), (-1,-1), 1, sev_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(mt)
    story.append(Spacer(1, 8))
    story.append(Paragraph(f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")} · Finding ID: {finding.get("id","")} · IDOR Hunter Pro', s_center))
    hr()

    # ── Vulnerability Details ──
    section('VULNERABILITY DETAILS')
    info_table([
        ('Affected URL',        finding.get('endpoint','')),
        ('HTTP Method',         finding.get('method','GET')),
        ('Vulnerable Parameter',f'{param.get("key","id")} ({param.get("param_type","numeric")})'),
        ('Injected ID (PoC)',   str(ev.get('injected_id',''))),
        ('Your ID (Baseline)',  str(param.get('original_value',''))),
        ('Diff Score',          f'{ev.get("diff_score",0):.3f}'),
        ('Exposed Fields',      ', '.join(fields_exposed) or 'Unknown'),
    ])

    # ── Description ──
    section('DESCRIPTION')
    story.append(Paragraph(
        f'The application fails to verify that the authenticated user is authorized to access '
        f'resources identified by the <font face="Courier" color="#00c9a7">{param.get("key","id")}</font> '
        f'parameter at endpoint <font face="Courier" color="#00c9a7">{finding.get("endpoint","")}</font>. '
        f'By modifying this parameter from the authenticated value '
        f'(<font face="Courier" color="#00c9a7">{param.get("original_value","")}</font>) '
        f'to another user\'s value '
        f'(<font face="Courier" color="#ff4d6d">{ev.get("injected_id","")}</font>), '
        f'an attacker can access private data belonging to other users without authorization. '
        f'This was confirmed across <b>{finding.get("hit_count",0)} independent probe iterations</b>.',
        s_body
    ))

    # ── Steps to Reproduce ──
    section('STEPS TO REPRODUCE')
    steps = [
        f'Log in to the application with a valid user account.',
        f'Navigate to: {finding.get("endpoint","")}',
        f'Intercept the {finding.get("method","GET")} request.',
        f'Locate parameter: {param.get("key","id")} = {param.get("original_value","")}',
        f'Replace with target ID: {ev.get("injected_id","")}',
        f'Forward the modified request.',
        f'Observe server returns data belonging to a different user.',
    ]
    for i, step in enumerate(steps, 1):
        story.append(Paragraph(f'{i}. {step}', s_body))

    # ── Evidence ──
    section('PROOF OF CONCEPT — EVIDENCE')

    orig_url = ev.get('original_request', {}).get('url', '')
    exploit_url = ev.get('exploit_request', {}).get('url', '')
    orig_status = ev.get('original_response', {}).get('status_code', '')
    exploit_status = ev.get('exploit_response', {}).get('status_code', '')
    orig_size = ev.get('original_response', {}).get('body_size', 0)
    exploit_size = ev.get('exploit_response', {}).get('body_size', 0)

    ev_data = [
        [Paragraph('<font color="#5a6478">REQUEST TYPE</font>', s_mono_sm),
         Paragraph('<font color="#5a6478">ORIGINAL (YOUR ID)</font>', s_mono_sm),
         Paragraph('<font color="#ff4d6d">EXPLOIT (INJECTED ID)</font>', s_mono_sm)],
        [Paragraph('URL', s_mono_sm),
         Paragraph(f'<font color="#c8d0dc">{orig_url[:60]}...</font>' if len(orig_url)>60 else orig_url, s_mono_sm),
         Paragraph(f'<font color="#ff4d6d">{exploit_url[:60]}...</font>' if len(exploit_url)>60 else exploit_url, s_mono_sm)],
        [Paragraph('Status', s_mono_sm),
         Paragraph(f'<font color="#c8d0dc">{orig_status}</font>', s_mono_sm),
         Paragraph(f'<font color="#ff4d6d">{exploit_status}</font>', s_mono_sm)],
        [Paragraph('Body Size', s_mono_sm),
         Paragraph(f'<font color="#c8d0dc">{orig_size} bytes</font>', s_mono_sm),
         Paragraph(f'<font color="#ff4d6d">{exploit_size} bytes</font>', s_mono_sm)],
    ]
    et = Table(ev_data, colWidths=[30*mm, 80*mm, 60*mm])
    et.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_BORDER),
        ('BACKGROUND', (0,1), (-1,-1), C_SURFACE),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_SURFACE, HexColor('#0d1116')]),
        ('GRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(et)

    # ── CVSS ──
    section('CVSS 3.1 SCORE')
    cvss_data = [[
        Paragraph(f'<font color="{sev_color.hexval()}" size="28"><b>{score:.1f}</b></font>', s_title),
        Paragraph(
            f'<font color="{sev_color.hexval()}"><b>{severity_label(score)}</b></font><br/>'
            f'<font color="#5a6478" size="8">{finding.get("cvss_vector","")}</font>',
            s_body
        )
    ]]
    ct = Table(cvss_data, colWidths=[35*mm, 135*mm])
    ct.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), sev_bg),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(ct)

    # ── Impact ──
    section('IMPACT')
    impact_fields = ', '.join(fields_exposed) if fields_exposed else 'user data'
    story.append(Paragraph(
        f'An attacker can enumerate user IDs and access private data belonging to any user '
        f'in the system, including: <b>{impact_fields}</b>. At scale, this exposes the entire '
        f'user database to unauthorized access, violating user privacy and potentially breaching '
        f'data protection regulations (GDPR, CCPA). Depending on accepted HTTP methods, '
        f'this may also enable unauthorized modification or deletion of user records.',
        s_body
    ))

    # ── Recommended Fix ──
    section('RECOMMENDED FIX')
    story.append(Paragraph(
        'Implement server-side authorization checks on every request that accesses user-owned '
        'resources. The server must verify that the authenticated session\'s user ID matches '
        'the resource owner — not just that the user is authenticated.',
        s_body
    ))
    story.append(Paragraph('Example fix (pseudocode):', s_body))
    story.append(Paragraph(
        'if request.user.id != requested_resource.owner_id:<br/>    return 403 Forbidden',
        s_code
    ))
    story.append(Paragraph(
        'Consider using indirect object references (mapping internal IDs to per-session tokens) '
        'to prevent enumeration entirely.',
        s_body
    ))

    # ── Footer ──
    story.append(Spacer(1, 12))
    hr()
    story.append(Paragraph(
        f'Generated by IDOR Hunter Pro · RedMind Suite · {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}',
        s_center
    ))

    doc.build(story)
    return output_path
