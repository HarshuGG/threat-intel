"""
CVE Enricher — extracts IOCs, MITRE ATT&CK TTPs, attack methods, threat actors.

Currently runs in MOCK mode (no API key needed).
To enable real AI enrichment, set in .env:
  AI_PROVIDER=ollama              # free, local — no API key needed
  AI_MODEL_OLLAMA=llama3.2        # any model you've pulled
  OLLAMA_BASE_URL=http://localhost:11434/v1

  AI_PROVIDER=openai              # requires API key
  AI_API_KEY=sk-...

Supports: ollama, openai, anthropic
"""
import json
import logging
import os
from datetime import datetime
from sqlalchemy.orm import Session
from .database import CVE

logger = logging.getLogger(__name__)

AI_PROVIDER = os.getenv("AI_PROVIDER", "mock")   # "openai", "anthropic", "ollama", "mock"
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL_OPENAI = os.getenv("AI_MODEL_OPENAI", "gpt-4o-mini")
AI_MODEL_ANTHROPIC = os.getenv("AI_MODEL_ANTHROPIC", "claude-haiku-4-5-20251001")
AI_MODEL_OLLAMA = os.getenv("AI_MODEL_OLLAMA", "llama3.2")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")

ENRICHMENT_PROMPT = """You are a senior threat intelligence analyst and threat hunter. Analyze the following CVE and return a structured JSON object with detailed threat intelligence that will help security teams detect and respond to this vulnerability.

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score}
Severity: {severity}
Affected Products: {affected_products}
References: {references}

Return ONLY valid JSON with this exact structure:
{{
  "ai_summary": "2-3 sentence executive summary for threat hunters explaining what this is, why it matters, and what attackers can do with it",
  "iocs": [
    {{"type": "domain|ip|hash|url|email|registry_key|file_path|user_agent", "value": "example.com", "description": "C2 server pattern observed in exploitation"}}
  ],
  "mitre_techniques": [
    {{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/", "description": "How this technique applies to this CVE"}}
  ],
  "attack_vectors": [
    {{"step": 1, "phase": "Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Exfiltration|Impact", "description": "Detailed step an attacker would take"}}
  ],
  "threat_actors": [
    {{"name": "Actor Name", "aliases": ["Alias1"], "description": "Why this actor may exploit this CVE"}}
  ],
  "remediation": "Specific, actionable remediation steps including patches, mitigations, and detection rules",
  "poc_available": true,
  "exploited_in_wild": false,
  "poc_urls": ["https://github.com/..."]
}}

Base your analysis on the CVE description and known exploitation patterns. If you don't have specific IOC data, provide realistic patterns based on the vulnerability type. Always include at least 2-3 MITRE techniques and 3-5 attack steps."""


def _mock_enrich(cve: CVE) -> dict:
    """
    Generates structured mock enrichment data based on CVE description keywords.
    This allows the site to display real-looking content without an API key.
    Replace with real AI enrichment once API key is configured.
    """
    desc = (cve.description or "").lower()
    cve_id = cve.cve_id or ""
    score = cve.cvss_score or 0.0

    # Determine vulnerability category from description keywords
    is_rce = any(k in desc for k in ["remote code execution", "rce", "execute arbitrary", "command execution"])
    is_sqli = any(k in desc for k in ["sql injection", "sqli", "database query"])
    is_xss = any(k in desc for k in ["cross-site scripting", "xss", "script injection"])
    is_privesc = any(k in desc for k in ["privilege escalation", "elevated privilege", "local privilege"])
    is_overflow = any(k in desc for k in ["buffer overflow", "heap overflow", "stack overflow", "memory corruption"])
    is_auth_bypass = any(k in desc for k in ["authentication bypass", "improper authentication", "unauthenticated"])
    is_lfi = any(k in desc for k in ["path traversal", "directory traversal", "local file inclusion"])
    is_ssrf = any(k in desc for k in ["server-side request forgery", "ssrf"])
    is_dos = any(k in desc for k in ["denial of service", "crash", "infinite loop", "resource exhaustion"])

    # Build MITRE techniques
    mitre = []
    attack_steps = []

    if is_rce or is_overflow:
        mitre += [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
             "url": "https://attack.mitre.org/techniques/T1190/",
             "description": "Attacker exploits the vulnerability in an internet-facing service to gain initial access"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution",
             "url": "https://attack.mitre.org/techniques/T1059/",
             "description": "Post-exploitation shell commands executed through the vulnerability"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
             "url": "https://attack.mitre.org/techniques/T1105/",
             "description": "Attacker downloads malware or tools after gaining code execution"},
        ]
        attack_steps = [
            {"step": 1, "phase": "Reconnaissance", "description": f"Attacker identifies vulnerable {', '.join([p['product'] for p in (cve.affected_products or [])[:2]]) or 'service'} instances using Shodan, Censys, or active scanning"},
            {"step": 2, "phase": "Initial Access", "description": f"Attacker crafts malicious payload exploiting {cve_id} to achieve remote code execution"},
            {"step": 3, "phase": "Execution", "description": "Attacker executes arbitrary OS commands or shellcode in the context of the vulnerable process"},
            {"step": 4, "phase": "Persistence", "description": "Attacker installs backdoor, cron job, or web shell for persistent access"},
            {"step": 5, "phase": "Lateral Movement", "description": "Attacker uses compromised host as pivot point to access internal network resources"},
        ]
    elif is_sqli:
        mitre += [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
             "url": "https://attack.mitre.org/techniques/T1190/",
             "description": "SQL injection exploited against web application database layer"},
            {"id": "T1005", "name": "Data from Local System", "tactic": "Collection",
             "url": "https://attack.mitre.org/techniques/T1005/",
             "description": "Database contents exfiltrated including credentials and PII"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion",
             "url": "https://attack.mitre.org/techniques/T1078/",
             "description": "Credentials stolen from database used for further access"},
        ]
        attack_steps = [
            {"step": 1, "phase": "Reconnaissance", "description": "Attacker fingerprints web application and identifies injectable parameters using automated scanners"},
            {"step": 2, "phase": "Initial Access", "description": f"Attacker injects SQL payload via vulnerable parameter to bypass authentication or extract data"},
            {"step": 3, "phase": "Collection", "description": "Attacker dumps database tables including user credentials, session tokens, and sensitive data"},
            {"step": 4, "phase": "Credential Access", "description": "Extracted password hashes cracked offline using hashcat/john or plain-text credentials used directly"},
            {"step": 5, "phase": "Lateral Movement", "description": "Valid credentials reused across other systems and services in the environment"},
        ]
    elif is_auth_bypass:
        mitre += [
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access",
             "url": "https://attack.mitre.org/techniques/T1078/",
             "description": "Authentication bypass grants attacker access as legitimate user"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
             "url": "https://attack.mitre.org/techniques/T1548/",
             "description": "Bypassed auth may grant elevated or admin-level permissions"},
        ]
        attack_steps = [
            {"step": 1, "phase": "Reconnaissance", "description": "Attacker identifies authentication endpoint and tests for bypass conditions"},
            {"step": 2, "phase": "Initial Access", "description": f"Attacker exploits {cve_id} authentication flaw to gain unauthorized access without valid credentials"},
            {"step": 3, "phase": "Discovery", "description": "Attacker enumerates accessible resources, users, and configurations"},
            {"step": 4, "phase": "Collection", "description": "Attacker exfiltrates sensitive data accessible without proper authorization"},
        ]
    elif is_privesc:
        mitre += [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
             "url": "https://attack.mitre.org/techniques/T1068/",
             "description": "Local attacker exploits vulnerability to gain root/SYSTEM privileges"},
            {"id": "T1134", "name": "Access Token Manipulation", "tactic": "Privilege Escalation",
             "url": "https://attack.mitre.org/techniques/T1134/",
             "description": "Elevated token used to impersonate high-privilege accounts"},
        ]
        attack_steps = [
            {"step": 1, "phase": "Initial Access", "description": "Attacker has low-privilege local access (e.g., via phishing or compromised service account)"},
            {"step": 2, "phase": "Privilege Escalation", "description": f"Attacker exploits {cve_id} to escalate from low-privilege user to root/SYSTEM/admin"},
            {"step": 3, "phase": "Defense Evasion", "description": "Elevated privileges used to disable security controls, clear logs, and establish persistence"},
            {"step": 4, "phase": "Impact", "description": "Full system compromise achieved; attacker can install ransomware, exfiltrate all data, or pivot"},
        ]
    else:
        # Generic
        mitre += [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
             "url": "https://attack.mitre.org/techniques/T1190/",
             "description": "Public-facing application vulnerability exploited for initial access"},
            {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution",
             "url": "https://attack.mitre.org/techniques/T1203/",
             "description": "Vulnerability exploited to execute attacker-controlled code"},
        ]
        attack_steps = [
            {"step": 1, "phase": "Reconnaissance", "description": "Attacker scans for vulnerable versions using version banners or PoC scanners"},
            {"step": 2, "phase": "Initial Access", "description": f"Attacker triggers {cve_id} vulnerability with a crafted request or payload"},
            {"step": 3, "phase": "Execution", "description": "Vulnerability exploited to perform unauthorized actions on the target system"},
            {"step": 4, "phase": "Impact", "description": "Depending on vulnerability type, attacker achieves data access, service disruption, or code execution"},
        ]

    # Build IOCs (generic patterns, real ones come from AI)
    products = cve.affected_products or []
    product_str = products[0]["product"] if products else "application"

    iocs = [
        {"type": "user_agent", "value": "Mozilla/5.0 (compatible; exploit/1.0)", "description": "Generic exploit scanner user agent pattern"},
        {"type": "url", "value": f"/api/vuln-endpoint?payload=<malicious>", "description": f"Exploit attempt against {product_str} endpoint — monitor access logs for anomalous params"},
    ]
    if is_rce:
        iocs.append({"type": "registry_key", "value": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\backdoor", "description": "Persistence mechanism after successful RCE"})
    if is_sqli:
        iocs.append({"type": "url", "value": "' OR 1=1--", "description": "Classic SQL injection payload — monitor WAF and DB query logs"})

    # Summary
    severity_word = "critical" if score >= 9 else "high-severity" if score >= 7 else "moderate"
    ai_summary = (
        f"{cve_id} is a {severity_word} vulnerability"
        f"{' with a CVSS score of ' + str(score) if score else ''} affecting "
        f"{', '.join([p['product'] for p in products[:2]]) if products else 'the target software'}. "
        f"{'An attacker can exploit this to achieve remote code execution without authentication. ' if is_rce and is_auth_bypass else ''}"
        f"{'This vulnerability allows SQL injection leading to unauthorized data access. ' if is_sqli else ''}"
        f"{'Authentication can be bypassed allowing unauthenticated access. ' if is_auth_bypass and not is_rce else ''}"
        f"Threat hunters should monitor for exploit attempts and apply vendor patches immediately."
    )

    remediation = cve.remediation or (
        "1. Apply vendor-supplied security patches immediately.\n"
        "2. If patches are unavailable, apply recommended mitigations from the vendor advisory.\n"
        "3. Enable WAF rules or IDS signatures to detect exploitation attempts.\n"
        "4. Monitor logs for indicators of compromise listed above.\n"
        "5. Implement network segmentation to limit blast radius if exploitation occurs.\n"
        "6. Subscribe to vendor security advisories for this product."
    )

    poc_available = score >= 7.0 or cve.cisa_kev or False

    return {
        "iocs": iocs,
        "mitre_techniques": mitre,
        "attack_vectors": attack_steps,
        "threat_actors": [],
        "remediation": remediation,
        "ai_summary": ai_summary,
        "poc_available": poc_available,
        "exploited_in_wild": cve.cisa_kev or False,
        "poc_urls": [],
        "enrichment_source": "mock",
    }


async def _enrich_openai(cve: CVE) -> dict:
    try:
        import openai
        client = openai.AsyncOpenAI(api_key=AI_API_KEY)

        products_str = json.dumps(cve.affected_products or [])
        refs_str = ", ".join((cve.references or [])[:5])

        prompt = ENRICHMENT_PROMPT.format(
            cve_id=cve.cve_id,
            description=cve.description or "",
            cvss_score=cve.cvss_score or "N/A",
            severity=cve.severity or "UNKNOWN",
            affected_products=products_str,
            references=refs_str,
        )

        response = await client.chat.completions.create(
            model=AI_MODEL_OPENAI,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.3,
        )
        result = json.loads(response.choices[0].message.content)
        result["enrichment_source"] = f"openai/{AI_MODEL_OPENAI}"
        return result

    except Exception as e:
        logger.error(f"OpenAI enrichment failed for {cve.cve_id}: {e}")
        return _mock_enrich(cve)


async def _enrich_anthropic(cve: CVE) -> dict:
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=AI_API_KEY)

        products_str = json.dumps(cve.affected_products or [])
        refs_str = ", ".join((cve.references or [])[:5])

        prompt = ENRICHMENT_PROMPT.format(
            cve_id=cve.cve_id,
            description=cve.description or "",
            cvss_score=cve.cvss_score or "N/A",
            severity=cve.severity or "UNKNOWN",
            affected_products=products_str,
            references=refs_str,
        )

        response = await client.messages.create(
            model=AI_MODEL_ANTHROPIC,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text
        # Extract JSON from response
        start = text.find("{")
        end = text.rfind("}") + 1
        result = json.loads(text[start:end])
        result["enrichment_source"] = f"anthropic/{AI_MODEL_ANTHROPIC}"
        return result

    except Exception as e:
        logger.error(f"Anthropic enrichment failed for {cve.cve_id}: {e}")
        return _mock_enrich(cve)


async def _enrich_ollama(cve: CVE) -> dict:
    """Enrich using local Ollama instance (OpenAI-compatible API)."""
    try:
        import httpx

        products_str = json.dumps(cve.affected_products or [])
        refs_str = ", ".join((cve.references or [])[:5])

        prompt = ENRICHMENT_PROMPT.format(
            cve_id=cve.cve_id,
            description=cve.description or "",
            cvss_score=cve.cvss_score or "N/A",
            severity=cve.severity or "UNKNOWN",
            affected_products=products_str,
            references=refs_str,
        )

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/chat/completions",
                json={
                    "model": AI_MODEL_OLLAMA,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "format": "json",
                },
            )
            response.raise_for_status()
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            start = text.find("{")
            end = text.rfind("}") + 1
            result = json.loads(text[start:end])
            result["enrichment_source"] = f"ollama/{AI_MODEL_OLLAMA}"
            return result

    except Exception as e:
        logger.error(f"Ollama enrichment failed for {cve.cve_id}: {e}")
        return _mock_enrich(cve)


async def enrich_cve(cve: CVE, db: Session) -> bool:
    """Enrich a single CVE with AI-generated threat intelligence."""
    try:
        if AI_PROVIDER == "ollama":
            data = await _enrich_ollama(cve)
        elif AI_PROVIDER == "openai" and AI_API_KEY:
            data = await _enrich_openai(cve)
        elif AI_PROVIDER == "anthropic" and AI_API_KEY:
            data = await _enrich_anthropic(cve)
        else:
            data = _mock_enrich(cve)

        cve.iocs = data.get("iocs", [])
        cve.mitre_techniques = data.get("mitre_techniques", [])
        cve.attack_vectors = data.get("attack_vectors", [])
        cve.threat_actors = data.get("threat_actors", [])
        cve.remediation = data.get("remediation", cve.remediation)
        cve.ai_summary = data.get("ai_summary", "")
        cve.poc_available = data.get("poc_available", False)
        cve.exploited_in_wild = data.get("exploited_in_wild", cve.exploited_in_wild or False)
        cve.poc_urls = data.get("poc_urls", [])
        cve.enrichment_source = data.get("enrichment_source", "mock")
        cve.enriched_at = datetime.utcnow()
        db.commit()
        return True

    except Exception as e:
        logger.error(f"Enrichment failed for {cve.cve_id}: {e}")
        return False


async def enrich_pending(db: Session, limit: int = 50) -> int:
    """Enrich all CVEs that haven't been enriched yet."""
    pending = db.query(CVE).filter(CVE.enriched_at.is_(None)).limit(limit).all()
    count = 0
    for cve in pending:
        if await enrich_cve(cve, db):
            count += 1
    return count
