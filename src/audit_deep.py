"""
Jira Deep Audit — Phase 2
===========================
Pulls the actual VALUES inside classification fields, resolutions,
link types, field contexts, and operational metadata that Phase 1
only counted but didn't enumerate.

Outputs: reports/deep_audit_report.md + reports/deep_audit_report.json
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from base64 import b64encode
from typing import Dict, List, Optional, Any

import requests

# ---------------------------------------------------------------------------
os.makedirs("reports", exist_ok=True)
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"logs/deep_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

JIRA_INSTANCE_URL = os.getenv("JIRA_INSTANCE_URL", "").rstrip("/")
JIRA_USER_EMAIL = os.getenv("JIRA_USER_EMAIL", "")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "INFSOC")



def create_session() -> requests.Session:
    session = requests.Session()
    credentials = b64encode(f"{JIRA_USER_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    session.headers.update({
        "Authorization": f"Basic {credentials}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    return session


def api_get(session: requests.Session, path: str, params: Optional[Dict] = None) -> Any:
    url = f"{JIRA_INSTANCE_URL}{path}"
    try:
        resp = session.get(url, params=params, timeout=30)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "5"))
            logger.warning(f"Rate limited on {path}, sleeping {retry_after}s")
            time.sleep(retry_after)
            resp = session.get(url, params=params, timeout=30)
        if resp.status_code in (404, 403):
            logger.warning(f"HTTP {resp.status_code} on {path}")
            return None
        if resp.status_code >= 400:
            logger.warning(f"HTTP {resp.status_code} on {path}: {resp.text[:200]}")
            return None
        return resp.json()
    except Exception as e:
        logger.error(f"Request failed for {path}: {e}")
        return None


def api_get_v3(session: requests.Session, path: str, params: Optional[Dict] = None) -> Any:
    """Use v3 API for search (v2 deprecated on this instance)."""
    url = f"{JIRA_INSTANCE_URL}{path}"
    try:
        resp = session.get(url, params=params, timeout=30)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "5"))
            time.sleep(retry_after)
            resp = session.get(url, params=params, timeout=30)
        if resp.status_code >= 400:
            logger.warning(f"HTTP {resp.status_code} on {path}: {resp.text[:200]}")
            return None
        return resp.json()
    except Exception as e:
        logger.error(f"Request failed for {path}: {e}")
        return None



# ---------------------------------------------------------------------------
# Deep Audit Collectors
# ---------------------------------------------------------------------------

def get_field_options(session: requests.Session, field_id: str, field_name: str) -> Dict:
    """Pull all allowed values for an option/select field via contexts."""
    logger.info(f"  Fetching options for {field_name} ({field_id})...")
    
    # Try the field configuration contexts endpoint (v2)
    contexts = api_get(session, f"/rest/api/2/field/{field_id}/context")
    
    options = []
    
    if contexts and isinstance(contexts, dict):
        ctx_values = contexts.get("values", contexts.get("contexts", []))
        for ctx in ctx_values:
            ctx_id = ctx.get("id")
            if ctx_id:
                opts = api_get(session, f"/rest/api/2/field/{field_id}/context/{ctx_id}/option")
                if opts and isinstance(opts, dict):
                    for opt in opts.get("values", []):
                        options.append({
                            "value": opt.get("value"),
                            "id": opt.get("id"),
                            "disabled": opt.get("disabled", False),
                        })
                time.sleep(0.3)
    
    # If no contexts approach worked, try createmeta approach
    if not options:
        # Try getting options from the create screen metadata
        pass  # We'll get these from the create meta data we already have
    
    return {
        "field_id": field_id,
        "field_name": field_name,
        "option_count": len(options),
        "options": options,
    }


def get_field_options_from_createmeta(session: requests.Session, field_id: str, issue_type_id: str) -> List[str]:
    """Get allowed values for a field from createmeta for a specific issue type."""
    meta = api_get(session, f"/rest/api/2/issue/createmeta/{JIRA_PROJECT_KEY}/issuetypes/{issue_type_id}", 
                   params={"expand": "fields"})
    if meta:
        fields = meta.get("fields", meta.get("values", {}))
        if isinstance(fields, dict) and field_id in fields:
            allowed = fields[field_id].get("allowedValues", [])
            return [v.get("value", v.get("name", str(v.get("id", "")))) for v in allowed]
    return []


def audit_classification_fields(session: requests.Session) -> Dict:
    """Pull all option values for key classification/reason fields."""
    logger.info("=" * 50)
    logger.info("DEEP AUDIT: Classification Field Values")
    logger.info("=" * 50)
    
    # Key fields we want to enumerate
    target_fields = [
        ("customfield_10288", "SOC categorisation", "10531"),  # Email request type
        ("customfield_10275", "Closure code", "10531"),
        ("customfield_10252", "Source", "10531"),
        ("customfield_10244", "Pending reason", "10534"),  # Incident type
        ("customfield_10242", "Urgency", "10534"),
        ("customfield_10243", "Impact", "10534"),
        ("customfield_10301", "Purple Testing", "10531"),
        ("customfield_10398", "Referred To (Group)", "10531"),
        ("customfield_10390", "Investigation reason", "10531"),
        ("customfield_10268", "Investigation reason (alt)", "10534"),
        ("customfield_10360", "Security Tool", "10550"),
        ("customfield_10469", "Security Risk Level", "10531"),
        ("customfield_10489", "Incident Priority", "10534"),
        ("customfield_10471", "Source (alt)", "10531"),
        ("customfield_10381", "Pending reason (alt)", "10531"),
        ("customfield_10399", "SIR Logged?", "10531"),
    ]
    
    results = {}
    for field_id, field_name, issue_type_id in target_fields:
        logger.info(f"  Pulling values for: {field_name} ({field_id})")
        
        # Method 1: Try field contexts API
        field_data = get_field_options(session, field_id, field_name)
        
        # Method 2: If no options from contexts, try createmeta
        if field_data["option_count"] == 0:
            values = get_field_options_from_createmeta(session, field_id, issue_type_id)
            if values:
                field_data["options"] = [{"value": v, "disabled": False} for v in values]
                field_data["option_count"] = len(values)
                field_data["source"] = "createmeta"
            else:
                field_data["source"] = "not_accessible"
        else:
            field_data["source"] = "field_context"
        
        results[field_id] = field_data
        time.sleep(0.3)
    
    return results



def audit_resolutions(session: requests.Session) -> Dict:
    """Get all resolution types available."""
    logger.info("Fetching resolution types...")
    resolutions = api_get(session, "/rest/api/2/resolution") or []
    return {
        "count": len(resolutions),
        "resolutions": [{"name": r.get("name"), "id": r.get("id"), "description": r.get("description", "")} for r in resolutions],
    }


def audit_issue_link_types(session: requests.Session) -> Dict:
    """Get all issue link types (blocks, duplicates, relates to, etc.)."""
    logger.info("Fetching issue link types...")
    data = api_get(session, "/rest/api/2/issueLinkType")
    if not data:
        return {"count": 0, "link_types": []}
    
    link_types = data.get("issueLinkTypes", [])
    return {
        "count": len(link_types),
        "link_types": [{
            "name": lt.get("name"),
            "id": lt.get("id"),
            "inward": lt.get("inward"),
            "outward": lt.get("outward"),
        } for lt in link_types],
    }


def audit_issue_security_levels(session: requests.Session) -> Dict:
    """Get security levels if configured."""
    logger.info("Fetching security levels...")
    data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/securitylevel")
    if not data:
        return {"configured": False, "levels": []}
    
    levels = data.get("levels", [])
    return {
        "configured": len(levels) > 0,
        "count": len(levels),
        "levels": [{"name": l.get("name"), "id": l.get("id"), "description": l.get("description", "")} for l in levels],
    }


def audit_filters(session: requests.Session) -> Dict:
    """Get saved filters (shared) for the project."""
    logger.info("Fetching saved filters...")
    # Get filters owned by the connected user or shared with project
    data = api_get(session, "/rest/api/2/filter/search", params={
        "projectId": "10414",  # INFSOC project ID from Phase 1
        "maxResults": 50,
    })
    if not data:
        # Try without project filter
        data = api_get(session, "/rest/api/2/filter/favourite")
        if data:
            return {
                "count": len(data) if isinstance(data, list) else 0,
                "filters": [{"name": f.get("name"), "jql": f.get("jql", ""), "owner": f.get("owner", {}).get("displayName", "")} for f in (data if isinstance(data, list) else [])],
                "note": "Showing favourite filters only (project filter not accessible)"
            }
        return {"count": 0, "filters": [], "note": "Filters not accessible"}
    
    filters = data.get("values", [])
    return {
        "count": len(filters),
        "filters": [{"name": f.get("name"), "jql": f.get("jql", ""), "owner": f.get("owner", {}).get("displayName", "")} for f in filters],
    }


def audit_dashboards(session: requests.Session) -> Dict:
    """Get dashboards."""
    logger.info("Fetching dashboards...")
    data = api_get(session, "/rest/api/2/dashboard", params={"maxResults": 50})
    if not data:
        return {"count": 0, "dashboards": []}
    
    dashboards = data.get("dashboards", [])
    return {
        "count": len(dashboards),
        "dashboards": [{"name": d.get("name"), "id": d.get("id"), "owner": d.get("owner", {}).get("displayName", "")} for d in dashboards],
    }



def audit_workflow_transitions(session: requests.Session) -> Dict:
    """Get workflow transitions per issue type by checking a sample issue or createmeta."""
    logger.info("Fetching workflow transitions per issue type...")
    
    # Get project statuses per issue type (already have this, but now map transitions)
    statuses_data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/statuses") or []
    
    transitions_by_type = {}
    for it in statuses_data:
        type_name = it.get("name")
        statuses = [s.get("name") for s in it.get("statuses", [])]
        transitions_by_type[type_name] = {
            "statuses": statuses,
            "status_count": len(statuses),
            "has_triage": any("triage" in s.lower() or "triaged" in s.lower() for s in statuses),
            "has_escalation": any("escalat" in s.lower() for s in statuses),
            "has_waiting": any("waiting" in s.lower() or "pending" in s.lower() for s in statuses),
            "has_cancelled": any("cancel" in s.lower() for s in statuses),
            "has_reopened": any("reopen" in s.lower() for s in statuses),
            "has_blocked": any("block" in s.lower() for s in statuses),
            "has_referred": any("refer" in s.lower() for s in statuses),
            "has_investigating": any("investigat" in s.lower() for s in statuses),
        }
    
    return transitions_by_type


def audit_request_type_fields(session: requests.Session) -> Dict:
    """Get fields visible on each JSM request type (portal view)."""
    logger.info("Fetching request type portal fields...")
    
    # Find service desk ID
    sds = api_get(session, "/rest/servicedeskapi/servicedesk")
    if not sds:
        return {"error": "Cannot access service desk API"}
    
    sd_id = None
    for sd in sds.get("values", []):
        if sd.get("projectKey") == JIRA_PROJECT_KEY:
            sd_id = sd.get("id")
            break
    
    if not sd_id:
        return {"error": f"No service desk for {JIRA_PROJECT_KEY}"}
    
    # Get request types
    rt_data = api_get(session, f"/rest/servicedeskapi/servicedesk/{sd_id}/requesttype")
    if not rt_data:
        return {"error": "Cannot fetch request types"}
    
    result = {}
    for rt in rt_data.get("values", []):
        rt_id = rt.get("id")
        rt_name = rt.get("name")
        
        # Get fields for this request type
        fields_data = api_get(session, f"/rest/servicedeskapi/servicedesk/{sd_id}/requesttype/{rt_id}/field")
        
        portal_fields = []
        if fields_data and isinstance(fields_data, dict):
            for field in fields_data.get("requestTypeFields", []):
                portal_fields.append({
                    "field_id": field.get("fieldId"),
                    "name": field.get("name"),
                    "required": field.get("required", False),
                    "visible": field.get("visible", True),
                    "description": field.get("description", ""),
                })
        
        result[rt_name] = {
            "id": rt_id,
            "field_count": len(portal_fields),
            "fields": portal_fields,
            "required_fields": [f["name"] for f in portal_fields if f.get("required")],
        }
        time.sleep(0.3)
    
    return result


def audit_labels_in_use(session: requests.Session) -> Dict:
    """Check what labels are being used in the project."""
    logger.info("Fetching labels in use...")
    # v3 search for label aggregation
    data = api_get_v3(session, "/rest/api/3/label", params={"maxResults": 100})
    if data:
        labels = data.get("values", [])
        return {"count": len(labels), "labels": labels[:100]}
    return {"count": 0, "labels": [], "note": "Labels API not accessible"}


def audit_issue_type_schemes(session: requests.Session) -> Dict:
    """Get issue type scheme for the project."""
    logger.info("Fetching issue type schemes...")
    data = api_get(session, "/rest/api/2/issuetypescheme")
    if not data:
        return {"accessible": False}
    
    schemes = data.get("schemes", data.get("values", []))
    return {
        "accessible": True,
        "count": len(schemes) if isinstance(schemes, list) else 0,
        "schemes": schemes[:10] if isinstance(schemes, list) else [],
    }


def audit_project_properties(session: requests.Session) -> Dict:
    """Get project properties (can contain config metadata)."""
    logger.info("Fetching project properties...")
    data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/properties")
    if not data:
        return {"accessible": False, "properties": []}
    
    keys = data.get("keys", [])
    properties = {}
    for key_info in keys:
        key = key_info.get("key")
        if key:
            val = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/properties/{key}")
            if val:
                properties[key] = val.get("value", val)
            time.sleep(0.2)
    
    return {"accessible": True, "property_count": len(properties), "properties": properties}


def audit_issue_counts_v3(session: requests.Session) -> Dict:
    """Use v3 search API to get issue counts."""
    logger.info("Fetching issue counts via v3 API...")
    
    result = {"total": 0, "by_type": {}, "by_status_category": {}, "by_priority": {}}
    
    # Total
    data = api_get_v3(session, "/rest/api/3/search/jql", params={
        "jql": f"project = {JIRA_PROJECT_KEY}",
        "maxResults": 0,
    })
    if data:
        result["total"] = data.get("total", 0)
    
    # By issue type
    types_data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/statuses") or []
    for it in types_data:
        type_name = it.get("name")
        count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
            "jql": f'project = {JIRA_PROJECT_KEY} AND issuetype = "{type_name}"',
            "maxResults": 0,
        })
        if count_data:
            result["by_type"][type_name] = count_data.get("total", 0)
        time.sleep(0.3)
    
    # By status category
    for cat in ["To Do", "In Progress", "Done"]:
        count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
            "jql": f'project = {JIRA_PROJECT_KEY} AND statusCategory = "{cat}"',
            "maxResults": 0,
        })
        if count_data:
            result["by_status_category"][cat] = count_data.get("total", 0)
        time.sleep(0.3)
    
    # By priority
    for pri in ["Highest", "High", "Medium", "Low", "Lowest"]:
        count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
            "jql": f'project = {JIRA_PROJECT_KEY} AND priority = "{pri}"',
            "maxResults": 0,
        })
        if count_data:
            result["by_priority"][pri] = count_data.get("total", 0)
        time.sleep(0.3)
    
    # Unassigned
    count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
        "jql": f"project = {JIRA_PROJECT_KEY} AND assignee = EMPTY AND statusCategory != Done",
        "maxResults": 0,
    })
    if count_data:
        result["unassigned_open"] = count_data.get("total", 0)
    
    # Created last 30 days
    count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
        "jql": f"project = {JIRA_PROJECT_KEY} AND created >= -30d",
        "maxResults": 0,
    })
    if count_data:
        result["created_last_30d"] = count_data.get("total", 0)
    
    # Resolved last 30 days
    count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
        "jql": f"project = {JIRA_PROJECT_KEY} AND resolved >= -30d",
        "maxResults": 0,
    })
    if count_data:
        result["resolved_last_30d"] = count_data.get("total", 0)
    
    # Open > 90 days
    count_data = api_get_v3(session, "/rest/api/3/search/jql", params={
        "jql": f"project = {JIRA_PROJECT_KEY} AND statusCategory != Done AND created <= -90d",
        "maxResults": 0,
    })
    if count_data:
        result["open_older_than_90d"] = count_data.get("total", 0)
    
    return result



# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_deep_report(data: Dict) -> str:
    """Generate Markdown report from deep audit data."""
    lines = []
    lines.append("# INFSOC Deep Audit — Phase 2")
    lines.append("")
    lines.append(f"**Instance:** {JIRA_INSTANCE_URL}")
    lines.append(f"**Project:** {JIRA_PROJECT_KEY}")
    lines.append(f"**Date:** {datetime.now().isoformat()}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Issue Counts (operational context)
    counts = data.get("issue_counts", {})
    lines.append("## 1. Issue Volume (Operational Context)")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| **Total issues (all time)** | {counts.get('total', 'N/A')} |")
    lines.append(f"| Created last 30 days | {counts.get('created_last_30d', 'N/A')} |")
    lines.append(f"| Resolved last 30 days | {counts.get('resolved_last_30d', 'N/A')} |")
    lines.append(f"| Open > 90 days (stale) | {counts.get('open_older_than_90d', 'N/A')} |")
    lines.append(f"| Unassigned & open | {counts.get('unassigned_open', 'N/A')} |")
    lines.append("")
    
    if counts.get("by_type"):
        lines.append("### By Issue Type")
        lines.append("")
        lines.append("| Issue Type | Count |")
        lines.append("|-----------|-------|")
        for t, c in sorted(counts["by_type"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {t} | {c} |")
        lines.append("")
    
    if counts.get("by_status_category"):
        lines.append("### By Status Category")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for s, c in counts["by_status_category"].items():
            lines.append(f"| {s} | {c} |")
        lines.append("")
    
    if counts.get("by_priority"):
        lines.append("### By Priority")
        lines.append("")
        lines.append("| Priority | Count |")
        lines.append("|----------|-------|")
        for p, c in sorted(counts["by_priority"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {p} | {c} |")
        lines.append("")
    
    # Classification Fields
    class_data = data.get("classification_fields", {})
    lines.append("## 2. Classification Fields — All Option Values")
    lines.append("")
    lines.append("These are the actual dropdown/select values configured for each field.")
    lines.append("")
    
    for field_id, field_info in class_data.items():
        name = field_info.get("field_name", field_id)
        opts = field_info.get("options", [])
        source = field_info.get("source", "unknown")
        lines.append(f"### {name} (`{field_id}`)")
        lines.append(f"*Source: {source} | Options: {field_info.get('option_count', 0)}*")
        lines.append("")
        if opts:
            lines.append("| # | Value | Disabled |")
            lines.append("|---|-------|----------|")
            for i, opt in enumerate(opts, 1):
                val = opt.get("value", "N/A")
                disabled = "Yes" if opt.get("disabled") else ""
                lines.append(f"| {i} | {val} | {disabled} |")
        else:
            lines.append("*No options accessible via API — check Jira admin UI.*")
        lines.append("")
    
    # Resolutions
    res_data = data.get("resolutions", {})
    lines.append("## 3. Resolution Types")
    lines.append("")
    lines.append(f"**Count:** {res_data.get('count', 0)}")
    lines.append("")
    if res_data.get("resolutions"):
        lines.append("| Resolution | Description |")
        lines.append("|-----------|-------------|")
        for r in res_data.get("resolutions", []):
            lines.append(f"| {r['name']} | {r.get('description', '')[:60]} |")
    lines.append("")
    
    # Link Types
    link_data = data.get("link_types", {})
    lines.append("## 4. Issue Link Types")
    lines.append("")
    lines.append(f"**Count:** {link_data.get('count', 0)}")
    lines.append("")
    if link_data.get("link_types"):
        lines.append("| Link Type | Inward | Outward |")
        lines.append("|-----------|--------|---------|")
        for lt in link_data.get("link_types", []):
            lines.append(f"| {lt['name']} | {lt.get('inward', '')} | {lt.get('outward', '')} |")
    lines.append("")
    
    # Security Levels
    sec_data = data.get("security_levels", {})
    lines.append("## 5. Issue Security Levels")
    lines.append("")
    if sec_data.get("configured"):
        lines.append(f"**Levels:** {sec_data.get('count', 0)}")
        lines.append("")
        for lvl in sec_data.get("levels", []):
            lines.append(f"- {lvl['name']}: {lvl.get('description', '')}")
    else:
        lines.append("*No issue security levels configured.*")
    lines.append("")
    
    # Workflow Transitions
    wf_data = data.get("workflow_transitions", {})
    lines.append("## 6. Workflow Analysis (per Issue Type)")
    lines.append("")
    lines.append("| Issue Type | Statuses | Triage | Escalate | Waiting | Cancelled | Reopened | Blocked | Referred | Investigating |")
    lines.append("|-----------|----------|--------|----------|---------|-----------|----------|---------|----------|---------------|")
    for type_name, info in wf_data.items():
        lines.append(f"| {type_name} | {info['status_count']} | {'✅' if info['has_triage'] else '❌'} | {'✅' if info['has_escalation'] else '❌'} | {'✅' if info['has_waiting'] else '❌'} | {'✅' if info['has_cancelled'] else '❌'} | {'✅' if info['has_reopened'] else '❌'} | {'✅' if info['has_blocked'] else '❌'} | {'✅' if info['has_referred'] else '❌'} | {'✅' if info['has_investigating'] else '❌'} |")
    lines.append("")
    
    # Request Type Fields (Portal)
    rt_data = data.get("request_type_fields", {})
    lines.append("## 7. Request Type Portal Fields (Customer View)")
    lines.append("")
    if isinstance(rt_data, dict) and not rt_data.get("error"):
        for rt_name, rt_info in rt_data.items():
            lines.append(f"### {rt_name}")
            lines.append(f"*Fields: {rt_info.get('field_count', 0)} | Required: {', '.join(rt_info.get('required_fields', []))}*")
            lines.append("")
            if rt_info.get("fields"):
                lines.append("| Field | Required | Description |")
                lines.append("|-------|----------|-------------|")
                for f in rt_info.get("fields", []):
                    lines.append(f"| {f['name']} | {'Yes' if f.get('required') else '' } | {f.get('description', '')[:50]} |")
            lines.append("")
    else:
        lines.append(f"*{rt_data.get('error', 'Not accessible')}*")
        lines.append("")
    
    # Labels
    label_data = data.get("labels", {})
    lines.append("## 8. Labels in Use")
    lines.append("")
    lines.append(f"**Count:** {label_data.get('count', 0)}")
    lines.append("")
    if label_data.get("labels"):
        # Group into columns for readability
        labels = label_data["labels"]
        lines.append("```")
        for i in range(0, len(labels), 4):
            chunk = labels[i:i+4]
            lines.append("  ".join(f"{l:<30}" for l in chunk))
        lines.append("```")
    lines.append("")
    
    # Filters
    filter_data = data.get("filters", {})
    lines.append("## 9. Saved Filters")
    lines.append("")
    lines.append(f"**Count:** {filter_data.get('count', 0)}")
    if filter_data.get("note"):
        lines.append(f"*{filter_data['note']}*")
    lines.append("")
    if filter_data.get("filters"):
        lines.append("| Filter | Owner | JQL |")
        lines.append("|--------|-------|-----|")
        for f in filter_data.get("filters", []):
            lines.append(f"| {f['name']} | {f.get('owner', '')} | `{f.get('jql', '')[:60]}` |")
    lines.append("")
    
    # Dashboards
    dash_data = data.get("dashboards", {})
    lines.append("## 10. Dashboards")
    lines.append("")
    lines.append(f"**Count:** {dash_data.get('count', 0)}")
    lines.append("")
    if dash_data.get("dashboards"):
        lines.append("| Dashboard | Owner |")
        lines.append("|-----------|-------|")
        for d in dash_data.get("dashboards", []):
            lines.append(f"| {d['name']} | {d.get('owner', '')} |")
    lines.append("")
    
    return "\n".join(lines)



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not JIRA_INSTANCE_URL or not JIRA_USER_EMAIL or not JIRA_API_TOKEN:
        logger.error("Missing JIRA_INSTANCE_URL, JIRA_USER_EMAIL, or JIRA_API_TOKEN")
        sys.exit(1)
    
    session = create_session()
    
    # Verify connectivity
    me = api_get(session, "/rest/api/2/myself")
    if not me:
        logger.error("Cannot connect to Jira")
        sys.exit(1)
    logger.info(f"Connected as: {me.get('displayName')}")
    
    logger.info("=" * 60)
    logger.info("JIRA DEEP AUDIT — PHASE 2")
    logger.info("=" * 60)
    
    data = {
        "meta": {
            "instance_url": JIRA_INSTANCE_URL,
            "project_key": JIRA_PROJECT_KEY,
            "date": datetime.now().isoformat(),
            "auditor": me.get("displayName"),
        },
        "issue_counts": audit_issue_counts_v3(session),
        "classification_fields": audit_classification_fields(session),
        "resolutions": audit_resolutions(session),
        "link_types": audit_issue_link_types(session),
        "security_levels": audit_issue_security_levels(session),
        "workflow_transitions": audit_workflow_transitions(session),
        "request_type_fields": audit_request_type_fields(session),
        "labels": audit_labels_in_use(session),
        "filters": audit_filters(session),
        "dashboards": audit_dashboards(session),
    }
    
    # Save JSON
    json_path = "reports/deep_audit_report.json"
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info(f"JSON saved: {json_path}")
    
    # Generate and save Markdown
    md = generate_deep_report(data)
    md_path = "reports/deep_audit_report.md"
    with open(md_path, "w") as f:
        f.write(md)
    logger.info(f"Markdown saved: {md_path}")
    
    print("\n" + "=" * 60)
    print("DEEP AUDIT COMPLETE")
    print("=" * 60)
    print(f"Total issues: {data['issue_counts'].get('total', 'N/A')}")
    print(f"Classification fields enumerated: {len(data['classification_fields'])}")
    print(f"JSON: {json_path}")
    print(f"Report: {md_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
