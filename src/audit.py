"""
Jira Project Functional Configuration Audit
=============================================
Connects to Jira Cloud and inspects the INFSOC project's structural setup:
issue types, fields, workflows, SLAs, request types, queues, priorities,
components, automation rules, and permissions.

Outputs:
  - reports/audit_report.json  (structured data)
  - reports/audit_report.md    (human-readable summary + recommendations)

Usage:
  Set environment variables (see .env.example) then run:
    python src/audit.py
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
# Logging
# ---------------------------------------------------------------------------
os.makedirs("reports", exist_ok=True)
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"logs/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)



# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
JIRA_INSTANCE_URL = os.getenv("JIRA_INSTANCE_URL", "").rstrip("/")
JIRA_USER_EMAIL = os.getenv("JIRA_USER_EMAIL", "")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "INFSOC")


def validate_config():
    """Ensure required env vars are set."""
    missing = []
    if not JIRA_INSTANCE_URL:
        missing.append("JIRA_INSTANCE_URL")
    if not JIRA_USER_EMAIL:
        missing.append("JIRA_USER_EMAIL")
    if not JIRA_API_TOKEN:
        missing.append("JIRA_API_TOKEN")
    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# HTTP Session
# ---------------------------------------------------------------------------
def create_session() -> requests.Session:
    """Create authenticated session for Jira Cloud."""
    session = requests.Session()
    credentials = b64encode(f"{JIRA_USER_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    session.headers.update({
        "Authorization": f"Basic {credentials}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    return session



def api_get(session: requests.Session, path: str, params: Optional[Dict] = None) -> Any:
    """GET from Jira REST API with rate-limit handling. Returns parsed JSON or None."""
    url = f"{JIRA_INSTANCE_URL}{path}"
    try:
        resp = session.get(url, params=params, timeout=30)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "5"))
            logger.warning(f"Rate limited on {path}, sleeping {retry_after}s")
            time.sleep(retry_after)
            resp = session.get(url, params=params, timeout=30)
        if resp.status_code == 404:
            logger.warning(f"404 Not Found: {path}")
            return None
        if resp.status_code == 403:
            logger.warning(f"403 Forbidden: {path} (insufficient permissions)")
            return None
        if resp.status_code >= 400:
            logger.warning(f"HTTP {resp.status_code} on {path}: {resp.text[:200]}")
            return None
        return resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {path}: {e}")
        return None


# ---------------------------------------------------------------------------
# Audit Collectors
# ---------------------------------------------------------------------------

def audit_project_info(session: requests.Session) -> Dict:
    """Get basic project metadata."""
    logger.info("Fetching project info...")
    data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}")
    if not data:
        return {"error": "Could not fetch project info"}
    return {
        "key": data.get("key"),
        "name": data.get("name"),
        "project_type": data.get("projectTypeKey"),
        "style": data.get("style"),
        "lead": data.get("lead", {}).get("displayName"),
        "description": data.get("description", ""),
        "url": data.get("self"),
    }



def audit_issue_types(session: requests.Session) -> Dict:
    """Get issue types available in the project and their statuses."""
    logger.info("Fetching issue types and statuses...")
    # Project-level statuses per issue type
    statuses_data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/statuses")
    
    # All issue types in the instance
    all_types = api_get(session, "/rest/api/2/issuetype") or []
    
    project_types = []
    if statuses_data:
        for item in statuses_data:
            type_info = {
                "name": item.get("name"),
                "id": item.get("id"),
                "subtask": item.get("subtask", False),
                "statuses": [s.get("name") for s in item.get("statuses", [])],
                "status_count": len(item.get("statuses", [])),
            }
            project_types.append(type_info)
    
    return {
        "project_issue_types": project_types,
        "total_instance_types": len(all_types),
        "instance_types": [{"name": t.get("name"), "id": t.get("id"), "subtask": t.get("subtask", False)} for t in all_types],
    }


def audit_fields(session: requests.Session) -> Dict:
    """Get all fields — identify custom fields and their usage."""
    logger.info("Fetching fields...")
    fields = api_get(session, "/rest/api/2/field") or []
    
    custom_fields = []
    system_fields = []
    
    for f in fields:
        entry = {
            "id": f.get("id"),
            "name": f.get("name"),
            "custom": f.get("custom", False),
            "schema_type": f.get("schema", {}).get("type", "unknown"),
            "searchable": f.get("searchable", False),
        }
        if f.get("custom"):
            custom_fields.append(entry)
        else:
            system_fields.append(entry)
    
    return {
        "total_fields": len(fields),
        "system_field_count": len(system_fields),
        "custom_field_count": len(custom_fields),
        "custom_fields": custom_fields,
        "system_fields": system_fields,
    }



def audit_workflows(session: requests.Session) -> Dict:
    """Get workflow information for the project."""
    logger.info("Fetching workflows...")
    
    # Try to get project workflows via the scheme
    # REST API v2: GET /rest/api/2/workflow — lists all workflows (admin only)
    workflows = api_get(session, "/rest/api/2/workflow") or []
    
    # Also get all statuses
    all_statuses = api_get(session, "/rest/api/2/status") or []
    status_categories = api_get(session, "/rest/api/2/statuscategory") or []
    
    workflow_list = []
    for wf in workflows:
        workflow_list.append({
            "name": wf.get("name"),
            "description": wf.get("description", ""),
            "is_default": wf.get("isDefault", False),
            "steps": wf.get("steps", 0) if isinstance(wf.get("steps"), int) else len(wf.get("steps", [])),
        })
    
    status_list = []
    for s in all_statuses:
        status_list.append({
            "name": s.get("name"),
            "id": s.get("id"),
            "category": s.get("statusCategory", {}).get("name", "Unknown"),
        })
    
    return {
        "workflows": workflow_list,
        "workflow_count": len(workflow_list),
        "statuses": status_list,
        "status_count": len(status_list),
        "status_categories": [c.get("name") for c in status_categories],
    }


def audit_priorities(session: requests.Session) -> Dict:
    """Get priority scheme."""
    logger.info("Fetching priorities...")
    priorities = api_get(session, "/rest/api/2/priority") or []
    
    return {
        "priorities": [{"name": p.get("name"), "id": p.get("id"), "description": p.get("description", "")} for p in priorities],
        "count": len(priorities),
    }



def audit_components(session: requests.Session) -> Dict:
    """Get project components."""
    logger.info("Fetching components...")
    components = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/components") or []
    
    return {
        "components": [{
            "name": c.get("name"),
            "id": c.get("id"),
            "lead": c.get("lead", {}).get("displayName") if c.get("lead") else None,
            "description": c.get("description", ""),
            "assignee_type": c.get("assigneeType", ""),
        } for c in components],
        "count": len(components),
    }


def audit_versions(session: requests.Session) -> Dict:
    """Get project versions/releases."""
    logger.info("Fetching versions...")
    versions = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/versions") or []
    
    return {
        "versions": [{
            "name": v.get("name"),
            "id": v.get("id"),
            "released": v.get("released", False),
            "archived": v.get("archived", False),
            "release_date": v.get("releaseDate"),
        } for v in versions],
        "count": len(versions),
    }


def audit_roles(session: requests.Session) -> Dict:
    """Get project roles and their members."""
    logger.info("Fetching roles...")
    roles = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/role") or {}
    
    role_details = []
    for role_name, role_url in roles.items():
        # Fetch role detail to get members
        role_id = role_url.split("/")[-1] if isinstance(role_url, str) else ""
        detail = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/role/{role_id}")
        if detail:
            actors = detail.get("actors", [])
            role_details.append({
                "name": detail.get("name"),
                "id": detail.get("id"),
                "description": detail.get("description", ""),
                "actor_count": len(actors),
                "actors": [{"name": a.get("displayName"), "type": a.get("type")} for a in actors],
            })
        time.sleep(0.2)  # Be gentle with rate limits
    
    return {
        "roles": role_details,
        "count": len(role_details),
    }



def audit_service_desk(session: requests.Session) -> Dict:
    """Get JSM-specific config: request types, queues, SLAs."""
    logger.info("Fetching Service Desk configuration...")
    
    result = {
        "service_desk_id": None,
        "request_types": [],
        "queues": [],
        "sla_metrics": [],
    }
    
    # Find the service desk ID for our project
    service_desks = api_get(session, "/rest/servicedeskapi/servicedesk")
    if not service_desks:
        logger.warning("Could not access Service Desk API — may not be JSM or insufficient permissions")
        result["error"] = "Service Desk API not accessible"
        return result
    
    sd_values = service_desks.get("values", [])
    sd_id = None
    for sd in sd_values:
        if sd.get("projectKey") == JIRA_PROJECT_KEY:
            sd_id = sd.get("id")
            break
    
    if not sd_id:
        result["error"] = f"No service desk found for project {JIRA_PROJECT_KEY}"
        return result
    
    result["service_desk_id"] = sd_id
    
    # Request Types
    logger.info("  Fetching request types...")
    rt_data = api_get(session, f"/rest/servicedeskapi/servicedesk/{sd_id}/requesttype")
    if rt_data:
        for rt in rt_data.get("values", []):
            result["request_types"].append({
                "name": rt.get("name"),
                "id": rt.get("id"),
                "description": rt.get("description", ""),
                "help_text": rt.get("helpText", ""),
                "issue_type_id": rt.get("issueTypeId"),
                "group_ids": rt.get("groupIds", []),
            })
    
    # Queues
    logger.info("  Fetching queues...")
    queue_data = api_get(session, f"/rest/servicedeskapi/servicedesk/{sd_id}/queue")
    if queue_data:
        for q in queue_data.get("values", []):
            result["queues"].append({
                "name": q.get("name"),
                "id": q.get("id"),
                "jql": q.get("jql", ""),
                "issue_count": q.get("issueCount"),
            })
    
    # SLA Metrics — may need specific permissions
    logger.info("  Fetching SLA metrics...")
    # Note: SLA details are per-issue in JSM, but we can check if SLAs are configured
    # Try a sample issue to see SLA fields
    sample_jql = f"project = {JIRA_PROJECT_KEY} ORDER BY created DESC"
    sample = api_get(session, "/rest/api/2/search", params={"jql": sample_jql, "maxResults": 1, "fields": "status"})
    if sample and sample.get("issues"):
        issue_key = sample["issues"][0]["key"]
        sla_data = api_get(session, f"/rest/servicedeskapi/request/{issue_key}/sla")
        if sla_data:
            for sla in sla_data.get("values", []):
                result["sla_metrics"].append({
                    "name": sla.get("name"),
                    "id": sla.get("id"),
                    "ongoing_cycle": sla.get("ongoingCycle"),
                    "completed_cycles": len(sla.get("completedCycles", [])),
                })
    
    return result



def audit_automation(session: requests.Session) -> Dict:
    """Check for automation rules (limited API access in Cloud)."""
    logger.info("Checking automation rules...")
    # Jira Cloud automation API is limited — try the project automation endpoint
    data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/properties")
    
    # Alternative: check via the newer automation API
    auto_data = api_get(session, "/gateway/api/automation/internal-api/jira/default/rest/v1/rule")
    
    result = {"accessible": False, "rules": [], "note": ""}
    
    if auto_data and isinstance(auto_data, dict):
        result["accessible"] = True
        rules = auto_data.get("results", auto_data.get("values", []))
        for rule in rules:
            if isinstance(rule, dict):
                result["rules"].append({
                    "name": rule.get("name"),
                    "state": rule.get("state", rule.get("ruleState", "unknown")),
                    "id": rule.get("id"),
                })
    else:
        result["note"] = "Automation API not accessible — rules must be checked manually in Jira UI"
    
    return result


def audit_notification_scheme(session: requests.Session) -> Dict:
    """Get notification scheme for the project."""
    logger.info("Fetching notification scheme...")
    # This requires admin permissions
    data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/notificationscheme")
    if not data:
        return {"accessible": False, "note": "Notification scheme not accessible (requires admin)"}
    
    events = []
    for event in data.get("notificationSchemeEvents", []):
        events.append({
            "event_name": event.get("event", {}).get("name"),
            "notification_count": len(event.get("notifications", [])),
        })
    
    return {
        "accessible": True,
        "name": data.get("name"),
        "id": data.get("id"),
        "events": events,
        "event_count": len(events),
    }



def audit_permission_scheme(session: requests.Session) -> Dict:
    """Get permission scheme summary."""
    logger.info("Fetching permission scheme...")
    data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/permissionscheme")
    if not data:
        return {"accessible": False, "note": "Permission scheme not accessible (requires admin)"}
    
    permissions = []
    for perm in data.get("permissions", []):
        permissions.append({
            "permission": perm.get("permission"),
            "holder_type": perm.get("holder", {}).get("type"),
            "holder_value": perm.get("holder", {}).get("parameter"),
        })
    
    return {
        "accessible": True,
        "name": data.get("name"),
        "id": data.get("id"),
        "permission_count": len(permissions),
        "permissions_summary": permissions[:20],  # First 20 for readability
    }


def audit_issue_type_screen_schemes(session: requests.Session) -> Dict:
    """Check what screens/fields are configured per operation."""
    logger.info("Fetching screen schemes...")
    
    # Get create metadata — shows what fields are available on create screen per issue type
    create_meta = api_get(session, "/rest/api/2/issue/createmeta", params={
        "projectKeys": JIRA_PROJECT_KEY,
        "expand": "projects.issuetypes.fields",
    })
    
    result = {"issue_type_fields": [], "note": ""}
    
    if not create_meta:
        # Try the newer createmeta endpoint (Jira Cloud deprecated the old one)
        result["note"] = "Create metadata not accessible via legacy endpoint, trying per-type"
        # Try per issue type
        types_data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/statuses") or []
        for it in types_data:
            type_id = it.get("id")
            type_name = it.get("name")
            meta = api_get(session, f"/rest/api/2/issue/createmeta/{JIRA_PROJECT_KEY}/issuetypes/{type_id}", params={"expand": "fields"})
            if meta:
                fields_on_create = []
                for field_id, field_info in meta.get("fields", meta.get("values", {})).items() if isinstance(meta.get("fields", meta.get("values", {})), dict) else []:
                    fields_on_create.append({
                        "id": field_id,
                        "name": field_info.get("name"),
                        "required": field_info.get("required", False),
                    })
                result["issue_type_fields"].append({
                    "issue_type": type_name,
                    "fields_on_create": fields_on_create,
                    "field_count": len(fields_on_create),
                })
            time.sleep(0.3)
        return result
    
    projects = create_meta.get("projects", [])
    for proj in projects:
        if proj.get("key") == JIRA_PROJECT_KEY:
            for it in proj.get("issuetypes", []):
                fields_on_create = []
                for field_id, field_info in it.get("fields", {}).items():
                    fields_on_create.append({
                        "id": field_id,
                        "name": field_info.get("name"),
                        "required": field_info.get("required", False),
                        "has_default": field_info.get("hasDefaultValue", False),
                        "allowed_values_count": len(field_info.get("allowedValues", [])),
                    })
                result["issue_type_fields"].append({
                    "issue_type": it.get("name"),
                    "fields_on_create": fields_on_create,
                    "field_count": len(fields_on_create),
                    "required_fields": [f for f in fields_on_create if f.get("required")],
                })
    
    return result



def audit_issue_count_summary(session: requests.Session) -> Dict:
    """Quick count of issues by type and status for context."""
    logger.info("Fetching issue count summary...")
    
    result = {"by_type": {}, "by_status": {}, "total": 0}
    
    # Total count
    total = api_get(session, "/rest/api/2/search", params={
        "jql": f"project = {JIRA_PROJECT_KEY}",
        "maxResults": 0,
    })
    if total:
        result["total"] = total.get("total", 0)
    
    # By issue type
    types_data = api_get(session, f"/rest/api/2/project/{JIRA_PROJECT_KEY}/statuses") or []
    for it in types_data:
        type_name = it.get("name")
        count_data = api_get(session, "/rest/api/2/search", params={
            "jql": f'project = {JIRA_PROJECT_KEY} AND issuetype = "{type_name}"',
            "maxResults": 0,
        })
        if count_data:
            result["by_type"][type_name] = count_data.get("total", 0)
        time.sleep(0.3)
    
    # By status category
    for cat in ["To Do", "In Progress", "Done"]:
        count_data = api_get(session, "/rest/api/2/search", params={
            "jql": f"project = {JIRA_PROJECT_KEY} AND statusCategory = \"{cat}\"",
            "maxResults": 0,
        })
        if count_data:
            result["by_status"][cat] = count_data.get("total", 0)
        time.sleep(0.3)
    
    return result


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_audit() -> Dict:
    """Run the full functional audit and return structured results."""
    validate_config()
    session = create_session()
    
    logger.info(f"=" * 60)
    logger.info(f"JIRA FUNCTIONAL CONFIGURATION AUDIT")
    logger.info(f"Instance: {JIRA_INSTANCE_URL}")
    logger.info(f"Project:  {JIRA_PROJECT_KEY}")
    logger.info(f"Date:     {datetime.now().isoformat()}")
    logger.info(f"=" * 60)
    
    # Test connectivity
    logger.info("Testing connectivity...")
    test = api_get(session, "/rest/api/2/myself")
    if not test:
        logger.error("Cannot connect to Jira — check credentials")
        sys.exit(1)
    logger.info(f"Connected as: {test.get('displayName')} ({test.get('emailAddress')})")
    
    # Run all audit collectors
    audit_data = {
        "meta": {
            "instance_url": JIRA_INSTANCE_URL,
            "project_key": JIRA_PROJECT_KEY,
            "audit_date": datetime.now().isoformat(),
            "auditor": test.get("displayName"),
        },
        "project": audit_project_info(session),
        "issue_types": audit_issue_types(session),
        "fields": audit_fields(session),
        "workflows": audit_workflows(session),
        "priorities": audit_priorities(session),
        "components": audit_components(session),
        "versions": audit_versions(session),
        "roles": audit_roles(session),
        "service_desk": audit_service_desk(session),
        "screens": audit_issue_type_screen_schemes(session),
        "automation": audit_automation(session),
        "notifications": audit_notification_scheme(session),
        "permissions": audit_permission_scheme(session),
        "issue_counts": audit_issue_count_summary(session),
    }
    
    return audit_data



# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_markdown_report(audit_data: Dict) -> str:
    """Generate human-readable Markdown report from audit data."""
    lines = []
    lines.append("# Jira Project Functional Audit Report")
    lines.append("")
    lines.append(f"**Instance:** {audit_data['meta']['instance_url']}")
    lines.append(f"**Project:** {audit_data['meta']['project_key']}")
    lines.append(f"**Date:** {audit_data['meta']['audit_date']}")
    lines.append(f"**Auditor:** {audit_data['meta']['auditor']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Project Info
    proj = audit_data.get("project", {})
    lines.append("## 1. Project Overview")
    lines.append("")
    lines.append(f"| Property | Value |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Name | {proj.get('name', 'N/A')} |")
    lines.append(f"| Key | {proj.get('key', 'N/A')} |")
    lines.append(f"| Type | {proj.get('project_type', 'N/A')} |")
    lines.append(f"| Style | {proj.get('style', 'N/A')} |")
    lines.append(f"| Lead | {proj.get('lead', 'N/A')} |")
    lines.append(f"| Description | {proj.get('description', 'None set')} |")
    lines.append("")
    
    # Issue Types
    it_data = audit_data.get("issue_types", {})
    lines.append("## 2. Issue Types")
    lines.append("")
    lines.append(f"**Project issue types:** {len(it_data.get('project_issue_types', []))}")
    lines.append(f"**Instance-wide types:** {it_data.get('total_instance_types', 0)}")
    lines.append("")
    lines.append("| Issue Type | Subtask | Statuses | Status Names |")
    lines.append("|-----------|---------|----------|--------------|")
    for it in it_data.get("project_issue_types", []):
        statuses_str = ", ".join(it.get("statuses", [])[:8])
        if len(it.get("statuses", [])) > 8:
            statuses_str += "..."
        lines.append(f"| {it['name']} | {it.get('subtask', False)} | {it.get('status_count', 0)} | {statuses_str} |")
    lines.append("")
    
    # Fields
    fields_data = audit_data.get("fields", {})
    lines.append("## 3. Fields")
    lines.append("")
    lines.append(f"**Total fields:** {fields_data.get('total_fields', 0)}")
    lines.append(f"**System fields:** {fields_data.get('system_field_count', 0)}")
    lines.append(f"**Custom fields:** {fields_data.get('custom_field_count', 0)}")
    lines.append("")
    if fields_data.get("custom_fields"):
        lines.append("### Custom Fields")
        lines.append("")
        lines.append("| Field Name | Field ID | Type |")
        lines.append("|-----------|----------|------|")
        for cf in fields_data.get("custom_fields", []):
            lines.append(f"| {cf['name']} | {cf['id']} | {cf.get('schema_type', 'unknown')} |")
        lines.append("")
    
    # Workflows
    wf_data = audit_data.get("workflows", {})
    lines.append("## 4. Workflows & Statuses")
    lines.append("")
    lines.append(f"**Workflow count:** {wf_data.get('workflow_count', 0)}")
    lines.append(f"**Status count:** {wf_data.get('status_count', 0)}")
    lines.append("")
    if wf_data.get("workflows"):
        lines.append("### Workflows")
        lines.append("")
        lines.append("| Workflow | Default | Steps |")
        lines.append("|---------|---------|-------|")
        for wf in wf_data.get("workflows", []):
            lines.append(f"| {wf['name']} | {wf.get('is_default', False)} | {wf.get('steps', 'N/A')} |")
        lines.append("")
    if wf_data.get("statuses"):
        lines.append("### All Statuses")
        lines.append("")
        lines.append("| Status | Category |")
        lines.append("|--------|----------|")
        for s in wf_data.get("statuses", []):
            lines.append(f"| {s['name']} | {s.get('category', 'Unknown')} |")
        lines.append("")
    
    return "\n".join(lines)



def generate_markdown_report_part2(audit_data: Dict) -> str:
    """Second part of the markdown report."""
    lines = []
    
    # Priorities
    pri_data = audit_data.get("priorities", {})
    lines.append("## 5. Priorities")
    lines.append("")
    lines.append(f"**Priority levels:** {pri_data.get('count', 0)}")
    lines.append("")
    lines.append("| Priority | Description |")
    lines.append("|----------|-------------|")
    for p in pri_data.get("priorities", []):
        lines.append(f"| {p['name']} | {p.get('description', '')[:60]} |")
    lines.append("")
    
    # Components
    comp_data = audit_data.get("components", {})
    lines.append("## 6. Components")
    lines.append("")
    lines.append(f"**Component count:** {comp_data.get('count', 0)}")
    lines.append("")
    if comp_data.get("components"):
        lines.append("| Component | Lead | Description |")
        lines.append("|-----------|------|-------------|")
        for c in comp_data.get("components", []):
            lines.append(f"| {c['name']} | {c.get('lead', 'None')} | {c.get('description', '')[:40]} |")
    else:
        lines.append("*No components configured.*")
    lines.append("")
    
    # Service Desk
    sd_data = audit_data.get("service_desk", {})
    lines.append("## 7. Service Desk (JSM)")
    lines.append("")
    if sd_data.get("error"):
        lines.append(f"*{sd_data['error']}*")
    else:
        lines.append(f"**Service Desk ID:** {sd_data.get('service_desk_id')}")
        lines.append("")
        
        # Request Types
        lines.append("### Request Types")
        lines.append("")
        if sd_data.get("request_types"):
            lines.append("| Request Type | Description | Issue Type ID |")
            lines.append("|-------------|-------------|---------------|")
            for rt in sd_data.get("request_types", []):
                lines.append(f"| {rt['name']} | {rt.get('description', '')[:50]} | {rt.get('issue_type_id', 'N/A')} |")
        else:
            lines.append("*No request types found.*")
        lines.append("")
        
        # Queues
        lines.append("### Queues")
        lines.append("")
        if sd_data.get("queues"):
            lines.append("| Queue | JQL | Issues |")
            lines.append("|-------|-----|--------|")
            for q in sd_data.get("queues", []):
                lines.append(f"| {q['name']} | `{q.get('jql', '')[:60]}` | {q.get('issue_count', 'N/A')} |")
        else:
            lines.append("*No queues found.*")
        lines.append("")
        
        # SLAs
        lines.append("### SLA Metrics")
        lines.append("")
        if sd_data.get("sla_metrics"):
            lines.append("| SLA | Completed Cycles |")
            lines.append("|-----|-----------------|")
            for sla in sd_data.get("sla_metrics", []):
                lines.append(f"| {sla['name']} | {sla.get('completed_cycles', 0)} |")
        else:
            lines.append("*No SLA metrics found or not configured.*")
        lines.append("")
    
    # Roles
    roles_data = audit_data.get("roles", {})
    lines.append("## 8. Project Roles")
    lines.append("")
    lines.append(f"**Roles configured:** {roles_data.get('count', 0)}")
    lines.append("")
    if roles_data.get("roles"):
        lines.append("| Role | Members | Actors |")
        lines.append("|------|---------|--------|")
        for r in roles_data.get("roles", []):
            actor_names = ", ".join([a["name"] for a in r.get("actors", [])[:5]])
            lines.append(f"| {r['name']} | {r.get('actor_count', 0)} | {actor_names} |")
    lines.append("")
    
    # Automation
    auto_data = audit_data.get("automation", {})
    lines.append("## 9. Automation Rules")
    lines.append("")
    if not auto_data.get("accessible"):
        lines.append(f"*{auto_data.get('note', 'Not accessible')}*")
    else:
        lines.append(f"**Rules found:** {len(auto_data.get('rules', []))}")
        lines.append("")
        if auto_data.get("rules"):
            lines.append("| Rule | State |")
            lines.append("|------|-------|")
            for rule in auto_data.get("rules", []):
                lines.append(f"| {rule['name']} | {rule.get('state', 'unknown')} |")
    lines.append("")
    
    # Screens
    screen_data = audit_data.get("screens", {})
    lines.append("## 10. Create Screen Fields (per Issue Type)")
    lines.append("")
    if screen_data.get("note"):
        lines.append(f"*Note: {screen_data['note']}*")
        lines.append("")
    if screen_data.get("issue_type_fields"):
        for itf in screen_data.get("issue_type_fields", []):
            lines.append(f"### {itf['issue_type']} ({itf.get('field_count', 0)} fields)")
            lines.append("")
            required = [f for f in itf.get("fields_on_create", []) if f.get("required")]
            if required:
                lines.append(f"**Required fields:** {', '.join([f['name'] for f in required])}")
            lines.append("")
    else:
        lines.append("*Screen metadata not accessible via API.*")
    lines.append("")
    
    # Issue Counts
    counts = audit_data.get("issue_counts", {})
    lines.append("## 11. Issue Count Summary")
    lines.append("")
    lines.append(f"**Total issues:** {counts.get('total', 0)}")
    lines.append("")
    if counts.get("by_type"):
        lines.append("| Issue Type | Count |")
        lines.append("|-----------|-------|")
        for t, c in counts.get("by_type", {}).items():
            lines.append(f"| {t} | {c} |")
        lines.append("")
    if counts.get("by_status"):
        lines.append("| Status Category | Count |")
        lines.append("|----------------|-------|")
        for s, c in counts.get("by_status", {}).items():
            lines.append(f"| {s} | {c} |")
        lines.append("")
    
    return "\n".join(lines)



# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    """Run audit, generate reports, save to files."""
    audit_data = run_audit()
    
    # Save raw JSON
    json_path = "reports/audit_report.json"
    with open(json_path, "w") as f:
        json.dump(audit_data, f, indent=2, default=str)
    logger.info(f"Raw audit data saved to {json_path}")
    
    # Generate and save Markdown report
    md_content = generate_markdown_report(audit_data)
    md_content += "\n" + generate_markdown_report_part2(audit_data)
    
    # Add recommendations (from recommendations engine)
    try:
        from recommendations import generate_recommendations
        md_content += "\n" + generate_recommendations(audit_data)
    except ImportError:
        logger.warning("Recommendations module not found — skipping")
    
    md_path = "reports/audit_report.md"
    with open(md_path, "w") as f:
        f.write(md_content)
    logger.info(f"Markdown report saved to {md_path}")
    
    # Print summary to stdout
    print("\n" + "=" * 60)
    print("AUDIT COMPLETE")
    print("=" * 60)
    print(f"JSON: {json_path}")
    print(f"Report: {md_path}")
    print(f"Total issues in project: {audit_data.get('issue_counts', {}).get('total', 'unknown')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
