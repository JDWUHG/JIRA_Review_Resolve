"""
Recommendations Engine
======================
Compares audit data against a baseline for a security operations
Jira Service Management project and generates actionable recommendations.
"""

from typing import Dict, List


# ---------------------------------------------------------------------------
# Baseline: What a well-configured Security Ops JSM project should have
# ---------------------------------------------------------------------------

EXPECTED_ISSUE_TYPES = [
    "Vulnerability",
    "Indicator",
    "Incident",
    "Problem",
    "Change",
    "Task",
    "Sub-task",
]

EXPECTED_COMPONENTS = [
    "Network",
    "Endpoint",
    "Cloud",
    "Identity",
    "Application",
    "Data",
]

EXPECTED_PRIORITIES = ["Highest", "High", "Medium", "Low", "Lowest"]

EXPECTED_STATUS_CATEGORIES = ["To Do", "In Progress", "Done"]



# Minimum expected workflow statuses for security tickets
EXPECTED_WORKFLOW_STATUSES = [
    "Open",           # or "New" / "To Do"
    "Triaged",        # Initial triage complete
    "In Progress",    # Being worked on
    "Awaiting Info",  # Blocked on external info
    "Mitigated",      # Temporary fix applied
    "Resolved",       # Permanently resolved
    "Closed",         # Done
    "Cancelled",      # Won't do
]

EXPECTED_CUSTOM_FIELDS_SECURITY = [
    "CVE-Key",
    "Indicator-Key",
    "CVSS Score",
    "Attack Vector",
    "Affected Assets",
    "Source Feed",
    "First Seen",
    "Last Seen",
    "Confidence",
    "TLP",
]

EXPECTED_SLA_METRICS = [
    "Time to first response",
    "Time to resolution",
]

EXPECTED_REQUEST_TYPES = [
    "Vulnerability",
    "Indicator",
    "Security Incident",
    "Access Request",
    "Exception Request",
]


# ---------------------------------------------------------------------------
# Analysis Functions
# ---------------------------------------------------------------------------

def check_issue_types(audit_data: Dict) -> List[Dict]:
    """Check issue type configuration."""
    findings = []
    it_data = audit_data.get("issue_types", {})
    project_types = [t["name"] for t in it_data.get("project_issue_types", [])]
    
    if not project_types:
        findings.append({
            "severity": "CRITICAL",
            "area": "Issue Types",
            "finding": "No issue types found in project",
            "recommendation": "Configure issue types: at minimum Vulnerability, Indicator, Incident, Task",
        })
        return findings
    
    # Check for expected types
    for expected in EXPECTED_ISSUE_TYPES:
        if expected not in project_types:
            sev = "HIGH" if expected in ["Vulnerability", "Indicator", "Incident"] else "MEDIUM"
            findings.append({
                "severity": sev,
                "area": "Issue Types",
                "finding": f"Missing issue type: {expected}",
                "recommendation": f"Add '{expected}' issue type to the project's issue type scheme",
            })
    
    # Check for unusual/unexpected types
    known_types = set(EXPECTED_ISSUE_TYPES + ["Epic", "Story", "Bug", "Service Request", "IT Help"])
    for t in project_types:
        if t not in known_types:
            findings.append({
                "severity": "LOW",
                "area": "Issue Types",
                "finding": f"Non-standard issue type present: {t}",
                "recommendation": f"Review whether '{t}' is needed — consider consolidating to standard types",
            })
    
    # Check workflow depth per type
    for it in it_data.get("project_issue_types", []):
        if it.get("status_count", 0) < 3:
            findings.append({
                "severity": "MEDIUM",
                "area": "Issue Types",
                "finding": f"Issue type '{it['name']}' has only {it['status_count']} statuses",
                "recommendation": f"A security ticket lifecycle needs at least: Open → In Progress → Resolved → Closed",
            })
        elif it.get("status_count", 0) > 12:
            findings.append({
                "severity": "LOW",
                "area": "Issue Types",
                "finding": f"Issue type '{it['name']}' has {it['status_count']} statuses — may be over-complicated",
                "recommendation": "Simplify workflow — too many statuses causes confusion and stale tickets",
            })
    
    return findings



def check_fields(audit_data: Dict) -> List[Dict]:
    """Check field configuration."""
    findings = []
    fields_data = audit_data.get("fields", {})
    custom_fields = fields_data.get("custom_fields", [])
    custom_names = [f["name"] for f in custom_fields]
    
    if fields_data.get("custom_field_count", 0) == 0:
        findings.append({
            "severity": "HIGH",
            "area": "Fields",
            "finding": "No custom fields configured",
            "recommendation": "Add custom fields for security context: CVE-Key, Indicator-Key, CVSS Score, Source Feed, Confidence, TLP",
        })
    else:
        # Check for expected security fields
        essential_fields = ["CVE-Key", "Indicator-Key"]
        for ef in essential_fields:
            # Fuzzy match (field names vary)
            found = any(ef.lower().replace("-", "").replace(" ", "") in n.lower().replace("-", "").replace(" ", "") for n in custom_names)
            if not found:
                findings.append({
                    "severity": "HIGH",
                    "area": "Fields",
                    "finding": f"Missing essential custom field: {ef}",
                    "recommendation": f"Add '{ef}' as a text custom field for deduplication",
                })
        
        # Check for nice-to-have fields
        nice_fields = ["CVSS Score", "Attack Vector", "Source Feed", "Confidence", "TLP", "First Seen", "Last Seen"]
        missing_nice = []
        for nf in nice_fields:
            found = any(nf.lower().replace(" ", "") in n.lower().replace(" ", "") for n in custom_names)
            if not found:
                missing_nice.append(nf)
        if missing_nice:
            findings.append({
                "severity": "MEDIUM",
                "area": "Fields",
                "finding": f"Missing recommended security fields: {', '.join(missing_nice)}",
                "recommendation": "Add these fields to provide richer security context on each ticket",
            })
    
    # Check for field bloat
    if fields_data.get("custom_field_count", 0) > 50:
        findings.append({
            "severity": "MEDIUM",
            "area": "Fields",
            "finding": f"High custom field count ({fields_data['custom_field_count']}) — potential field bloat",
            "recommendation": "Audit custom fields — remove unused ones. High field count slows down Jira and confuses users",
        })
    
    return findings


def check_workflows(audit_data: Dict) -> List[Dict]:
    """Check workflow configuration."""
    findings = []
    wf_data = audit_data.get("workflows", {})
    statuses = wf_data.get("statuses", [])
    status_names = [s["name"] for s in statuses]
    
    if not statuses:
        findings.append({
            "severity": "CRITICAL",
            "area": "Workflows",
            "finding": "No status information available",
            "recommendation": "Check workflow configuration — project may be using a default workflow",
        })
        return findings
    
    # Check for essential statuses
    essential_statuses = ["In Progress", "Done", "Closed"]
    for es in essential_statuses:
        found = any(es.lower() in s.lower() for s in status_names)
        if not found:
            findings.append({
                "severity": "HIGH",
                "area": "Workflows",
                "finding": f"Missing essential status: {es}",
                "recommendation": f"Add '{es}' status to the workflow",
            })
    
    # Check for triage/security-specific statuses
    security_statuses = ["Triaged", "Mitigated", "Awaiting"]
    missing_security = []
    for ss in security_statuses:
        found = any(ss.lower() in s.lower() for s in status_names)
        if not found:
            missing_security.append(ss)
    if missing_security:
        findings.append({
            "severity": "MEDIUM",
            "area": "Workflows",
            "finding": f"Missing security-specific statuses: {', '.join(missing_security)}",
            "recommendation": "Add triage/mitigation statuses for a proper security ticket lifecycle",
        })
    
    # Check status categories
    categories = set(s.get("category", "") for s in statuses)
    for expected_cat in EXPECTED_STATUS_CATEGORIES:
        if expected_cat not in categories:
            findings.append({
                "severity": "HIGH",
                "area": "Workflows",
                "finding": f"No statuses in category: {expected_cat}",
                "recommendation": f"Ensure at least one status maps to the '{expected_cat}' category",
            })
    
    return findings



def check_components(audit_data: Dict) -> List[Dict]:
    """Check component configuration."""
    findings = []
    comp_data = audit_data.get("components", {})
    
    if comp_data.get("count", 0) == 0:
        findings.append({
            "severity": "MEDIUM",
            "area": "Components",
            "finding": "No components configured",
            "recommendation": f"Add components to categorise tickets by domain: {', '.join(EXPECTED_COMPONENTS)}",
        })
    elif comp_data.get("count", 0) < 3:
        findings.append({
            "severity": "LOW",
            "area": "Components",
            "finding": f"Only {comp_data['count']} components configured",
            "recommendation": "Consider adding more components for better categorisation and routing",
        })
    
    # Check if components have leads
    components = comp_data.get("components", [])
    orphans = [c["name"] for c in components if not c.get("lead")]
    if orphans:
        findings.append({
            "severity": "LOW",
            "area": "Components",
            "finding": f"Components without a lead: {', '.join(orphans)}",
            "recommendation": "Assign a lead to each component for auto-assignment routing",
        })
    
    return findings


def check_service_desk(audit_data: Dict) -> List[Dict]:
    """Check JSM configuration."""
    findings = []
    sd_data = audit_data.get("service_desk", {})
    
    if sd_data.get("error"):
        findings.append({
            "severity": "HIGH",
            "area": "Service Desk",
            "finding": sd_data["error"],
            "recommendation": "Verify the project is a Service Management project and API permissions are correct",
        })
        return findings
    
    # Request Types
    rt_count = len(sd_data.get("request_types", []))
    if rt_count == 0:
        findings.append({
            "severity": "HIGH",
            "area": "Service Desk",
            "finding": "No request types configured",
            "recommendation": f"Add request types: {', '.join(EXPECTED_REQUEST_TYPES)}",
        })
    elif rt_count < 3:
        findings.append({
            "severity": "MEDIUM",
            "area": "Service Desk",
            "finding": f"Only {rt_count} request types configured",
            "recommendation": "Add more request types for different security intake scenarios",
        })
    
    # Queues
    queue_count = len(sd_data.get("queues", []))
    if queue_count == 0:
        findings.append({
            "severity": "HIGH",
            "area": "Service Desk",
            "finding": "No agent queues configured",
            "recommendation": "Set up queues for triage: Unassigned, My Open, Critical/High Priority, Awaiting Response",
        })
    
    # SLAs
    sla_count = len(sd_data.get("sla_metrics", []))
    if sla_count == 0:
        findings.append({
            "severity": "HIGH",
            "area": "Service Desk",
            "finding": "No SLA metrics found",
            "recommendation": "Configure SLAs: Time to First Response and Time to Resolution at minimum, with targets per priority",
        })
    
    return findings


def check_priorities(audit_data: Dict) -> List[Dict]:
    """Check priority configuration."""
    findings = []
    pri_data = audit_data.get("priorities", {})
    priorities = [p["name"] for p in pri_data.get("priorities", [])]
    
    if len(priorities) < 3:
        findings.append({
            "severity": "HIGH",
            "area": "Priorities",
            "finding": f"Only {len(priorities)} priority levels configured",
            "recommendation": "A security ops project needs at least: Highest, High, Medium, Low, Lowest",
        })
    
    # Check for expected priorities
    for ep in EXPECTED_PRIORITIES:
        if ep not in priorities:
            findings.append({
                "severity": "LOW",
                "area": "Priorities",
                "finding": f"Missing priority level: {ep}",
                "recommendation": f"Add '{ep}' priority for proper severity mapping from CVSS/threat feeds",
            })
    
    return findings



def check_roles(audit_data: Dict) -> List[Dict]:
    """Check role/permission setup."""
    findings = []
    roles_data = audit_data.get("roles", {})
    
    if roles_data.get("count", 0) == 0:
        findings.append({
            "severity": "MEDIUM",
            "area": "Roles",
            "finding": "No project roles found",
            "recommendation": "Configure roles: Administrator, Service Desk Team, Service Desk Customers",
        })
    else:
        # Check if roles have members
        empty_roles = [r["name"] for r in roles_data.get("roles", []) if r.get("actor_count", 0) == 0]
        if empty_roles:
            findings.append({
                "severity": "MEDIUM",
                "area": "Roles",
                "finding": f"Roles with no members: {', '.join(empty_roles)}",
                "recommendation": "Assign users/groups to these roles for proper access control",
            })
    
    return findings


def check_automation(audit_data: Dict) -> List[Dict]:
    """Check automation setup."""
    findings = []
    auto_data = audit_data.get("automation", {})
    
    if not auto_data.get("accessible"):
        findings.append({
            "severity": "LOW",
            "area": "Automation",
            "finding": "Automation rules not accessible via API",
            "recommendation": "Check automation manually in Jira UI — consider rules for: auto-triage, SLA breach notifications, stale ticket reminders",
        })
    elif len(auto_data.get("rules", [])) == 0:
        findings.append({
            "severity": "MEDIUM",
            "area": "Automation",
            "finding": "No automation rules configured",
            "recommendation": "Add automation for: auto-assign on creation, SLA breach escalation, close stale tickets, notify on critical priority",
        })
    
    return findings


def check_issue_counts(audit_data: Dict) -> List[Dict]:
    """Check issue distribution for health signals."""
    findings = []
    counts = audit_data.get("issue_counts", {})
    
    total = counts.get("total", 0)
    if total == 0:
        findings.append({
            "severity": "HIGH",
            "area": "Usage",
            "finding": "Project has zero issues — it's empty",
            "recommendation": "The project has never been used or all issues were deleted. Verify the integration pipeline is actually creating tickets.",
        })
    
    # Check if everything is stuck in To Do
    by_status = counts.get("by_status", {})
    todo = by_status.get("To Do", 0)
    in_progress = by_status.get("In Progress", 0)
    done = by_status.get("Done", 0)
    
    if total > 0 and done == 0:
        findings.append({
            "severity": "HIGH",
            "area": "Usage",
            "finding": "No issues have been resolved/closed",
            "recommendation": "Tickets are being created but never completed — workflow may be broken or team isn't processing them",
        })
    
    if total > 0 and todo > 0 and (todo / total) > 0.8:
        findings.append({
            "severity": "HIGH",
            "area": "Usage",
            "finding": f"{int(todo/total*100)}% of issues are still in 'To Do'",
            "recommendation": "Massive backlog in To Do — either the workflow isn't being used or triage isn't happening",
        })
    
    return findings



# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

def generate_recommendations(audit_data: Dict) -> str:
    """Run all checks and produce a recommendations section."""
    all_findings = []
    
    all_findings.extend(check_issue_types(audit_data))
    all_findings.extend(check_fields(audit_data))
    all_findings.extend(check_workflows(audit_data))
    all_findings.extend(check_components(audit_data))
    all_findings.extend(check_service_desk(audit_data))
    all_findings.extend(check_priorities(audit_data))
    all_findings.extend(check_roles(audit_data))
    all_findings.extend(check_automation(audit_data))
    all_findings.extend(check_issue_counts(audit_data))
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))
    
    # Generate Markdown
    lines = []
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 12. Recommendations & Findings")
    lines.append("")
    
    # Summary counts
    critical = len([f for f in all_findings if f["severity"] == "CRITICAL"])
    high = len([f for f in all_findings if f["severity"] == "HIGH"])
    medium = len([f for f in all_findings if f["severity"] == "MEDIUM"])
    low = len([f for f in all_findings if f["severity"] == "LOW"])
    
    lines.append(f"**Total findings:** {len(all_findings)}")
    lines.append(f"- CRITICAL: {critical}")
    lines.append(f"- HIGH: {high}")
    lines.append(f"- MEDIUM: {medium}")
    lines.append(f"- LOW: {low}")
    lines.append("")
    
    # Detail table
    if all_findings:
        lines.append("| # | Severity | Area | Finding | Recommendation |")
        lines.append("|---|----------|------|---------|----------------|")
        for i, f in enumerate(all_findings, 1):
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
            lines.append(f"| {i} | {sev_emoji} {f['severity']} | {f['area']} | {f['finding']} | {f['recommendation']} |")
        lines.append("")
    else:
        lines.append("*No findings — project configuration looks healthy!*")
        lines.append("")
    
    # Action plan
    lines.append("## 13. Suggested Action Plan")
    lines.append("")
    lines.append("### Immediate (Critical/High)")
    lines.append("")
    for f in all_findings:
        if f["severity"] in ["CRITICAL", "HIGH"]:
            lines.append(f"- [ ] **{f['area']}:** {f['recommendation']}")
    lines.append("")
    lines.append("### Short-term (Medium)")
    lines.append("")
    for f in all_findings:
        if f["severity"] == "MEDIUM":
            lines.append(f"- [ ] **{f['area']}:** {f['recommendation']}")
    lines.append("")
    lines.append("### Nice-to-have (Low)")
    lines.append("")
    for f in all_findings:
        if f["severity"] == "LOW":
            lines.append(f"- [ ] **{f['area']}:** {f['recommendation']}")
    lines.append("")
    
    return "\n".join(lines)
