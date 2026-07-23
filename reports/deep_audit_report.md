# INFSOC Deep Audit — Phase 2

**Instance:** https://emishealthgroup.atlassian.net
**Project:** INFSOC (ESIT - UK Cyber Security Operations)
**Date:** 2026-07-23
**Auditor:** Johann DeWinnaar

---

## 1. Issue Volume (Operational Context)

| Metric | Count |
|--------|-------|
| **Total issues (all time)** | **0** |
| To Do | 0 |
| In Progress | 0 |
| Done | 0 |
| Created last 30 days | 0 |
| Resolved last 30 days | 0 |
| Open > 90 days (stale) | 0 |
| Unassigned & open | 0 |

**CRITICAL: The project is completely empty.** Zero issues exist across all types, statuses and priorities. Either:
- The `esit-jira-connector` pipeline has never successfully created an issue
- All issues were bulk-deleted at some point
- The API token doesn't have visibility to existing issues (unlikely given admin role)

---

## 2. Classification Fields — All Option Values

### SOC Categorisation (`customfield_10288`) — 28 values

These are the case/ticket categories used to classify SOC work:

| # | Category | Type |
|---|----------|------|
| 1 | Alert - AWS IaaS | Alert |
| 2 | Alert - CrowdStrike | Alert |
| 3 | Alert - Darktrace | Alert |
| 4 | Alert - Incident Report | Alert |
| 5 | Alert - Office 365 DLP | Alert |
| 6 | Alert - Phishing Simulation | Alert |
| 7 | Alert - Secureworks | Alert |
| 8 | Alert - Sentinel | Alert |
| 9 | Alert - Suspect Email | Alert |
| 10 | Alert - SIEM | Alert |
| 11 | Alert - Vulnerability | Alert |
| 12 | Alert - Zscaler | Alert |
| 13 | Alert - PaNDA (ESRO) | Alert |
| 14 | Alert - DLP | Alert |
| 15 | Request - Antigena email release | Request |
| 16 | Request - Device Isolated | Request |
| 17 | Request - Tuning Request | Request |
| 18 | Request - Report, Export or Dashboard Request | Request |
| 19 | Request - Security Approval | Request |
| 20 | Request - Security Tool Access | Request |
| 21 | Request - Training | Request |
| 22 | Request - Vulnerability Reports | Request |
| 23 | Request - Tenable/Nessus | Request |
| 24 | Azure - User at risk | Alert |
| 25 | Feed Activity Check | Operational |
| 26 | Vulnerability Advisory | Advisory |
| 27 | Jira Testing | Testing |
| 28 | Optum Advisory | Advisory |

---

### Closure Code (`customfield_10275`) — 45 values

| # | Closure Code | Category |
|---|-------------|----------|
| 1 | True-positive - 3rd party error | True Positive |
| 2 | True-positive - Human error (Internal) | True Positive |
| 3 | True-positive - Malicious activity (Internal) | True Positive |
| 4 | True-positive - Malicious activity (External) | True Positive |
| 5 | True-positive - Misconfiguration | True Positive |
| 6 | True-Positive - Phishing email | True Positive |
| 7 | True-positive - Physical damage (Accidental) | True Positive |
| 8 | True-positive - Physical damage (Malicious) | True Positive |
| 9 | True-positive - System Fault | True Positive |
| 10 | True-positive - Reconnaissance | True Positive |
| 11 | True-positive - Unauthorized access | True Positive |
| 12 | True-positive - DLP | True Positive |
| 13 | False-positive - 3rd party error | False Positive |
| 14 | False-positive - Human error (Internal) | False Positive |
| 15 | False-positive - Misconfiguration | False Positive |
| 16 | False-Positive - Penetration testing | False Positive |
| 17 | False-Positive - Phishing email (Misreported) | False Positive |
| 18 | False-Positive - Phishing email (Training) | False Positive |
| 19 | False-positive - Scanning (External) | False Positive |
| 20 | False-positive - Scanning (Internal) | False Positive |
| 21 | False-positive - System fault | False Positive |
| 22 | False-positive - Unauthorized access | False Positive |
| 23 | False-positive - DLP | False Positive |
| 24 | Escalated to SIR | Escalation |
| 25 | Escalated to SLT | Escalation |
| 26 | Zscaler exception created | Resolution |
| 27 | Request fulfilled | Resolution |
| 28 | Request declined | Resolution |
| 29 | Triaged | Resolution |
| 30 | Cancelled by customer | Cancelled |
| 31 | Security Approval - Approved | Approval |
| 32 | Security approval - Rejected | Approval |
| 33 | Vulnerability Not Present | Vulnerability |
| 34 | Vulnerability / Threat not Present | Vulnerability |
| 35 | IOC Blocked | IOC |
| 36 | IOC Investigated - No threat found | IOC |
| 37 | IOC Confirmed - Threat Mitigated | IOC |
| 38 | IOC Action Update Complete | IOC |
| 39 | IOI Review - False Positive | IOC |
| 40 | IOI Review True Positive | IOC |
| 41 | Month End QA | Operational |
| 42 | General Analyst Request | Operational |
| 43 | BAU Activity | Operational |
| 44 | Informational - No action required | Informational |
| 45 | DLP | DLP |

---

### Source (`customfield_10252`) — 6 values

| # | Source |
|---|--------|
| 1 | Email |
| 2 | Phone |
| 3 | Monitoring systems |
| 4 | Vendor/technical advisory |
| 5 | Customer |
| 6 | Other |

---

### Urgency (`customfield_10242`) — 4 values

| # | Urgency |
|---|---------|
| 1 | Critical |
| 2 | High |
| 3 | Medium |
| 4 | Low |

---

### Impact (`customfield_10243`) — 4 values

| # | Impact |
|---|--------|
| 1 | Extensive / Widespread |
| 2 | Significant / Large |
| 3 | Moderate / Limited |
| 4 | Minor / Localized |

---

### Pending Reason (`customfield_10244`) — 4 values

| # | Reason |
|---|--------|
| 1 | More info required |
| 2 | Awaiting approval |
| 3 | Waiting on vendor |
| 4 | Pending on change request |

---

### Product Categorization (`customfield_10245`) — 16 values

| # | Category |
|---|----------|
| 1 | Communication |
| 2 | Document |
| 3 | People |
| 4 | Service |
| 5 | Software |
| 6 | Hardware - Component |
| 7 | Hardware - CPD |
| 8 | Hardware - Disc |
| 9 | Hardware - Peripheral |
| 10 | Hardware - Process Equipment |
| 11 | Hardware - Power |
| 12 | Hardware - Tape |
| 13 | Hardware - Virtual |
| 14 | InfoSec - Approvals |
| 15 | InfoSec - Access |
| 16 | InfoSec - Tenable Report |

---

### Purple Testing (`customfield_10301`) — 4 values

| # | Value |
|---|-------|
| 1 | Yes |
| 2 | No |
| 3 | Yes - Nmap |
| 4 | Yes - DDoS |

---

### Security Tool (`customfield_10360`) — 5 values

| # | Tool |
|---|------|
| 1 | Darktrace |
| 2 | Crowdstrike |
| 3 | Tenable SC |
| 4 | Tenable IO |
| 5 | Other |

---

### Referred To (Group) (`customfield_10398`) — 7 values

| # | Group |
|---|-------|
| 1 | Crowdstrike |
| 2 | Cyberfort |
| 3 | Darktrace |
| 4 | Group IT |
| 5 | Group Security |
| 6 | Hosted Networks |
| 7 | Hosted Platforms |

---

### SIR Logged? (`customfield_10399`) — 1 value

| # | Value |
|---|-------|
| 1 | Yes |

---

## 3. Resolution Types — 12 total

| # | Resolution | Description |
|---|-----------|-------------|
| 1 | Done | Work has been completed on this issue |
| 2 | Rejected | This is not a valid defect |
| 3 | Duplicate | The problem is a duplicate of an existing work item |
| 4 | Cannot Reproduce | All attempts at reproducing failed |
| 5 | Won't Do | This issue won't be actioned |
| 6 | Completed | Work has been completed |
| 7 | Fixed | A fix is checked into the tree and tested |
| 8 | For Discussion | For Discussion |
| 9 | Won't Fix | Will never be fixed |
| 10 | Incomplete | Not completely described |
| 11 | Deployed | Deployed |
| 12 | Transferred | Issue to be fixed by another team |

---

## 4. Issue Link Types — 15 total

| # | Link Type | Inward | Outward |
|---|-----------|--------|---------|
| 1 | Blocks | is blocked by | blocks |
| 2 | Cloners | is cloned by | clones |
| 3 | Defect | created by | created |
| 4 | Duplicate | is duplicated by | duplicates |
| 5 | Gantt End to End | has to be finished together with | has to be finished together with |
| 6 | Gantt End to Start | has to be done after | has to be done before |
| 7 | Gantt Start to End | earliest end is start of | start is earliest end of |
| 8 | Gantt Start to Start | has to be started together with | has to be started together with |
| 9 | Issue split | split from | split to |
| 10 | Parent-Child | is child of | is parent of |
| 11 | Polaris work item link | is implemented by | implements |
| 12 | Problem/Incident | is caused by | causes |
| 13 | Relates | relates to | relates to |
| 14 | Risk mitigation | is mitigated by | mitigates risk |
| 15 | Test | is tested by | tests |

---

## 5. Issue Security Levels

**Not configured.** No issue security levels exist on this project.

---

## 6. Workflow Analysis (per Issue Type)

| Issue Type | Statuses | Triage | Escalate | Waiting | Cancel | Reopen | Block | Refer | Investigate |
|-----------|----------|--------|----------|---------|--------|--------|-------|-------|------------|
| Email request | 6 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Report an incident | 7 | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Request access to Security tools | 6 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Request Security Team approval | 6 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Report, Export or Dashboard Request | 6 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Cyberfort Request | 6 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Request Device Isolation | 6 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Engineering/Config Request | 5 | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Zscaler Issue/Request | 5 | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Darktrace Alert | 5 | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Vulnerability** | **4** | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Threat Indicator** | **4** | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

**Key Gaps in Vulnerability/Indicator workflows:**
- No Triage status
- No Escalation path
- No Cancel/Won't Do
- No Reopen
- No Blocked status
- Only 4 statuses: To Do → Pending → In Progress → Done

---

## 7. Request Type Portal Fields (Customer/Agent View)

### Vulnerability (portal)
| Field | Required |
|-------|----------|
| Summary | Yes |
| Urgency | No |
| Start date | No |
| Description | No |
| Referred Date | No |
| Referred To (Person) | No |
| Source | No |
| Closure code | No |
| Due date | No |

### Threat Indicator (portal)
| Field | Required |
|-------|----------|
| Summary | Yes |
| Description | No |
| Source | No |

### Report an incident (portal)
| Field | Required |
|-------|----------|
| Summarize the problem | Yes |
| Describe the problem | Yes |
| Attachment | No |
| How urgent is this? | No |
| What's the impact? | No |

### Email request (portal)
| Field | Required |
|-------|----------|
| Subject | Yes |
| Body | No |
| Attachment | No |

---

## 8. Labels in Use

**100 labels** — but ALL appear to be from other projects (version numbers like `10.23_Regression`, `2.39.1.x`, `3.1.1.15`). **Zero security-relevant labels** are in use.

---

## 9. Dashboards

**50 dashboards** visible — but ALL belong to other teams/products (CaMIS, Emerson, EDM, EHI, Andromeda, Clinical Record). **No INFSOC/Security-specific dashboard exists.**

---

## 10. Saved Filters

**0 saved filters** accessible to this account for INFSOC.

---

## 11. Key Findings from Deep Audit

### CRITICAL

| # | Finding | Impact |
|---|---------|--------|
| 1 | **Project is completely empty (0 issues)** | The connector pipeline isn't creating tickets. Nothing operational is happening here. |
| 2 | **Vulnerability/Indicator workflows are too simple** (4 statuses, no triage/escalate/reopen) | When tickets DO arrive, they'll hit a dead-end workflow |
| 3 | **No SLAs configured** (Phase 1 finding confirmed) | No response/resolution time targets |
| 4 | **Custom field ID mismatch** in esit-jira-connector (10100/10101 vs actual 11442/11443) | Connector is writing to wrong fields |

### HIGH

| # | Finding | Impact |
|---|---------|--------|
| 5 | **No security-specific dashboard** | No operational visibility |
| 6 | **No saved filters** | No pre-built views for SOC analysts |
| 7 | **Labels are all from other projects** | No meaningful tagging for security |
| 8 | **No issue security levels** | Can't restrict sensitive tickets |
| 9 | **Closure codes are well-defined (45)** but the workflow is too simple to use them effectively | Good taxonomy, broken process |

### OBSERVATIONS (Positive)

| # | What's Good |
|---|-------------|
| 1 | SOC categorisation (28 values) is comprehensive — covers alerts + requests |
| 2 | Closure codes (45) are detailed with True/False positive taxonomy + IOC outcomes |
| 3 | Urgency × Impact matrix exists (Critical/High/Medium/Low × Widespread/Large/Limited/Localized) |
| 4 | Referral groups defined (Crowdstrike, Cyberfort, Darktrace, Group IT, etc.) |
| 5 | Product categorization includes InfoSec-specific values |
| 6 | Issue link type "Problem/Incident" (causes/is caused by) exists for root cause linking |
| 7 | Issue link type "Risk mitigation" exists |
| 8 | Resolution types include "Deployed", "Transferred", "Won't Do" — good for SOC use |

---

## 12. Recommended Immediate Actions

1. **Fix the connector** — update `esit-jira-connector` to use `customfield_11442` (CVE-Key) and `customfield_11443` (Indicator-Key)
2. **Test the pipeline** — manually trigger a workflow to confirm tickets actually land in INFSOC
3. **Expand Vulnerability workflow** — add: Triaged, Escalated, Mitigated, Blocked, Cancelled, Reopened
4. **Expand Indicator workflow** — same as above
5. **Configure SLAs** — set response/resolution targets per priority
6. **Create a SOC dashboard** with gadgets for: open by priority, open by SOC category, SLA health, created vs resolved trend
7. **Create saved filters** for common views: my open, unassigned, critical/high, by tool source
8. **Add components** — Network, Endpoint, Cloud, Identity, Application, Data
9. **Add CVE-Key / Indicator-Key to Vulnerability/Indicator screens** as visible fields (currently they exist but may not be on the screen)
