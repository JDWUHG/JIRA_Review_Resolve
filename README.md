# Jira Project Audit

Functional configuration audit for the **INFSOC** Jira Service Management project.

This is a **structural audit** — it inspects how the project is set up (issue types, fields, workflows, SLAs, queues, request types) and compares against a sensible baseline for a security operations service desk.

## What It Audits

| Area | Description |
|------|-------------|
| Issue Types | Types available, whether they're appropriate for security ops |
| Fields | Custom & system fields per issue type, required field checks |
| Workflows | Statuses, transitions, dead-end detection |
| SLAs | Response/resolution targets, whether they're active |
| Request Types | JSM portal request types and field mapping |
| Priorities | Priority levels and distribution |
| Components | Whether logical grouping is configured |
| Queues | Agent queue setup (JSM) |
| Automation | Active automation rules |
| Permissions | Role/permission scheme overview |

## Usage

### Run Locally

```bash
cp .env.example .env
# Fill in your JIRA_API_TOKEN
pip install -r requirements.txt
python src/audit.py
```

Output lands in `reports/` as:
- `audit_report.json` — raw structured data
- `audit_report.md` — human-readable summary with recommendations

### Run via GitHub Actions

1. Add secrets to this repo: `JIRA_INSTANCE_URL`, `JIRA_USER_EMAIL`, `JIRA_API_TOKEN`
2. Go to Actions → "Run Jira Audit" → Run workflow
3. Download the report artifact when complete

## Secrets Required

| Secret | Value |
|--------|-------|
| `JIRA_INSTANCE_URL` | `https://emishealthgroup.atlassian.net` |
| `JIRA_USER_EMAIL` | `johann.dewinnaar@emishealth.com` |
| `JIRA_API_TOKEN` | API token from https://id.atlassian.net/manage-profile/security/api-tokens |
