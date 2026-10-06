"""Static lists the seed draws from. Everything here is synthetic: the company,
the people, the domains and the systems are the FleetLine model of Assignment 1.
"""
from __future__ import annotations

from warden.models.enums import Criticality, NhiType, Sensitivity, SystemCategory

EMAIL_DOMAIN = "fleetline.example"
CONSULTANCY_DOMAIN = "devhouse.example"

# (department, headcount, job titles cycled through the department's people).
# Headcounts sum to 60; Drivers plus Field Service is the "about 20 drivers and
# field technicians" of spec section 8; IT holds exactly one IT Coordinator.
DEPARTMENTS: tuple[tuple[str, int, tuple[str, ...]], ...] = (
    ("Operations", 8, ("Dispatcher", "Operations Planner", "Fleet Supervisor")),
    ("Field Service", 8, ("Field Technician",)),
    ("Drivers", 12, ("Driver",)),
    ("Finance", 5, ("Accountant", "Controller", "Billing Clerk")),
    ("Sales", 6, ("Account Manager", "Sales Representative")),
    ("Customer Support", 6, ("Support Agent", "Support Team Lead")),
    ("IT", 3, ("IT Coordinator", "System Administrator", "Help Desk Technician")),
    ("Management", 4, ("Chief Executive", "Operations Manager", "Finance Manager", "Sales Manager")),
    ("R&D", 3, ("Software Engineer", "Data Analyst", "Software Engineer")),
    ("External Development", 5, ("DevOps Engineer", "Developer", "Developer", "Developer", "DevOps Engineer")),
)

# Sixty distinct synthetic names, assigned to the departments above in order:
# Operations 0 to 7, Field Service 8 to 15, Drivers 16 to 27, Finance 28 to 32,
# Sales 33 to 38, Customer Support 39 to 44, IT 45 to 47, Management 48 to 51,
# R&D 52 to 54, External Development 55 to 59.
NAMES: tuple[tuple[str, str], ...] = (
    ("Noa", "Levi"), ("Yossi", "Cohen"), ("Tamar", "Friedman"), ("Amir", "Ben-David"), ("Shira", "Katz"), ("Omer", "Peretz"), ("Lior", "Shapiro"), ("Yael", "Biton"),
    ("Itai", "Azulay"), ("Michal", "Dahan"), ("Gal", "Malka"), ("Roni", "Amar"), ("Ido", "Gabai"), ("Hila", "Sasson"), ("Nir", "Elbaz"), ("Efrat", "Ohana"),
    ("Moshe", "Alon"), ("Rivka", "Segal"), ("Avi", "Nahum"), ("Tal", "Barzilay"), ("Dor", "Yosef"), ("Oren", "Mor"), ("Sivan", "Hadad"), ("Eli", "Turgeman"),
    ("Adi", "Golan"), ("Ben", "Harari"), ("Yonatan", "Ashkenazi"), ("Liat", "Kaplan"),
    ("Ruth", "Weiss"), ("Uri", "Zohar"), ("Keren", "Shalom"), ("Daniel", "Regev"), ("Orit", "Baruch"),
    ("Shai", "Levin"), ("Maor", "Tal"), ("Inbal", "Rosen"), ("Guy", "Navon"), ("Anat", "Ziv"), ("Roy", "Ayalon"),
    ("Tzipi", "Halevi"), ("Erez", "Dayan"), ("Vered", "Sela"), ("Nadav", "Kimchi"), ("Merav", "Lavi"), ("Gilad", "Oz"),
    ("Dana", "Mizrahi"), ("Smadar", "Peled"), ("Yuval", "Stern"),
    ("Alon", "Bar"), ("Ronen", "Avital"), ("Neta", "Doron"), ("Boaz", "Carmel"),
    ("Tomer", "Shahar"), ("Lea", "Argov"), ("Asaf", "Reuven"),
    ("Eitan", "Barak"), ("Maya", "Peretz"), ("Hadar", "Lev"), ("Ofir", "Sagi"), ("Elad", "Nir"),
)

# Departed people as (index into NAMES, days since departure). 90 to 900 days is
# the spec's "3 to 30 months". Index 55 (Eitan Barak, DevOps Engineer at the
# consultancy) is the demo leaver of spec section 14; index 57 (Hadar Lev,
# Developer) is the second former consultancy developer.
DEPARTED: tuple[tuple[int, int], ...] = ((55, 400), (57, 120), (6, 700), (10, 200), (25, 95), (19, 500), (30, 300), (41, 850))
DEMO_LEAVER_INDEX = 55  # index 56, Maya Peretz, is the active developer who receives the transfer in the demo
ADMIN_PERSON_INDEX = 45  # Dana Mizrahi, IT Coordinator
VIEWER_PERSON_INDEX = 49  # Ronen Avital, Operations Manager

SYSTEMS: tuple[tuple[str, SystemCategory, Criticality, str], ...] = (
    ("SAP Business One", SystemCategory.erp, Criticality.high, "ERP: invoices, customers, payments and inventory."),
    ("AWS Account", SystemCategory.cloud, Criticality.high, "Production cloud account for the portals and data pipelines."),
    ("Customer Portal", SystemCategory.cloud, Criticality.high, "Customer-facing web application hosted by FleetLine."),
    ("Driver Portal", SystemCategory.cloud, Criticality.medium, "Driver-facing web application hosted by FleetLine."),
    ("Bitbucket", SystemCategory.ci_cd, Criticality.high, "Source repositories and pipelines."),
    ("Google Workspace", SystemCategory.saas, Criticality.high, "Mail, drive and calendar for the company."),
    ("Slack", SystemCategory.messaging, Criticality.medium, "Team messaging and alert channels."),
    ("CRM", SystemCategory.saas, Criticality.medium, "Customer relationship management subscription."),
    ("Invoice Reader Agent", SystemCategory.ai_agent_platform, Criticality.high, "AI agent that reads invoices from a shared mailbox and posts them to SAP."),
    ("Support Reply Agent", SystemCategory.ai_agent_platform, Criticality.medium, "AI agent that drafts support replies from CRM tickets."),
    ("Firewall and VPN", SystemCategory.network, Criticality.high, "Perimeter firewall and remote access VPN."),
    ("PostgreSQL RDS", SystemCategory.database, Criticality.high, "Managed database behind the portals."),
    ("Email Gateway", SystemCategory.saas, Criticality.medium, "Outbound mail relay for notifications."),
)

# Scopes per system: 3 to 8 each (spec section 8), 59 in total.
SCOPES: dict[str, tuple[tuple[str, Sensitivity], ...]] = {
    "SAP Business One": (
        ("sap.invoices.read", Sensitivity.medium), ("sap.invoices.write", Sensitivity.high), ("sap.customers.read", Sensitivity.medium),
        ("sap.payments.write", Sensitivity.high), ("sap.inventory.read", Sensitivity.low), ("sap.reports.read", Sensitivity.low),
    ),
    "AWS Account": (
        ("aws.s3.read", Sensitivity.medium), ("aws.s3.full", Sensitivity.high), ("aws.ec2.describe", Sensitivity.low), ("aws.ec2.admin", Sensitivity.high),
        ("aws.iam.admin", Sensitivity.high), ("aws.rds.connect", Sensitivity.high), ("aws.cloudwatch.read", Sensitivity.low), ("aws.lambda.invoke", Sensitivity.medium),
    ),
    "Customer Portal": (
        ("portal.orders.read", Sensitivity.medium), ("portal.orders.write", Sensitivity.high), ("portal.customers.read", Sensitivity.high), ("portal.admin", Sensitivity.high),
    ),
    "Driver Portal": (
        ("driver.routes.read", Sensitivity.low), ("driver.routes.write", Sensitivity.medium), ("driver.location.read", Sensitivity.medium), ("driver.admin", Sensitivity.high),
    ),
    "Bitbucket": (
        ("repo.read", Sensitivity.low), ("repo.write", Sensitivity.medium), ("repo.admin", Sensitivity.high), ("pipelines.run", Sensitivity.medium),
        ("pipelines.variables.write", Sensitivity.high),
    ),
    "Google Workspace": (
        ("gmail.readonly", Sensitivity.high), ("gmail.send", Sensitivity.high), ("drive.readonly", Sensitivity.medium), ("drive.file", Sensitivity.medium),
        ("calendar.readonly", Sensitivity.low), ("admin.directory.user", Sensitivity.high),
    ),
    "Slack": (
        ("slack.chat:write", Sensitivity.medium), ("slack.channels:read", Sensitivity.low), ("slack.files:write", Sensitivity.medium), ("slack.admin", Sensitivity.high),
    ),
    "CRM": (
        ("crm.contacts.read", Sensitivity.medium), ("crm.contacts.write", Sensitivity.medium), ("crm.tickets.read", Sensitivity.medium),
        ("crm.tickets.write", Sensitivity.high), ("crm.admin", Sensitivity.high),
    ),
    "Invoice Reader Agent": (
        ("agent.invoices.run", Sensitivity.medium), ("agent.tools.configure", Sensitivity.high), ("agent.logs.read", Sensitivity.low),
    ),
    "Support Reply Agent": (
        ("agent.replies.run", Sensitivity.medium), ("agent.tools.configure", Sensitivity.high), ("agent.logs.read", Sensitivity.low),
    ),
    "Firewall and VPN": (
        ("vpn.connect", Sensitivity.medium), ("firewall.rules.read", Sensitivity.medium), ("firewall.rules.write", Sensitivity.high), ("vpn.admin", Sensitivity.high),
    ),
    "PostgreSQL RDS": (
        ("db.warden.read", Sensitivity.medium), ("db.warden.write", Sensitivity.high), ("db.replication", Sensitivity.high), ("db.admin", Sensitivity.high),
    ),
    "Email Gateway": (
        ("mail.relay", Sensitivity.medium), ("mail.logs.read", Sensitivity.low), ("mail.admin", Sensitivity.high),
    ),
}

# The two AI agents' grants (spec section 8): system name and scope name.
INVOICE_AGENT_SCOPES = (("Google Workspace", "gmail.readonly"), ("SAP Business One", "sap.invoices.write"))
SUPPORT_AGENT_SCOPES = (("CRM", "crm.contacts.read"), ("CRM", "crm.tickets.write"), ("Slack", "slack.chat:write"))

# Which systems can host each NHI type when the profile does not fix one.
TYPE_SYSTEMS: dict[NhiType, tuple[str, ...]] = {
    NhiType.service_account: ("SAP Business One", "AWS Account", "PostgreSQL RDS", "Firewall and VPN", "Google Workspace", "Email Gateway", "Customer Portal", "Driver Portal"),
    NhiType.api_key: ("AWS Account", "CRM", "Customer Portal", "Driver Portal", "Slack", "Email Gateway", "Google Workspace", "PostgreSQL RDS"),
    NhiType.oauth_grant: ("Google Workspace", "Slack", "CRM"),
    NhiType.webhook: ("Slack", "CRM", "Bitbucket", "Customer Portal", "Driver Portal"),
    NhiType.deploy_key: ("Bitbucket",),
    NhiType.certificate: ("Firewall and VPN", "Customer Portal", "Driver Portal", "Email Gateway", "AWS Account"),
    NhiType.ci_token: ("Bitbucket",),
    NhiType.ai_agent: ("Invoice Reader Agent", "Support Reply Agent"),
}

NAME_PREFIX: dict[NhiType, str] = {
    NhiType.service_account: "svc",
    NhiType.api_key: "key",
    NhiType.oauth_grant: "oauth",
    NhiType.webhook: "hook",
    NhiType.deploy_key: "deploy",
    NhiType.certificate: "cert",
    NhiType.ci_token: "ci",
    NhiType.ai_agent: "agent",
}

PURPOSES: tuple[str, ...] = (
    "invoice-sync", "backup", "reporting", "monitoring", "billing", "dispatch", "telemetry", "notifications", "etl", "payroll",
    "routing", "support", "crm-sync", "audit-export", "fleet-tracking", "onboarding", "alerts", "analytics", "warehouse", "metrics",
)

REPOS: tuple[str, ...] = ("fleetline/portal", "fleetline/driver-app", "fleetline/infra", "fleetline/etl")
PIPELINES: tuple[str, ...] = ("build-portal", "deploy-driver-app", "nightly-etl")
TOKEN_SCOPES: tuple[str, ...] = ("repository:write", "pipeline:variable", "repository:read")
WEBHOOK_EVENTS: tuple[str, ...] = ("order.created", "shipment.updated", "invoice.paid", "ticket.opened")
CERTIFICATE_ISSUERS: tuple[str, ...] = ("FleetLine Internal CA", "External CA")
AUTH_METHODS: tuple[str, ...] = ("password", "key", "certificate")
GRANT_TYPES: tuple[str, ...] = ("authorization_code", "client_credentials")
