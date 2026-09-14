# Security Policy

`MASTER_RULES.md` is authoritative.

Security requirements and vendor implementation are separate layers. Customer/organization/CIS/NIST/ISO/PCI or regional requirements describe required controls; vendor documentation describes how a product can implement them.

Automation uses least privilege. Diagnostic workers must not automatically receive unrestricted administrative rights. Secrets, passwords, PSKs, private keys, tokens, SNMP secrets, and certificate private keys must not appear in sanitized exports, model context, repository content, or handover documents.

Safety-critical uncertainty fails closed. Management-path risk, unsupported configuration, unverified commands, version uncertainty, missing rollback, unresolved conflicts, or missing required input are valid blocking outcomes.