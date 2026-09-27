# ASD Essential Eight — host-01

> Generated against a production host running two public sites. Host identifiers redacted; all measurements are real.

> This view assesses only the parts of the Essential Eight that apply to a single Linux server. It is not an Essential Eight maturity assessment of an organisation.

Run `20260927T084403Z-host-01` · 2026-09-27T08:44:03Z · profile prod-vps

**Scope of the framework, in ASD's words:**

> "The Essential Eight has been designed to protect organisations' internet-connected information technology networks. While the principles behind the Essential Eight may be applied to enterprise mobility and operational technology networks, it was not designed for such purposes and alternative mitigation strategies may be more appropriate to defend against unique cyber threats to these environments."  
> — Essential Eight maturity model, ASD, November 2023

Many Maturity Level One requirements name workstations, office productivity suites, web browsers, email clients, PDF software or Microsoft Office. Those are marked not applicable to a server. Requirements that apply but concern organisational processes (asset discovery, vulnerability scanning, access request approval) cannot be observed from inside one host and are reported as not assessed.

**How results are combined.** A mitigation strategy meets Maturity Level One only if every applicable requirement is Effective (the assessment process guide's rule). One Ineffective requirement means the level is not achieved; any requirement without an outcome means it is not determined. A risk acceptance never turns an Ineffective requirement into an Effective one.

Only Maturity Level One is assessed. Maturity Levels Two and Three are **not assessed in this version**.

## Maturity Level One by mitigation strategy

| Strategy | ML1 result | Applicable requirements | Effective | Ineffective | Not assessed / no visibility |
|---|---|---:|---:|---:|---:|
| Patch applications | **Not determined** | 6 of 9 | 0 | 0 | 6 |
| Patch operating systems | **Not determined** | 6 of 8 | 2 | 0 | 4 |
| Multi-factor authentication | **Not determined** | 4 of 7 | 0 | 0 | 4 |
| Restrict administrative privileges | **Not achieved** | 4 of 7 | 0 | 1 | 3 |
| Application control | **Not applicable** | 0 of 3 | 0 | 0 | 0 |
| Restrict Microsoft Office macros | **Not applicable** | 0 of 4 | 0 | 0 | 0 |
| User application hardening | **Not applicable** | 0 of 4 | 0 | 0 | 0 |
| Regular backups | **Not determined** | 6 of 6 | 0 | 0 | 6 |

## Requirements with host evidence

| Requirement | Summary | Outcome | Evidence |
|---|---|---|---|
| PA-ML1-05 † | Critical or actively exploited vulnerabilities in online services are patched within 48 hours of the fix being released. | **Not assessed (partial evidence only)** | PAT-03 PASS |
| PA-ML1-06 † | Other vulnerabilities in online services are patched within two weeks of the fix being released. | **Not assessed (partial evidence only)** | PAT-03 PASS |
| PO-ML1-05 † | Critical or actively exploited OS vulnerabilities on internet-facing servers are patched within 48 hours of the fix being released. | **Effective** | PAT-01 PASS, PAT-02 PASS |
| PO-ML1-06 † | Other OS vulnerabilities on internet-facing servers are patched within two weeks of the fix being released. | **Effective** | PAT-01 PASS, PAT-02 PASS |
| RAP-ML1-02 † | Privileged users have a dedicated privileged account used only for privileged duties. | **Ineffective** | ACC-01 FAIL · risk accepted, ACC-03 PASS, ACC-05 PASS |
| RB-ML1-01 | Backups of data, applications and settings are made and kept according to business criticality and continuity needs. | **Not assessed (partial evidence only)** | RES-01 MANUAL |
| RB-ML1-02 † | Backups of data, applications and settings are synchronised so they restore to a common point in time. | **Not assessed (partial evidence only)** | RES-02 MANUAL |
| RB-ML1-03 | Backups are kept in a secure and resilient manner. | **Not assessed (partial evidence only)** | RES-01 MANUAL |
| RB-ML1-04 † | Restoring from backups to a common point in time is tested in disaster recovery exercises. | **Not assessed (awaiting attestation)** | RES-02 MANUAL |
| RB-ML1-05 | Unprivileged accounts cannot access other accounts' backups. | **Not assessed (partial evidence only)** | RES-04 PASS |
| RB-ML1-06 | Unprivileged accounts cannot modify or delete backups. | **Not assessed (partial evidence only)** | RES-04 PASS |

*Partial evidence* means the checks can disprove the requirement but cannot prove it on their own:

- **PA-ML1-05:** Container image age can reveal stale application builds but cannot prove a 48-hour patch window.
- **PA-ML1-06:** Container image age can reveal stale builds but cannot prove the two-week window.
- **RB-ML1-01:** The host shows schedules, freshness against the declared RPO and retention; the assessment process guide also expects documented continuity requirements.
- **RB-ML1-02:** A restore drill exercises one data set; synchronisation across data, applications and settings needs a wider view.
- **RB-ML1-03:** An off-host copy (attested under RES-01) shows resilience; encryption and access to that copy are not assessed.
- **RB-ML1-05:** File and directory permissions of on-host backups are checked (RES-04); access to off-host copies is not.
- **RB-ML1-06:** File and directory permissions of on-host backups are checked (RES-04); off-host copies are not.

## Not assessed (15)

These requirements apply to a server like this one, but this run holds no evidence for them. They are gaps in coverage, not passes.

| Requirement | Summary | Why |
|---|---|---|
| PA-ML1-01 | Assets are discovered automatically, at least every two weeks, to feed vulnerability scanning. | An organisation-wide process; not observable from inside one host. |
| PA-ML1-02 | Vulnerability scanning uses a scanner whose vulnerability database is current. | Vulnerability scanning is outside this tool's scope (no CVE matching). |
| PA-ML1-03 | Online services are scanned daily for missing patches. | The host serves online services, but scanning is an external process. |
| PA-ML1-08 | Online services whose vendor no longer supports them are removed. | Requires knowing each application's vendor support status; not collected in this version. |
| PO-ML1-01 | Assets are discovered automatically, at least every two weeks, to feed vulnerability scanning. | An organisation-wide process; not observable from inside one host. |
| PO-ML1-02 | Vulnerability scanning uses a scanner whose vulnerability database is current. | Vulnerability scanning is outside this tool's scope; a package manager's upgradable list is not a vulnerability scanner. |
| PO-ML1-03 | Operating systems of internet-facing servers and network devices are scanned daily for missing patches. | Scanning is an external process; not observable from inside the host. |
| PO-ML1-08 | Operating systems no longer supported by their vendor are replaced. | The assessment process guide suggests checking /etc/os-release against distribution support dates. The release is recorded in every run, but this version ships no support-date table, so no verdict is made. |
| MFA-ML1-01 | Users of the organisation's own online services holding sensitive data authenticate with MFA. | The host serves online services; their login flows are application behaviour, not host configuration. At this level MFA focuses on online services, not server administration. |
| MFA-ML1-04 | Staff using the organisation's own online customer services with sensitive customer data authenticate with MFA. | Application login behaviour; not observable from host configuration. |
| MFA-ML1-06 | Customers of online customer services holding sensitive customer data authenticate with MFA. | Application login behaviour; not observable from host configuration. |
| MFA-ML1-07 | MFA combines something the user has with something they know, or something they have unlocked by something they know or are. | Describes the online services' MFA factors; not observable from host configuration. |
| RAP-ML1-01 | Requests for privileged access are validated when first made. | An approval process; evidence is request records, not host state. |
| RAP-ML1-03 | Privileged accounts, unless explicitly authorised, cannot reach the internet, email or web services. | Egress restrictions per account are not assessed in this version. |
| RAP-ML1-04 | Privileged accounts authorised for online services are limited to what their duties require. | Depends on documented authorisations; not observable from host state. |

## Not applicable (22)

These requirements do not apply to a Linux server.

| Requirement | Summary | Why |
|---|---|---|
| PA-ML1-04 † | Office suites, browsers and extensions, email clients, PDF software and security products are scanned weekly for missing patches. | A server does not run these end-user application classes. |
| PA-ML1-07 † | Office suites, browsers and extensions, email clients, PDF software and security products are patched within two weeks. | A server does not run these end-user application classes. |
| PA-ML1-09 | Unsupported office suites, browsers, email clients, PDF software, Flash Player and security products are removed. | A server does not run these end-user application classes. |
| PO-ML1-04 † | Operating systems of workstations and non-internet-facing servers and devices are scanned every two weeks. | Concerns other asset classes; the audited host is an internet-facing server. |
| PO-ML1-07 † | OS vulnerabilities on workstations and non-internet-facing servers and devices are patched within one month. | Concerns other asset classes; the audited host is an internet-facing server. |
| MFA-ML1-02 | Users of third-party online services holding the organisation's sensitive data authenticate with MFA. | Concerns the organisation's use of third-party services, not this host. |
| MFA-ML1-03 | Where available, MFA is used for third-party online services holding non-sensitive data. | Concerns the organisation's use of third-party services, not this host. |
| MFA-ML1-05 | Staff using third-party online customer services with sensitive customer data authenticate with MFA. | Concerns the organisation's use of third-party services, not this host. |
| RAP-ML1-05 † | Privileged users work in separate privileged and unprivileged operating environments. | Operating-environment separation concerns administrators' workstations, not the server they administer. |
| RAP-ML1-06 † | Unprivileged accounts cannot log on to privileged operating environments. | Operating-environment separation concerns administrators' workstations. |
| RAP-ML1-07 † | Privileged accounts, other than local administrator accounts, cannot log on to unprivileged operating environments. | Operating-environment separation concerns administrators' workstations. |
| AC-ML1-01 | Application control is implemented on workstations. | Maturity Level One requires application control on workstations only; internet-facing servers are added at Maturity Level Two. |
| AC-ML1-02 | Application control covers user profiles and temporary folders used by the OS, browsers and email clients. | Qualifies the workstation implementation required at this level. |
| AC-ML1-03 | Application control limits executables, libraries, scripts, installers and similar content to an approved set. | Qualifies the workstation implementation required at this level. |
| OM-ML1-01 | Office macros are disabled for users without a demonstrated business need. | Microsoft Office does not run on a Linux server. |
| OM-ML1-02 | Office macros in files from the internet are blocked. | Microsoft Office does not run on a Linux server. |
| OM-ML1-03 | Antivirus scanning of Office macros is enabled. | Microsoft Office does not run on a Linux server. |
| OM-ML1-04 | Users cannot change Office macro security settings. | Microsoft Office does not run on a Linux server. |
| UAH-ML1-01 | Internet Explorer 11 is disabled or removed. | Internet Explorer does not exist on Linux. |
| UAH-ML1-02 | Web browsers do not run Java from the internet. | A server does not run an interactive web browser. |
| UAH-ML1-03 | Web browsers do not process web advertisements from the internet. | A server does not run an interactive web browser. |
| UAH-ML1-04 | Users cannot change web browser security settings. | A server does not run an interactive web browser. |

## Evidence towards higher maturity levels (not assessed)

| Level | Strategy | Requirement | Evidence | Note |
|---|---|---|---|---|
| ML2 | Multi-factor authentication | MFA is used to authenticate privileged users of systems. | ACC-06 FAIL | SSH administration is 'privileged users of systems'; at Maturity Level One MFA focuses on online services. |
| ML2 | Application control | Application control is implemented on internet-facing servers. | BAS-04 PASS | AppArmor/SELinux confine programs but do not restrict execution to an approved set; at best a weak counterpart. |
| ML3 | Restrict administrative privileges | Privileged access is limited to what users and services need. | ACC-03 PASS, ACC-05 PASS | Application accounts without privileges and no passwordless full root are host-level evidence for this. |

† Applicability or mapping judgement flagged for review.

## Sources

- *Essential Eight maturity model*, Australian Signals Directorate, First published June 2017; last updated November 2023. https://www.cyber.gov.au/ (CC BY 4.0). Used for: Requirements (Appendix A) and the scope statement quoted above.
- *Essential Eight assessment process guide*, Australian Signals Directorate, First published November 2022; last updated October 2024. https://www.cyber.gov.au/ (CC BY 4.0). Used for: Assessment outcome terms, the implementation rule, per-requirement context.
- *Essential Eight explained*, Australian Signals Directorate, First published February 2017; last updated November 2023. https://www.cyber.gov.au/ (CC BY 4.0). Used for: The list of eight mitigation strategies.

Requirement IDs are assigned by this tool and are not ASD identifiers. Summaries are paraphrases; the maturity model is the authoritative text.
