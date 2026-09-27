# server-hardening-audit

Read-only Linux server hardening audit that produces evidence-backed reports
mapped to the ASD Essential Eight and ISO/IEC 27001:2022.

> **Status: under development.** Nothing here is released yet. The sections
> below will be filled in before v0.1.0.

Only use this tool on systems you are authorised to test.

## Non-goals

These are deliberate. They keep the tool small enough to trust with root.

- **No automatic remediation.** The tool never changes the host. It reports
  what is true and suggests fixes; applying them is a human decision.
- **No remote execution, resident agent, or central console.** It runs
  locally on the audited host, once, and exits.
- **Not a replacement for Lynis, OpenSCAP or CIS-CAT.** It turns check
  results into evidence-backed, framework-mapped reports; it can read an
  existing Lynis report rather than compete with it.
- **No vulnerability scanning** (no CVE matching).
- **No organisational compliance maturity assessment.** It assesses the
  technical controls of a single host, not an organisation.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
