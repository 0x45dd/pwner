# Security policy

## Reporting a vulnerability in pwner itself

**Report it privately first.** We would rather fix it before it is public, and you will be
credited if you want to be named.

Use [GitHub's private vulnerability reporting](https://github.com/0x45dd/pwner/security/advisories/new)
— the **Report a vulnerability** button on the Security tab. It is a private channel between
you and the maintainers; nothing is visible until an advisory is published.

**Please do not open a public issue for a security bug.**

Include enough to reproduce: the version or commit, a short description, and the steps — run
against your own lab, not against anyone else's host.

What to expect: an acknowledgement within **3 working days**, then a fix and a disclosure
date we agree with you.

## What counts as a vulnerability here

pwner is an offensive tool, so "it scanned a host" is not a bug. What matters is anything
that breaks the two guarantees the tool makes:

- **A scope escape.** Any way to make a tool reach a host or network outside the authorized
  target — a tool argument that bypasses the check, a parser that mis-reads a host, a
  code path that skips the dispatch wrapper. This is the most serious class.
- **A consent bypass.** Any way for an intrusive action to run without the operator
  approving it, including the model approving on its own behalf.
- **A credential leak from pwner itself.** The saved API key or a session transcript ending
  up somewhere world-readable, or a key appearing in output.
- **Remote code execution on the operator's machine**, for instance through a crafted
  response from a scanned host or from a model provider.

Prompt injection that makes the agent *ask* for something out of scope is not by itself a
vulnerability — the guard is supposed to refuse it. Prompt injection that gets past the
guard is exactly a vulnerability, and is the interesting case.

## Scope of this policy

This policy covers the pwner codebase. It does not cover the external binaries pwner drives
(nmap, nuclei, netexec, impacket, hydra and the rest) — report those upstream. It does not
cover hosts you scanned.

## Supported versions

pwner is pre-1.0 and only the `main` branch is supported. There are no backported fixes yet.
