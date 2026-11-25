# Security policy

This project holds other people's credentials, so we treat every report seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/BloubHQ/credentials/security/advisories/new).

Include what you can of:

- the component (`engine`, `transport`, `verify`) and version or commit;
- what an attacker in which position (operator, caller, destination server, log store, network)
  can do, and what they gain;
- a reproduction: a policy, a request or a test is ideal.

We aim to acknowledge within 3 working days and to agree on a disclosure date with you,
normally within 90 days. We credit reporters who wish to be credited.

## Scope

In scope: anything that lets a party get a secret value, a user key or a grant it should not
have; use a record outside its signed policy; act without a confirmed log entry; or change
the log without `verify` noticing. The parties and assumptions are in
[docs/threat-model.md](docs/threat-model.md).

Out of scope: the residual risks listed there (for example, attacks that need the node to run
outside a TEE), and denial of service by the node operator.

## Supported versions

Until 1.0, only the latest commit of `main` receives fixes.
