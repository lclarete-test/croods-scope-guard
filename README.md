# Croods Scope Guard

A small, MIT-licensed library for Croods authorization scopes. It contains:

1. **Ruby guard:** an opt-in `prepend` patch that scopes the tenant model by ID
   and rejects missing tenant/owner association paths instead of silently
   returning the full query.
2. **Python CLI:** a read-only static audit that generates HTML, Markdown and
   JSON reports, with line links pinned to the scanned git commit. No AI or
   external service is used.

## Audit a checkout

Python 3.9+ required. From this directory:

```sh
python3 -m croods_scope_guard /path/to/croods-rails --report-dir ./report
```

The audit detects source patterns and examines an example Rails schema when
available. It **does not execute Ruby or Rails**, prove an exploit, or establish
that a company uses this dependency in production. A finding's impact depends
on the application's resource associations and role policy.

To add a CI gate for the presence of a risky source pattern, use `--fail-on-risk`.
It returns exit code 2 when a pattern exists; exit 1 means the checkout cannot
be audited. CI gating is optional because existing code will be flagged until
the underlying condition is fixed or reviewed.

The Python scanner has unit tests. The Ruby runtime guard has standalone unit
tests and a GitHub Actions job; integration with a real Rails application
remains to be verified before production use.

## Enforce at runtime

Follow [ruby/README.md](ruby/README.md) to add the Ruby component to a Rails
application. It is opt-in, and this repository is never modified by a scan.

## Recommended proof in a real application

Create two tenants, users and records belonging to each. Request the index,
show, update and destroy routes with a user's token and the other tenant's
record ID. Confirm that these requests do not expose or alter that record;
repeat after adding the runtime guard. Include a specifically authorized
tenant-creation flow if the application supports onboarding.
