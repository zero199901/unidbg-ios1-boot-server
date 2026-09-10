# Local artifacts

`artifacts/` contains local runtime output: logs, crash reports, request samples,
analysis results, and backups. Its contents are ignored by default because they can
contain sensitive capture data and do not belong in the source history.

Promote only a reviewed, sanitized, reproducible result into `docs/` or an
appropriate versioned test fixture.
