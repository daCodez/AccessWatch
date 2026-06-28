# ADR-001: Use SQL Server Light Behind Repository Interfaces

## Status
Accepted

## Date
2026-06-28

## Context
AccessWatch is a local-first Windows security helper. The MVP stores application identities, listening ports, network events, incidents, rules, and trust decisions locally. The product guardrails rule out cloud sync for now, and the Windows Service must continue to run safely as a console/debug worker.

The first foundation used SQLite because it was embedded, fast to start with, and easy to test. We are moving away from SQLite because its native dependency path is producing a vulnerability advisory and we do not want new AccessWatch work to depend on that database stack.

We still want to keep the persistence layer easy to swap because database needs may change as the dashboard, incidents, and rule engine mature. SQL Server LocalDB is convenient for development, while SQL Server Express is a better fit for a service-friendly local install.

Important constraints:

- Do not depend on Windows Event Logs as the main data source.
- Do not add cloud sync.
- Keep service, detection, rules, and UI code independent from concrete database details.
- Preserve local privacy and low operational overhead.
- Keep the repository API small enough to implement against another provider without changing product logic.

## Decision
Use SQL Server as the implemented MVP persistence provider, with LocalDB as the default development and first-run connection target. Keep `IAccessWatchRepository` as the product-facing persistence boundary and keep provider details inside `AccessWatch.Data`.

Future installs can point the same repository implementation at SQL Server Express by changing the connection string. Detection, scoring, notification, service, and UI projects must not take dependencies on SQL Server-specific APIs.

## Alternatives Considered

### SQLite only
- Pros: Embedded, simple install, strong MVP velocity, easy test setup.
- Cons: Current dependency path includes a native SQLite vulnerability advisory; future reporting and migrations may need more care.
- Rejected because AccessWatch should not depend on the vulnerable SQLite native dependency path going forward.

### SQL Server LocalDB only
- Pros: Familiar SQL Server tooling and T-SQL behavior; easy for developer machines.
- Cons: LocalDB is user-profile oriented and can be awkward for a Windows Service running as `LocalSystem` or a dedicated service account.
- Accepted as the default development target, but not as the only install target.

### SQL Server Express only
- Pros: Better fit for a Windows Service than LocalDB and still local.
- Cons: Heavier install and more operational surface than the MVP needs today.
- Accepted as the preferred service-friendly install target once packaging is designed.

### Generic database abstraction
- Pros: Maximum flexibility.
- Cons: Adds architecture weight before the data access surface is stable.
- Rejected for now. Repository interfaces are enough.

## Consequences
- AccessWatch no longer depends on SQLite packages.
- Local developer runs use SQL Server LocalDB by default.
- Service-friendly installs should use SQL Server Express or another SQL Server instance by connection string.
- Future migrations should avoid provider-specific assumptions outside `AccessWatch.Data`.
- Any new data access method must be added to `IAccessWatchRepository` first and covered by tests against the active provider.
