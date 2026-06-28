# AccessWatch MVP Spec

AccessWatch is a Windows security helper focused on learning a user's home network, detecting remote-access risk, watching for new listening ports, resolving the real application behind network activity, storing history in SQLite, and presenting low-noise user guidance.

Core product rule:

Detect everything. Interrupt only when the risk is real.

## Do Not Build

- Do not build antivirus scanning.
- Do not build packet sniffing yet.
- Do not depend on Windows Event Logs for the MVP.
- Do not build OpenAI API integration yet.
- Do not add cloud sync.
- Do not auto-block anything dangerous yet.
- Do not create noisy popups for every event.
- Do not use file names alone in alerts.
- Do not hardcode personal devices, user names, or personal names.

## Phase Scope

Do not attempt the whole product at once.

### Phase 1 Foundation

- Solution structure.
- Shared models and enums.
- SQLite schema.
- Repository layer.
- Windows Service shell that can also run safely as a debug console worker.
- First listening-port scan.
- App identity resolver stub.
- Unit tests for risk scoring.

### Phase 2 New Port Watch

- Detect current listening TCP ports.
- Resolve local address, port number, reachability, and owning process when possible.
- Save detected applications and ports to SQLite.
- Create a `NewListeningPort` event the first time a listening port is seen.

### Phase 3 Smart App Identity

- Resolve process name.
- Resolve full file path when accessible.
- Resolve product name and file description.
- Resolve publisher and signature status when possible.
- Resolve SHA256 hash.
- Never alert using only a file name when richer identity is available.

### Phase 4 Network Familiarization

- Learn current local-network devices.
- Store devices in SQLite.
- Guess device type from hostname, MAC vendor when available, and open-port hints.
- Default new devices to `Unknown`.

### Phase 5 Rule Engine and Incidents

- Score risk.
- Choose low-noise notification actions.
- Group repeated related events into incidents.
- Keep blocking as a safe stub until lockdown behavior is designed.

### Phase 6 Tray Notifications

- Add friendly, low-noise notifications.
- Support future quick actions.
- Do not notify for every event.

### Phase 7 Dashboard

- Add simple pages for overview, devices, applications, ports, incidents, trust decisions, and settings.

### Phase 8 Manual ChatGPT Handoff

- Add redacted manual JSON summaries.
- Do not call OpenAI APIs yet.

## First Task Scope

Build only Phase 1 foundation and the first part of New Port Watch:

1. Create the AccessWatch solution structure.
2. Add shared models and enums.
3. Add SQLite database initialization.
4. Add repository interfaces and basic implementations.
5. Add a Windows Service worker that can also run safely in debug/console mode.
6. Add a listening port scanner service.
7. Resolve owning process ID when possible.
8. Add an `AppIdentityResolver` stub that collects process name, file path, product name, file description, publisher when possible, signature status when possible, and SHA256 hash.
9. Save detected apps and ports to SQLite.
10. Create a `NewListeningPort` event when a new port is first seen.
11. Add simple rule scoring:
    - Local-only trusted/signed app: `Low`.
    - Network-reachable known app: `Medium`.
    - Network-reachable unknown/unsigned app: `High`.
    - High-risk port plus unknown/unsigned app: `High`.
12. Add unit tests for rule scoring.

## Success Criteria

The first version is successful when:

- The solution builds.
- Tests pass.
- SQLite database initializes.
- The service can run as a console/debug worker.
- Current listening ports are detected.
- Owning process is resolved when possible.
- App identity is saved.
- New listening ports create events.

## Sample Scenarios

### Visual Studio Dev Server

Scenario:

Visual Studio opens `127.0.0.1:5173`.

Expected:

Silent log. Low risk.

### Unknown Public Listener

Scenario:

Unknown unsigned app opens `0.0.0.0:4444`.

Expected:

High risk. `AskBeforeAllow`.

### Plex Listener

Scenario:

Trusted Plex app opens `0.0.0.0:32400`.

Expected:

Soft notification first time. Silent log after trusted.

### Microsoft Signed Connection

Scenario:

Known Microsoft signed process connects to a Microsoft endpoint.

Expected:

Low risk. No action needed.

## Coding Rules

Before making changes:

- Run `git status`.
- Inspect existing files.
- Do not wipe work.
- Do not replace large files blindly.
- Make small focused changes.
- Keep public methods documented with XML comments.
- Add clear comments for security logic.
- Summarize changed files at the end.

## Testing Rules

- Run the solution build after code changes.
- Run tests when code behavior changes.
- Keep rule scoring covered by tests.
- Keep SQLite initialization and first-write paths covered by tests.
- Keep the service loop runnable in debug/console mode.

