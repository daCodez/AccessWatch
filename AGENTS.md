# AccessWatch Agent Rules

Use these rules for all Codex work in this repository.

## Product Guardrails

- Do not build antivirus scanning.
- Do not build packet sniffing yet.
- Do not depend on Windows Event Logs for the MVP.
- Do not build OpenAI API integration yet.
- Do not add cloud sync.
- Do not auto-block anything dangerous yet.
- Do not create noisy popups for every event.
- Do not use file names alone in alerts.
- Do not hardcode personal devices, user names, or personal names.

## Build Order

Work one phase at a time:

1. Foundation and database.
2. New Port Watch.
3. Smart App Identity.
4. Network Familiarization.
5. Rule engine and incidents.
6. Tray notifications.
7. Dashboard.
8. Manual ChatGPT handoff.

Read `accesswatch_mvp_spec.md` before starting feature work.

## Working Rules

- Run `git status` before and after changes.
- Inspect existing files before editing.
- Do not wipe or replace existing work.
- Do not replace large files blindly.
- Make small focused changes.
- Keep public methods documented with XML comments.
- Add clear comments where security or risk logic is not obvious.
- Run the relevant build and tests for code changes.
- Summarize what changed, how to run it, what is stubbed, and the next recommended step.

## MVP Success Checks

The current MVP foundation should continue to satisfy:

- Solution builds.
- Tests pass.
- SQL Server database initializes.
- Service runs as a console/debug worker.
- Current listening ports are detected.
- Owning process is resolved when possible.
- App identity is saved.
- New listening ports create events.

