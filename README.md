# Warden

Portal for domain lifecycle monitoring:
- onboard and generate sites
- track health / reputation / categorization
- manage email warmup
- monitor changes over time

## Quick Start

```bash
python3 warden.py setup --start
```

Open:

```text
http://127.0.0.1:5000
```

## Common Commands

```bash
python3 warden.py status
python3 warden.py restart
python3 warden.py stop
python3 warden.py start
python3 warden.py logs --lines 100
python3 warden.py uninstall
```

Foreground run (manual/debug):

```bash
python3 warden.py run --debug
```

Optional setup shortcut:

```bash
python3 setup.py
```

## Basic Use

1. Open **Settings** and add API keys.
2. Pick your email provider for warmup:
   - `Mailjet`
   - `SMTP2GO`
3. Onboard domains and generate sites.
4. Run health / reputation / categorization checks.
5. Use **Email Manager** for warmup sends and scheduling.

## Email Provider Notes

- Warmup sending + scheduling uses the provider selected in **Settings**.
- Mailjet event sync/history is only available when **Mailjet** is the selected provider.
- SMTP2GO currently supports warmup sending via API (provider test included in Settings).

## Data / Credential Storage

Warden stores state in encrypted JSON files (AES-GCM when available):

- `portal/config.json` (API keys + settings)
- `domains.json` (tracked domains)
- `portal/scan_state.json` (scan history/state)
- `portal/email_log.json` (warmup log/state)

Key source order:

1. `WARDEN_MASTER_KEY` environment variable
2. macOS Keychain (`warden.master.key`)
3. `portal/.warden.key` fallback file

Important:

- This protects credentials at rest.
- If the host is fully compromised (user/root access), assume secrets can be extracted because the app must decrypt them to run.

## Backup / Migration

Back up these files together:

```bash
tar -czf warden-backup.tgz \
  domains.json \
  portal/config.json \
  portal/scan_state.json \
  portal/email_log.json \
  portal/.warden.key
```

Restore on another machine:

1. Copy the project.
2. Restore the files above to the same paths.
3. Keep the same key source (`WARDEN_MASTER_KEY` or `portal/.warden.key`).

If the key changes, encrypted data will not decrypt.

## Notes

- Keep Warden bound to localhost unless you intentionally want remote access.
- macOS uses `launchd`; Linux/Windows use Warden’s built-in background service mode.
