# Contributing to WebRecon

Thanks for wanting to help. WebRecon is small on purpose, so the most useful
contributions are usually narrow ones: a new technology fingerprint, a parsing
fix, a rough edge smoothed off.

## Scope

WebRecon owns exactly one step: deciding which open ports serve a web interface
and summarising what is behind them. It is not a port scanner and not a deep web
enumerator — `nmap` and `whatweb`/`ffuf` already do those jobs well.

Changes that widen that scope (adding port scanning, directory brute-forcing,
exploitation) will likely be declined, however well written. Changes that make
the triage step faster, more accurate or more readable are very welcome.

## Ground rules

1. **Stay dependency-light.** `bash` 4+, `curl`, and standard GNU tools. New
   hard dependencies are a hard sell. `openssl` is the model to follow: the
   script detects it, uses it when present, and degrades cleanly when it is not.
2. **Keep it a single file.** `webrecon.sh` being one portable script you can
   `scp` onto a box is a feature, not an accident.
3. **Match the surrounding style.** Lowercase function names, `local` for
   function variables, quoted expansions, existing colour constants.
4. **Run `shellcheck webrecon.sh`** before opening a PR and fix what it flags,
   or say why a warning is a false positive.

## Adding a technology fingerprint

This is the most common contribution and is usually a one-line change. The
fingerprint map lives in `probe_url()`; each entry matches against headers and
body and sets a guess. Add yours alongside the existing ones, keep the match
specific enough not to fire on unrelated services, and mention in the PR which
real service you matched it against.

## Testing

There is no test suite — test by running the tool. Before opening a PR:

- Run against at least one service that **should** match your change and one
  that should **not**, and paste both results in the PR.
- Check that `--quiet`, `--no-color` and `-o report.json` still behave.
- Confirm the script still runs with `openssl` unavailable if you touched the
  TLS path.

**Redact real engagement data.** Scan output pasted into a PR or issue is public
forever. Replace client IPs, hostnames and certificate SANs with lab values or
obvious placeholders. Output from Hack The Box, TryHackMe or your own lab is
fine as-is.

## Pull requests

Fork, branch, and open a PR describing what changed and why. Keep one logical
change per PR — a fingerprint addition and a parser refactor belong in two.

## Legal and ethical use

WebRecon is for authorized testing and education only. Do not use issues, PRs or
discussions to solicit help attacking systems you do not have permission to
test. Contributions that exist mainly to make unauthorized use easier are out of
scope.
