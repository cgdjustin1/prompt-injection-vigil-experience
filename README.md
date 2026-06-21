# Frontier Agent — Repo-Powered Minimum Experience

This project is the first concrete example of a broader **Frontier Agent** positioning:

> For people who want to understand the world's newest AI / GitHub / paper / product signals, and use them immediately with the lowest possible setup cost.

The user is not buying a GitHub link or a tutorial. They are buying the compression:

```text
frontier signal
→ cloned / verified repo capability
→ minimum usable experience
→ downloadable artifact
→ optional deeper path
```

Current example: **Prompt Injection Audit Report** powered by the cloned upstream repository `deadbits/vigil-llm`.

## Target user

- People who want to keep up with the latest AI frontier without spending hours reading papers or configuring repos.
- Founders / builders / investors / creators who need to judge whether a new AI project is actually useful.
- Users who want a 30-minute hands-on experience, not a passive news summary.
- Teams that want output artifacts: reports, CSVs, JSON, dashboards, saved workspaces.

## How this example works

1. Clone upstream Vigil repo to `~/code/frontier-repo-experiences/vigil-llm`.
2. Compile Vigil's `data/yara/*.yar` prompt-injection signatures.
3. Scan a curated corpus of prompt / RAG / tool-instruction assets.
4. Export:
   - `public/vigil-results.json`
   - `public/vigil-audit-summary.csv`
5. Render the results in a static cloud experience.

## Generate data

```bash
cd ~/code/prompt-injection-vigil-experience
VIGIL_REPO=~/code/frontier-repo-experiences/vigil-llm ../frontier-repo-experiences/vigil-llm/.venv/bin/python scripts/run_vigil_scan.py
python3 -m http.server 8790
```

## Boundary

This v0 uses Vigil YARA signatures offline. It is not yet a live user-input backend.

Accurate label:

```text
repo-powered static experience = real upstream capability ran at build time
```

Not yet:

```text
live custom upload workspace / realtime API / saved team reports
```
