# Prompt Injection Radar — Vigil Repo-Powered Experience

A repo-powered Frontier Experience using the cloned upstream repository `deadbits/vigil-llm` as the capability engine.

## How it works

1. Clone upstream Vigil repo to `~/code/frontier-repo-experiences/vigil-llm`.
2. Compile Vigil's `data/yara/*.yar` prompt-injection signatures.
3. Scan curated prompt scenarios.
4. Export `public/vigil-results.json`.
5. Render the results in a static cloud experience.

## Generate data

```bash
cd ~/code/prompt-injection-vigil-experience
VIGIL_REPO=~/code/frontier-repo-experiences/vigil-llm ../frontier-repo-experiences/vigil-llm/.venv/bin/python scripts/run_vigil_scan.py
python3 -m http.server 8790
```

Boundary: v0 uses Vigil YARA signatures offline. It is not yet a live user-input backend.
