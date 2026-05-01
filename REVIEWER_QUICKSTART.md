# Black-X-Templar — reviewer quick start (~5 minutes)

## 1. One-command setup
```bash
python -m venv .venv && .venv\Scripts\activate && pip install -r requirements.txt -r requirements-demo.txt
```

## 2. Run the full demo (offline-first)
```bash
python preseed_ioc_cache.py --input sample_ioc_seed.json --clear
python _smoke_v2.py
streamlit run app.py
```

## 3. Key things to test immediately

- ThreatFox tab → should show cached IOCs (offline mode)
- Kinetic Hooks tab → run "Response Cycle" in Dry-Run mode
- Red-Team Mirror tab → extended corpus (220/220)
- Prometheus exporter: `python export_security_metrics_prometheus.py --port 9109`

## 4. What success looks like

- Smoke suite = PASS
- Neural Mirror = 220/220 correct
- No medium/high Bandit or Semgrep findings
- All logs signed with HMAC

Questions or issues? Open an issue or email the maintainer.
