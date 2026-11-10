"""Command-line interface:  python -m phishguard <scan|train|gen-data|serve>"""
import argparse
import json
import logging
import os
import sys
import time

from . import __version__
from .analyzer import analyze, format_report
from .ml_model import DEFAULT_MODEL, load_model, train


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishguard", description="Email security gateway with phishing detection")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan one or more .eml files")
    s.add_argument("files", nargs="+")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.add_argument("--live-dns", action="store_true", help="query SPF/DMARC records of sender domain")
    s.add_argument("--verify-dkim", action="store_true", help="cryptographically verify DKIM signature")
    s.add_argument("--no-ml", action="store_true", help="disable ML classifier")
    s.add_argument("--vt", action="store_true", help="use VirusTotal (needs VT_API_KEY env var)")

    t = sub.add_parser("train", help="train the ML classifier from a CSV (columns: text,label)")
    t.add_argument("--data", default="data/training_data.csv")
    t.add_argument("--model", default=DEFAULT_MODEL)

    g = sub.add_parser("gen-data", help="generate synthetic demo training data")
    g.add_argument("--out", default="data/training_data.csv")
    g.add_argument("--n", type=int, default=600, help="samples per class")

    v = sub.add_parser("serve", help="run the SMTP gateway")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8025)
    v.add_argument("--relay", help="downstream SMTP host:port for clean mail (omit to only analyse)")
    v.add_argument("--live-dns", action="store_true")
    v.add_argument("--vt", action="store_true")
    v.add_argument("--quarantine", default="quarantine")

    a = ap.parse_args(argv)

    if a.cmd == "gen-data":
        from .dataset import write_csv
        print(f"Wrote {write_csv(a.out, a.n)} rows to {a.out}")
        return 0
    if a.cmd == "train":
        print(json.dumps(train(a.data, a.model), indent=2))
        return 0

    model = None if getattr(a, "no_ml", False) else load_model()
    vt_key = os.environ.get("VT_API_KEY", "") if getattr(a, "vt", False) else ""
    if getattr(a, "vt", False) and not vt_key:
        print("warning: --vt given but VT_API_KEY is not set; skipping VirusTotal", file=sys.stderr)

    if a.cmd == "scan":
        rc = 0
        for path in a.files:
            with open(path, "rb") as fh:
                r = analyze(fh.read(), model=model, live_dns=a.live_dns,
                            verify_dkim_sig=a.verify_dkim, vt_key=vt_key)
            print(json.dumps(r.to_dict(), indent=2) if a.json else f"== {path}\n{format_report(r)}\n")
            rc = max(rc, {"clean": 0, "suspicious": 1, "malicious": 2}[r.verdict])
        return rc

    if a.cmd == "serve":
        from .gateway import run_gateway
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        ctrl = run_gateway(a.host, a.port, model=model, relay=a.relay, live_dns=a.live_dns,
                           vt_key=vt_key, quarantine_dir=a.quarantine)
        print(f"PhishGuard gateway running on {a.host}:{a.port} (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            ctrl.stop()
        return 0


if __name__ == "__main__":
    sys.exit(main())
