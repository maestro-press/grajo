"""One-off generator (controller): builds a P1-schema (v1) engine DB with the base commit 931329eb1 Store code. Valid only at that commit: after the v2 migration Store creates v2 files, so this script is kept as provenance, never re-run."""
import sys
from decimal import Decimal as D
from pathlib import Path
out = Path(sys.argv[1])
if out.exists():
    out.unlink()
from crow_coinbase.store import Store
s = Store(out)
assert s.schema_version() == 1
s.create_bot("g1", "BTC-USDC", "grid", {"levels": 4}, D("50"), D("0"))
s.create_bot("r1", "ETH-USDC", "rebalance", {"target": "0.5"}, D("30"), D("0.01"))
s.insert_order("cb-g1-B-1-000000000001", "g1", "bot", "BTC-USDC", "BUY", 1, D("60000"), D("0.0005"), status="OPEN", order_id="ex-1", product_type="SPOT")
s.insert_order("cb-g1-S-2-000000000002", "g1", "bot", "BTC-USDC", "SELL", 2, D("61000"), D("0.0005"), status="FILLED", order_id="ex-2", product_type="SPOT")
s.insert_order("cb-ai-B-1-000000000003", "ai", "ai", "ETH-USDC", "BUY", 0, D("3000"), D("0.005"), status="CANCELLED", order_id="ex-3", product_type="SPOT")
s.record_fill({"trade_id": "t-1", "order_id": "ex-2", "side": "SELL", "size": "0.0005", "price": "61000", "commission": "0.15", "trade_time": "2026-11-01T12:00:00Z", "trade_type": "FILL"}, "cb-g1-S-2-000000000002")
s.update_hwm("g1", D("50.5")); s.update_hwm("ai", D("25")); s.update_hwm("portfolio", D("120"))
s.put("halted", False); s.put("poll_seconds", 60)
for i, (lvl, msg) in enumerate([("info", "engine started"), ("warn", "stale data"), ("info", "bot g1 placed 2 orders")]):
    s.event(lvl, msg)
s.close()
