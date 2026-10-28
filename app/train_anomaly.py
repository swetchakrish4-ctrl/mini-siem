"""Train the optional IsolationForest on your stored successful logins.

    python -m app.train_anomaly            # uses the last 60 days
Run the simulator's  --history  mode first if you have no real data yet. Restart run.py afterwards."""
import argparse
import os
from datetime import timedelta

import joblib
from sqlalchemy import select

from .config import settings
from .db import SessionLocal
from .det_ml import LoginBaseline, train_isolation_forest
from .models import Event
from .parse_common import utcnow


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=60)
    args = ap.parse_args()
    with SessionLocal() as db:
        rows = db.execute(select(Event.user, Event.ts, Event.src_ip, Event.host).where(
            Event.event_type == "login_success", Event.user.is_not(None),
            Event.ts >= utcnow() - timedelta(days=args.days)).order_by(Event.ts)).all()
    print(f"{len(rows)} successful logins found")
    model = train_isolation_forest(rows, LoginBaseline(settings.ml_min_history, settings.local_utc_offset_minutes))
    os.makedirs(os.path.dirname(settings.ml_model_path), exist_ok=True)
    joblib.dump(model, settings.ml_model_path)
    print("model saved to", settings.ml_model_path, "- restart the server to load it")


if __name__ == "__main__":
    main()
