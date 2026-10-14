# Time-windowed risk scoring upgrade

This upgrade replaces cumulative lifetime scoring with a 15-minute sliding
window. It keeps the highest historical score in `peak_risk_score`, while the
normal `risk_score` represents the current threat.

## Install on Ubuntu

From the project directory, back up the three existing files and then copy the
upgrade over the project:

```bash
cd ~/cyber-deception

cp profiler/risk_score.py profiler/risk_score.py.before-windowed-risk
cp profiler/profile_manager.py profiler/profile_manager.py.before-windowed-risk
cp logger/database.py logger/database.py.before-windowed-risk

tar -xzf /media/sf_VM-Shared/cyber-deception-windowed-risk-v1.tar.gz \
  -C ~/cyber-deception

venv/bin/python -m py_compile \
  profiler/risk_score.py \
  profiler/profile_manager.py \
  logger/database.py

venv/bin/python -c "from logger.database import init_db; init_db()"

sudo systemctl restart cyber-deception-pipeline.service
```

## Verify

Wait for one pipeline cycle, then run:

```bash
journalctl -u cyber-deception-pipeline.service \
  --since "3 minutes ago" --no-pager

python3 - <<'PY'
from logger.database import get_connection

c = get_connection()
for row in c.execute(
    """
    SELECT source_ip, risk_score, risk_bucket,
           peak_risk_score, primary_attack_type, status
    FROM attackers
    ORDER BY risk_score DESC
    """
):
    print(dict(row))
c.close()
PY
```

The default window is 15 minutes. It can be changed with the systemd service
environment variable `DECEPTION_RISK_WINDOW_MINUTES`.
