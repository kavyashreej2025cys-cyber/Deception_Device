# Lab activation policy upgrade

This lab-only policy allows mapped adaptive decoys to activate when:

- current risk score is at least 60;
- model confidence is at least 70%;
- guarded auto-approval is enabled;
- the source belongs to the isolated lab network;
- all existing decoy safety checks pass.

## Install

```bash
cd ~/cyber-deception

cp adaptive/decision_engine.py adaptive/decision_engine.py.before-risk-60
cp adaptive/auto_approver.py adaptive/auto_approver.py.before-risk-60

tar -xzf /media/sf_VM-Shared/cyber-deception-lab-activation-risk60-v1.tar.gz \
  -C ~/cyber-deception

venv/bin/python -m py_compile \
  adaptive/decision_engine.py \
  adaptive/auto_approver.py

sudo cp deploy/systemd/cyber-deception-pipeline.service \
  /etc/systemd/system/cyber-deception-pipeline.service

sudo systemctl daemon-reload
sudo systemctl restart cyber-deception-pipeline.service
```

Existing decisions are audit records and are not rewritten. Generate a new
attack after installation to create a new decision under policy version 1.1.0.
