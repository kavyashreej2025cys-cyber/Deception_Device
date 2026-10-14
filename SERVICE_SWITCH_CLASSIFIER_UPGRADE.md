# Latest-service classifier upgrade

This upgrade prevents an older attack type from dominating a newer service
target. The live classifier now:

- reads only events newer than the last completed prediction;
- detects the newest contiguous target-service segment;
- waits for five events from that service before classifying;
- excludes older-service events from the new feature vector;
- retains all raw events and historical predictions for investigation.

## Install on Ubuntu

```bash
cd ~/cyber-deception

cp ai/classifier_service.py ai/classifier_service.py.before-service-switch

tar -xzf /media/sf_VM-Shared/cyber-deception-service-switch-v1.tar.gz \
  -C ~/cyber-deception

venv/bin/python -m py_compile ai/classifier_service.py

sudo cp deploy/systemd/cyber-deception-pipeline.service \
  /etc/systemd/system/cyber-deception-pipeline.service

sudo systemctl daemon-reload
sudo systemctl restart cyber-deception-pipeline.service
```

After installation, generate at least five interactions against the newly
targeted service. Existing prediction rows remain unchanged as audit history.
