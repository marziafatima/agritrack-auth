import os

# The host (SnapDeploy) tells the app its port through the PORT variable. We also listen on the usual
# fallback ports, so the health check finds the app whichever of them the host uses.
ports = []
for p in (os.environ.get("PORT"), "8000", "7991", "5000"):
    if p and p not in ports:
        ports.append(p)
bind = [f"0.0.0.0:{p}" for p in ports]
workers = 1
timeout = 60
