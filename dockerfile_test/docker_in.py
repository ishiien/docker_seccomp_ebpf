import subprocess

s = subprocess.run(["docker-compose","exec","php","/bin/bash"])
a = subprocess.run("exit")