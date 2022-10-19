import subprocess

s = subprocess.run("sudo docker run -it --name nginx_seccomp --security-opt='seccomp=seccomp.json' nginx /bin/bash",shell=True)