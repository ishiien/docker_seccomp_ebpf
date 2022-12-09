from dock import dockerfile,docker_sdk
from docker_start import run_trace
from time import sleep
import subprocess

# container_list is list of containers to be traced
container_list = []
dockerfile.Check_Docker_Compose(container_list)
if not container_list:
    print("container id is not set")
    exit(1)

#Create Docker container
print("container create now")
dockerfile.Create_Container_Test()

# asynchronous processing
container_id = 0
while container_id == 0:
    for name in container_list:
        container_name = name.replace("container_name:", "").strip()
        container_id = docker_sdk.ContainerName_to_ContainerId(container_name)
        if container_id != 0:
            break
print("contaier_id get now")

# Start syscall trace container and Enter the container
print("container trace start")
run_trace.run_tracer(container_id)

a = subprocess.run(["mv","./seccomp.json","./dockerfile_production"])

#exec production_dockerfile
dockerfile.Exec_Dockerfile_Production()


