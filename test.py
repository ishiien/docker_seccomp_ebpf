from docker_sdk import dockerfile,docker_sdk
from docker_start import run_trace
from time import sleep
import subprocess

# container_list is list of containers to be traced
container_name_list = []
container_command_list = []
command_list = {}
get_command_list = {}
container_id_list = []
dockerfile.Check_Docker_Compose(container_name_list)
#dockerfile.Check_Docker_Compose_CMD(command_list)

if not container_name_list:
    print("container id is not set")
    exit(1)
#Create Docker container
print("container create now")
dockerfile.Create_Container_Test()

# asynchronous processing
list_length = len(container_name_list)
count_length = 0
container_id = 0
while list_length > count_length:
    for container_name in container_name_list:
        container_id = docker_sdk.ContainerName_to_ContainerId(container_name)
        if container_id != 0 and container_id not in container_id_list:
            container_id_list.append(container_id)
            count_length = count_length + 1











