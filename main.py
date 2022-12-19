from docker_sdk import dockerfile,docker_sdk
from docker_start import run_trace
from time import sleep
import subprocess

# container_list is list of containers to be traced
container_name_list = []
command_list = []
dockerfile.Check_Docker_Compose(container_name_list)
#dockerfile.Check_Docker_Compose_CMD(command_list)

if not container_name_list:
    print("container id is not set")
    exit(1)

#Create Docker container
print("container create now")
dockerfile.Create_Container_Test()

# asynchronous processing
container_id_list = []
list_length = len(container_name_list)
count_length = 0
container_id = 0
while list_length > count_length:
    for container_name in container_name_list:
        container_id = docker_sdk.ContainerName_to_ContainerId(container_name)
        if container_id != 0 and container_id not in container_id_list:
            container_id_list.append(container_id)
            count_length = count_length + 1

container_name_arg = 0
for container_id in container_id_list:
    dockerfile.Check_Exec_Command(container_id,container_name_list[container_name_arg],command_list)
    container_name_arg = container_name_arg + 1


print("container trace start")
container_count = 0

container_command_list = []

for container_id in container_id_list:
    container_name = container_name_list[container_count]
    run_trace.run_tracer(container_id,container_name,command_list)
    container_count = container_count + 1
    print("container trace done","container_id: %s" % (container_id))

## json find and move production
for container_name in container_name_list:
    main_cmd = "mv"
    target_file = container_name + "." + "json"
    target_dir = "./dockerfile_production"
    a = subprocess.run([main_cmd,target_file,target_dir])

dockerfile.Down_Dockerfile_Test()
dockerfile.Exec_Dockerfile_Production()



