from dock import dockerfile,docker_sdk
from docker_start import run_trace
from time import sleep

# exec_list is Predefined commands and programs
# container_list is list of containers to be traced
exec_list = []
container_list = []

dockerfile.check_docker_file(exec_list)
dockerfile.check_docker_compose(container_list)

# container name change container id

if not container_list:
    print("container id is not set")
    exit(1)

container_id = 0
while container_id == 0:
    for name in container_list:
        name = name.replace("container_name:", "").strip()
        container_id = docker_sdk.check_container_name(name)

print(container_id)



#run_trace.run_tracer(container_id)

# start syscall trace
#for container in container_list:
#    container_name = container.replace("container_name:","").strip()
#
#    # docker-compose & docker file exec
#    dockerfile.exec_dock_directory()
#
#    # container run syscall trace
#    run_trace.run_tracer(container_name)
#
#    # if container is running , next section # trace syscall when user enter the container
#
#    # exec trace & proc trace
#    execve_trace.execve_syscall_trace(container_name)
#
#    # make production container