from dock import dockerfile,docker_sdk
from docker_start import run_trace
from time import sleep


# container_list is list of containers to be traced
container_list = []
dockerfile.check_docker_compose(container_list)
if not container_list:
    print("container id is not set")
    exit(1)

dockerfile.Create_Container_Test()

# asynchronous processing
container_id = 0
while container_id == 0:
    for name in container_list:
        container_name = name.replace("container_name:", "").strip()
        container_id = docker_sdk.ContainerName_to_ContainerId(container_name)
        if container_id != 0:
            break

# Start syscall trace container and Create Docker container
run_trace.run_tracer(container_id)

# if container is running ,trace syscall when user enter the container
print("please enter the container")
# docker-compose exec -it servece_name

# exec production_dockerfile
#dockerfile.exec_dockerfile_production()


