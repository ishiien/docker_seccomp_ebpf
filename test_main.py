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

# exec test_dockerfile
dockerfile.exec_dockerfile_test()

# asynchronous processing

# exec production_dockerfile
dockerfile.exec_dockerfile_production()


# start syscall trace containers
#for container in container_list:
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