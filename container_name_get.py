import docker

def ContainerId_to_ContainerName(container_id):
    client = docker.from_env()
    for c in client.containers.list(all=True,filters={"id": container_id}):
        container_name = c.attrs["Name"]
        print(container_name)

target_container_id = "83833cd94224"
ContainerId_to_ContainerName(target_container_id)
