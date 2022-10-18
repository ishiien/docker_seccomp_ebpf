import docker

client = docker.from_env()
containers = client.containers.list()
for c in containers:
    container_id = c.attrs['Id']
    container_name = c.attrs['Name']
    print("{}:{}".format(container_id, container_name))
    process = c.top(ps_args="aux")
    for proc in process['Processes']:
        print(proc)


