import subprocess
import yaml


def check_policy():
    with open('../policy/policy.yml') as file:
        display = yaml.safe_load(file)
        policy = display['run_process']
        for container_policy in policy:
            execute = container_policy["container"]["run"]
            for val in execute:
                print(val["value"])

check_policy()

s = subprocess.run("ls",shell=True)