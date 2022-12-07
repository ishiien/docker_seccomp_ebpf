from collections import defaultdict

test = defaultdict(list)

pid = [13,58,32]
argv = ["local","etc/pass","os"]

for i in range(0,3):
    test[pid[i]].append(argv[i])

print(test[20])