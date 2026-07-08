import re
from collections import Counter
import sys

def parser(path):
    pattern = r'^(\S+) .*? \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\d+|-)'

    corruptedLines = 0
    correctLines = 0
    totalRequests = 0
    ipSet = set()
    endpointCounter = Counter()
    error = 0

    with open(path, 'r') as file:
        for line in file:
            try:
                match = re.match(pattern, line)
                totalRequests += 1

                if not match:
                    raise ValueError("corrupted line")
                
                correctLines += 1
                ip = match.group(1)
                time = match.group(2)
                method = match.group(3)
                endpoint = match.group(4)
                statusCode = match.group(5)
                sizeInBytes = match.group(6)

                ipSet.add(ip)
                endpointCounter[endpoint] += 1

                if (statusCode.startswith('4') or statusCode.startswith('5')):
                    error += 1

            except ValueError:
                corruptedLines += 1
                continue

    print(f"Total corrupted lines: {corruptedLines}")
    print(f"Total requests: {totalRequests}")
    print(f"Unique IPs: {len(ipSet)}")
    print(f"Endpoint counts: {endpointCounter.most_common(2)}")
    print(f"Error requests: {error}")
    print(f"Correct lines: {correctLines}")
    if correctLines > 0:
        print(f"Error rate: {error / correctLines * 100:.2f}%")
    else:
        print("Error rate: 0.00%")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Enter the path to file")
    else:
        path = sys.argv[1]
        parser(path)