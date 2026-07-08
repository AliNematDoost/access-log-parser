import re
from collections import Counter
import sys
import math

def parser(path, threshold):
    pattern = r'^(\S+) .*? \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\d+|-)'

    corruptedLines = 0
    correctLines = 0
    totalRequests = 0
    ipSet = set()
    endpointCounter = Counter()
    error = 0
    hourlyCounter = Counter()

    # this is for tracking 401 errors
    maliciousIp = dict()

    # this is for tracking 5xx errors
    internalError = dict()

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
                hour = time.split(':')[1]

                ipSet.add(ip)
                endpointCounter[endpoint] += 1
                hourlyCounter[hour] += 1

                if (statusCode.startswith('4') or statusCode.startswith('5')):
                    error += 1
                    if statusCode == '401' and endpoint == '/login':
                        if ip in maliciousIp:
                            maliciousIp[ip] += 1
                        else:
                            maliciousIp[ip] = 1
                    elif statusCode.startswith('5'):
                        if hour in internalError:
                            internalError[hour] += 1
                        else:
                            internalError[hour] = 1

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
    print(hourlyCounter)

    for hour, count in hourlyCounter.items():
        print(f"Hour: {hour} " + f"  |  Requests count: {count}  |  ")
        print("-------------")

    for ip, count in maliciousIp.items():
        if count > threshold:
            print(f"Ip: {ip} had {count} accesses to login with 401 status code")

    for hour, count in internalError.items():
        if count > 500:
            print(f"hour {hour} has had {count} number of 5xx errors")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Enter the path to file")
    else:
        path = sys.argv[1]

        threshold = 50
        if len(sys.argv) > 2:
            threshold = int(sys.argv[2])

        parser(path, threshold)