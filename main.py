import re
from collections import Counter
import sys
import math
import gzip
import json

def parser(path, threshold, repotType):
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

    openType = open
    mode = 'r'
    if path.endswith('.gz'):
        openType = gzip.open
        mode = 'rt'
    
    with openType(path, mode) as file:
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

    if reportType == 'text':
        print()
        print(f"- Total corrupted lines: {corruptedLines}")
        print("-----------------------------------------------------")
        print(f"- Total requests: {totalRequests}")
        print("-----------------------------------------------------")
        print(f"- Unique IPs: {len(ipSet)}")
        print("-----------------------------------------------------")
        print(f"- Endpoint counts: {endpointCounter.most_common(10)}")
        print("-----------------------------------------------------")
        print(f"- Error requests: {error}")
        print("-----------------------------------------------------")
        print(f"- Correct lines: {correctLines}")
        
        errorRate = 0
        if correctLines > 0:
            errorRate = error / correctLines * 100
        print(f"- Error Rate is {errorRate:.2f}")
        
        print(hourlyCounter)
        print("-----------------------------------------------------")

        for hour, count in hourlyCounter.items():
            print(f"- Hour: {hour} " + f"  |  Requests count: {count}  |  ")
            print("--------------------")
        print("-----------------------------------------------------")

        for ip, count in maliciousIp.items():
            if count > threshold:
                print(f"- Ip: {ip} had {count} accesses to login with 401 status code")
        print("-----------------------------------------------------")

        # TODO : not having 5xx error for an hour
        lastRate = internalError.get("00")
        for hour, count in internalError.items():
            dif = count - lastRate
            if dif > 500:
                print(f"- Error rate in hour {hour} jumped by {dif} and reached {count} 5xx errors")
            lastRate = count
    else:
        # TODO: complete the json format
        report = {
            "requests": totalRequests,
            "corrupted": corruptedLines,
            "unique_ips": len(ipSet),
            "top_endpoints": endpointCounter.most_common(10),
            "error_rate": errorRate,
            # "hourly_congestion": hou
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Enter the path to file")
    else:
        path = sys.argv[1]

        threshold = 50
        if len(sys.argv) > 2:
            threshold = int(sys.argv[2])

        reportType = 'text'
        if "--json" in sys.argv:
            reportType = 'json'

        parser(path, threshold, reportType)