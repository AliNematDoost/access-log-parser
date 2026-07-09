import re
from collections import Counter
import argparse
import gzip
import json

def parser(path, tLogin, tError, topN, endInSec, reportType):
    pattern = r'^(\S+) .*? \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "(\S+) (\S+) \S+" (\d+) (\d+|-)'

    corruptedLines = 0
    correctLines = 0
    totalRequests = 0
    errorRate = 0
    ipSet = set()
    endpointCounter = Counter()
    error = 0
    hourlyCounter = Counter()

    # this is for tracking 401 errors
    maliciousIp = Counter()

    # this is for tracking 5xx errors
    internalError = Counter()

    openType = open
    mode = 'r'
    if path.endswith('.gz'):
        openType = gzip.open
        mode = 'rt'
    
    with openType(path, mode) as file:
        for line in file:
            try:
                match = re.match(pattern, line)
                if not match:
                    raise ValueError("corrupted line")
                
                ip = match.group(1)
                time = match.group(2)
                endpoint = match.group(4)
                statusCode = match.group(5)

                timeParts = time.split(':')
                hour = timeParts[1]
                minute = timeParts[2]
                second = timeParts[3].split()[0]

                currentTimeInSec = int(second) + int(minute) * 60 + int(hour) * 3600
                if currentTimeInSec >= endInSec:
                    break

                totalRequests += 1
                correctLines += 1
                ipSet.add(ip)
                endpointCounter[endpoint] += 1
                hourlyCounter[hour] += 1

                if (statusCode.startswith('4') or statusCode.startswith('5')):
                    error += 1
                    if statusCode == '401' and endpoint == '/login':
                        maliciousIp[ip] += 1
                    elif statusCode.startswith('5'):
                        internalError[hour] += 1

            except Exception:
                totalRequests += 1
                corruptedLines += 1
                continue

    if correctLines > 0:
        errorRate = f"{error / correctLines * 100:.2f}"

    spikes = dict()
    for hour, count in internalError.items():
        if count > tError:
            spikes[hour] = count


    if reportType == 'text':
        print()
        print(f"- Total corrupted lines: {corruptedLines}")
        print("-----------------------------------------------------")
        print(f"- Total requests: {totalRequests}")
        print("-----------------------------------------------------")
        print(f"- Unique IPs: {len(ipSet)}")
        print("-----------------------------------------------------")
        
        print("endpoint" + 42 * " " + "usage")
        print("--------" + 42 * " " + "-----")
        for endpoint, count in endpointCounter.most_common(topN):
            print(endpoint + " " * (50 - len(endpoint)) + str(count))
            
        print("-----------------------------------------------------")
        print(f"- Error requests: {error}")
        print("-----------------------------------------------------")
        print(f"- Correct lines: {correctLines}")
        print("-----------------------------------------------------")
        print(f"- Error Rate is {errorRate}")
        print("-----------------------------------------------------")

        for hour, count in hourlyCounter.items():
            print(f"- Hour: {hour} " + f"  |  Requests count: {count}  |  ")
        print("-----------------------------------------------------")

        for ip, count in maliciousIp.items():
            if count > tLogin:
                print(f"- Ip: {ip} had {count} accesses to login with 401 status code")
        print("-----------------------------------------------------")

        for hour, count in spikes.items():
            print(f"- Error rate in hour {hour} spiked and reached {count} 5xx errors")

    else:
        report = {
            "requests": totalRequests,
            "corrupted": corruptedLines,
            "unique_ips": len(ipSet),
            "top_endpoints": endpointCounter.most_common(topN),
            "error_rate": errorRate,
            "hourly_congestion": {
                hour: count for hour, count in hourlyCounter.items()
            },
            "malicious_IP": {
                ip: count for ip, count in maliciousIp.items() if count > tLogin
            },
            "5xx_spikes": {
                hour: count for hour, count in spikes.items()
            }
        }
        
        jsonOutput = json.dumps(report, indent=4)
        print(jsonOutput)


if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description="access log parser")
    argParser.add_argument("path", help="path to log file (.log or .gz file)")
    argParser.add_argument("--tl", type=int, default=50, help="threshold for malicious 401 errors on login page")
    argParser.add_argument("--te", type=int, default=500, help="threshold for spikes in 5xx errors in an specific hour.")
    argParser.add_argument("--json", action="store_true", help="type of report would be json if this flag appears")
    argParser.add_argument("--top", type=int, default=10, help="show only top n endpoints")
    argParser.add_argument("--time", type=str, default="24:00:00", help="logs after this hour:minute will not be processed")

    args = argParser.parse_args()
    reportType = 'json' if args.json else 'text'

    endTime = args.time
    endHour = int(endTime.split(':')[0])
    endMinute = int(endTime.split(':')[1])
    endSecond = int(endTime.split(':')[2])
    totalEndInSec = endSecond + endMinute * 60 + endHour * 3600

    parser(args.path, args.tl, args.te, args.top, totalEndInSec, reportType)