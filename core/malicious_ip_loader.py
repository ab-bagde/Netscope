malicious_ip = {}
def load_malicious_ip(): 
    global malicious_ip
    with open("database/Malicious_IP_Database.txt", "r") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            ip, threat, severity, source, description = [
                x.strip() for x in line.split("|")
            ]

            malicious_ip[ip] = {
            "threat" : threat,
            "severity" : severity,
            "source" : source,
            "description" : description
            }
    return malicious_ip