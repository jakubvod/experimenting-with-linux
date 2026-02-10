import sys
import os
import re


def prepare_result(possible_breaches: dict[str, dict[str, list[str | int]]]) -> str:
    result: str = "\nRESULTS\n\n"
    result += "POSSIBLE BREACHES (SSH):\n"

    for ip, data in possible_breaches["SSH"].items():
        # data = [date, time, username, attempts]
        result += f"IP: {ip} | USERNAME: {data[2]} | ATTEMPTS: {data[3]} | TIME: {data[1]} | DATE: {data[0]}\n" 
    result += "\nPOSSIBLE BREACHES (SUDO):\n"
    for username, data in possible_breaches["SUDO"].items():
         # data = [date, time, command, attempts]
        result += f"USERNAME: {username} | COMMAND: {data[2]} | ATTEMPTS: {data[3]} | TIME: {data[1]} | DATE: {data[0]}\n"
    return result

def analyzer(filename: str) -> None:
    if not os.path.isfile(filename):
        print(f"File '{filename}' doesn't exist or it's not a file.")
        return

    possible_breaches: dict[str, dict[str, list[str | int]]] = {"SSH": {}, "SUDO": {}}
    # EXAMPLE: 2026-02-10T22:15:51.181649+01:00 jacob-DEVICENAME sshd[9959]: Failed password for jacob from IP_ADRESS port PORT ssh2
    ssh_pattern: str = r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*Failed password for\s+(\w+)\s+from\s+([\d.]*)"
    # EXAMPLE: 2026-02-10T22:06:24.299263+01:00 jacob-DEVICENAME sudo: jacob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/jacob/Desktop/script ; USER=root ; COMMAND=/usr/bin/ls
    sudo_pattern: str = r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*sudo:\s+(\w+)\s+:\s+(\d+)\s+incorrect password attempts.*COMMAND=(.*)$"
 
    try:
        with open(filename, "r") as log_file:
            for line in log_file:
                ssh_match = re.search(ssh_pattern, line)
                sudo_match = re.search(sudo_pattern, line)
                
                if ssh_match:
                    date = ssh_match.group(1)
                    time = ssh_match.group(2)
                    username = ssh_match.group(3)
                    ip = ssh_match.group(4)

                    if ip in possible_breaches["SSH"]:
                        possible_breaches["SSH"][ip][3] += 1 # Invalid attempt
                    else:
                        possible_breaches["SSH"][ip] = [date, time, username, 1]     
                    
                elif sudo_match:
                    date = sudo_match.group(1)
                    time = sudo_match.group(2)
                    username = sudo_match.group(3)
                    all_attempts = sudo_match.group(4)
                    command = sudo_match.group(5)
                    
                    if username in possible_breaches["SUDO"]:
                        possible_breaches["SUDO"][username][3] += int(all_attempts) # Invalid attempt
                    else:
                        possible_breaches["SUDO"][username] = [date, time, command, int(all_attempts)]
    except Exception as e:
        print(f"Error during reading: {e}")
        return
        
        
    result_string = prepare_result(possible_breaches)
    
    try:
        with open("log_results.txt", "w") as result_file:
            result_file.write(result_string)
    except Exception as e:
        print(f"Error during writing: {e}") 
    return

if __name__ == "__main__":
    if len(sys.argv) == 2:
        analyzer(sys.argv[1])
    else:
        print("Too few arguments.")