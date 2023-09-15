import nmap
import time
import csv
import os
import sys
from requests import get, head
from json import loads

#########################

colors = {
    "red" : '\033[91m',
    "green" : '\033[92m',
    "blue" : '\033[94m',
    "yellow" : '\033[93m',
    "white" : '\033[0m',
    "cyan" : '\033[96m'
}

#########################

print(colors["green"] + r' __  __  ___' + colors["cyan"] + r'__     _____' + colors["green"] + r'                     _____')
print(r'|  \/  |/ _' + colors["cyan"] + r'___|   / ____|' + colors["green"] + r'                   / ____|')
print(r'| \  / | |' + colors["cyan"] + r'       | (___   ___ _ ____   __' + colors["green"] + r'  | (___   ___ __ _ _ __')
print(r"| |\/| | |" + colors["cyan"] + r"        \___ \ / _ \ '__\ \ / /" + colors["green"] + r"   \___ \ / __/ _` | '_ \ ")
print(r'| |  | | |_' + colors["cyan"] + r'___    ____) |  __/ |   \ V /' + colors["green"] + r'    ____) | (_| (_| | | | |')
print(r'|_|  |_|\___' + colors["cyan"] + r'__|  |_____/ \___|_|    \_/' + colors["green"] + r'    |_____/ \___\__,_|_| |_|')

#########################

if len(sys.argv) > 1 and sys.argv[1] == "-setup":
    print("\n" + "-"*20 + "\nInstalling all necessary libriaries: ")
    os.system("pip3 install python-nmap")
    os.system("pip3 install requests")
    print("\n" + "-"*20 + "\nSuccessfully installed!")
    exit(0)

#########################

if not os.path.exists("results"):
    os.mkdir("results")

#########################

print("\n" + colors["cyan"] + "-"*20 + colors["yellow"] + "\nType server address: " + colors["white"])
addr = input("> ").strip()

print("\n" + colors["cyan"] + "-"*20 + colors["yellow"] + "\nSpecify PORT range [min-max]. \nPress ENTER to continue with default range (10000-60000)." + colors["white"])
ports = input("> ").strip()

print("\n" + colors["cyan"] + "-"*20 + colors["yellow"] + "\nDo you want to create also .txt file with scan results (.csv file is created automatically)? [Y/N]" + colors["white"])
user_choice = input("> ").strip()

txt_create = True
if user_choice == "" or user_choice.upper() == "N":
    txt_create = False

if ports == "":
    ports = "10000-60000"

try:
    test = head(f"http://{addr}")
except:
    print(colors["red"] + 'WRONG SERVER ADDRESS!' + colors["white"])
    exit(0)

print("\n" + colors["cyan"]  + "-"*20 + colors["red"] + f"\n\nTARGET ->" + colors["white"] + f" {addr}\n" + "\n" + colors["cyan"] + "-"*20 + "\n")

#########################

print(colors["yellow"] + f"[{time.strftime('%H:%M:%S', time.localtime())}] Scan started...\n" + colors["white"])

start = time.time()

scanner = nmap.PortScanner()

scanner.scan(str(addr), ports)

print(colors["yellow"] + f"Scanned successfully in: {time.time() - start} seconds. \n" + colors["cyan"] + "\n" + "-"*20 + colors["white"])

#########################

if os.path.exists(f"results/{addr}.csv"):
    os.remove(f"results/{addr}.csv")


if txt_create == True:
    if os.path.exists(f"results/{addr}.txt") :
        os.remove(f"results/{addr}.txt")
    txt_file = open(f"results/{addr}.txt", 'w')
    txt_file.write(f"{time.strftime('%H:%M:%S', time.localtime())}\n")

with open(f"results/{addr}.csv", "w", newline="") as csv_file:

    writer = csv.DictWriter(csv_file, fieldnames=['ADDRESS', 'PORT', 'VERSION', 'ONLINE_PLAYERS', 'MAX_PLAYERS', 'SOFTWARE', 'PLUGINS', 'MOTD'])
    writer.writeheader()

    row = {
        "ADDRESS" : "",
        "PORT" : "",
        "VERSION" : "",
        "ONLINE_PLAYERS" : 0,
        "MAX_PLAYERS" : 0,
        "SOFTWARE" : "",
        "PLUGINS" : [],
        "MOTD" : []
    }

    for port in scanner[scanner.all_hosts()[0]]["tcp"].keys():
        if scanner[scanner.all_hosts()[0]]["tcp"][port]['state'] == "open" and port % 5 == 0:

            url = fr"https://api.mcsrvstat.us/3/{addr}:{str(port)}"
            data = loads(get(url).text)
            plugins = f""
            my_motd = f""

            row["ADDRESS"] = data['ip']
            row["PORT"] = data['port']

            try:
                version = f"{data['version']}"
                row["VERSION"] = version
            except KeyError:
                version = "NO DATA"
                row['VERSION'] = "NO DATA"

            try:
                players = colors["blue"] + f" ONLINE:" + colors["white"] + f" {data['players']['online']} |" + colors["blue"] + f" MAX:" + colors["white"] + f" {data['players']['max']}"
                row["ONLINE_PLAYERS"] = data['players']['online']
                row["MAX_PLAYERS"] = data['players']['max']
            except KeyError:
                players = "PLAYER LIST HIDDEN"
                row["ONLINE_PLAYERS"] = "HIDDEN"
                row["MAX_PLAYERS"] = "HIDDEN"

            try:
                software = f"{data['software']}"
                row["SOFTWARE"] = software
            except KeyError:
                software = "NO DATA"
                row["SOFTWARE"] = "NO DATA"

            try:
                for plugin in data['plugins']:
                    plugins += f"\n|  | {plugin['name']} v{plugin['version']}"
                row["PLUGINS"] = data['plugins']
            except KeyError:
                plugins += "\n|  | NO PLUGINS"
                row["PLUGINS"] = "NO DATA"

            try:
                for motd in data['motd']['clean']:
                    my_motd += f"\n|  | {motd}"
                row["MOTD"] = data['motd']['clean']
            except KeyError:
                my_motd += "\n|  | NO MOTD"
                row["MOTD"] = "NO DATA"

            print("\n" + colors["red"] + f"{data['ip']}:{data['port']}" + colors["white"] + f"\n|" + colors["blue"] + f"  VERSION: " + colors["white"] + f"{version} \n|" + f" {players}" +  f"\n|" + colors["blue"] + f"  SOFTWARE: {software}" + colors["white"] + f"\n|" + colors["blue"] + f"  PLUGINS:" + colors["white"] + f"{plugins} \n|" + colors["blue"] + f"  MOTD:" + colors["white"] + f"{my_motd}" + colors["cyan"] + "\n\n----------------------" + colors["white"])

            if txt_create == True:
                txt_file.write("\n" + f"{data['ip']}:{data['port']} \n|  VERSION: {version} \n|  {players} \n|  SOFTWARE: {software} \n|  PLUGINS:{plugins} \n|  MOTD: {my_motd} \n\n----------------------\n")

            writer.writerow(row)

txt_file.close()

#########################
