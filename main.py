import nmap
import time
import csv
import os
from requests import get, head
from json import loads

#########################

print(r"""
  __  __ _____ _   _ ______ _____ _____            ______ _______
 |  \/  |_   _| \ | |  ____/ ____|  __ \     /\   |  ____|__   __|
 | \  / | | | |  \| | |__ | |    | |__) |   /  \  | |__     | |
 | |\/| | | | | . ` |  __|| |    |  _  /   / /\ \ |  __|    | |
 | |  | |_| |_| |\  | |___| |____| | \ \  / ____ \| |       | |
 |_|  |_|_____|_| \_|______\_____|_|  \_\/_/    \_\_|       |_|

   _____  _____          _   _ _   _ ______ _____
  / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \
 | (___ | |       /  \  |  \| |  \| | |__  | |__) |
  \___ \| |      / /\ \ | . ` | . ` |  __| |  _  /
  ____) | |____ / ____ \| |\  | |\  | |____| | \ \
 |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\

 """)

#########################

if not os.path.exists("results"):
    os.mkdir("results")

#########################

print("\n" + "-"*20 + "\nType server address: ")
addr = input("> ").strip()

print("\n" + "-"*20 + "\nSpecify PORT range [min-max]. \nPress ENTER to continue with default range (10000-60000).")
ports = input("> ").strip()

print("\n" + "-"*20 + "\nDo you want to create also .txt file with scan results (.csv file is created automatically)? [Y/N]")
user_choice = input("> ").strip()

txt_create = True
if user_choice == "" or user_choice.upper() == "N":
    txt_create = False

if ports == "":
    ports = "10000-60000"

try:
    test = head(f"http://{addr}")
except:
    print('WRONG SERVER ADDRESS!')
    exit(0)

print("\n" + "-"*20 + f"\n\nTARGET -> {addr}\n" + "\n" + "-"*20 + "\n")

#########################

print(f"[{time.strftime('%H:%M:%S', time.localtime())}] Scan started...\n")

start = time.time()

scanner = nmap.PortScanner()

scanner.scan(str(addr), ports)

print(f"Scanned successfully in: {time.time() - start} seconds. \n" + "\n" + "-"*20)

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
                players = f"ONLINE: {data['players']['online']} | MAX: {data['players']['max']}"
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

            print("\n" + f"{data['ip']}:{data['port']} \n|  VERSION: {version} \n|  {players} \n|  SOFTWARE: {software} \n|  PLUGINS:{plugins} \n|  MOTD: {my_motd} \n\n----------------------")

            if txt_create == True:
                txt_file.write("\n" + f"{data['ip']}:{data['port']} \n|  VERSION: {version} \n|  {players} \n|  SOFTWARE: {software} \n|  PLUGINS:{plugins} \n|  MOTD: {my_motd} \n\n----------------------\n")

            writer.writerow(row)

txt_file.close()

#########################
