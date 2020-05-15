#!/usr/bin/env python3

import sys
import os
import argparse
import subprocess
from subprocess import Popen, PIPE, STDOUT

banner = """
   _         _          __                                     _
  /_\  _   _| |_ ___   /__\ __  _   _ _ __ ___   ___ _ __ __ _| |_ ___  _ __
 //_\\\\| | | | __/ _ \ /_\| '_ \| | | | '_ ` _ \ / _ \ '__/ _` | __/ _ \| '__|
/  _  \ |_| | || (_) //__| | | | |_| | | | | | |  __/ | | (_| | || (_) | |
\_/ \_/\__,_|\__\___/\__/|_| |_|\__,_|_| |_| |_|\___|_|  \__,_|\__\___/|_|

"""

class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def get_args():
    parser = argparse.ArgumentParser(description='Script AutoEnumerator \nBy @CyberVaca - hackplayers.com')
    parser.add_argument('-t', dest='target', type=str, required=True, help='target')
    parser.add_argument('--fast', dest='scan_fast', action='store_true',required=False, help='nmap fast')
    parser.add_argument('--full', dest='scan_full', action='store_true', required=False, help='nmap full' )
    parser.add_argument('--services', dest='enum_services', action="store_true", required=False, help='services')
    parser.add_argument('--recon', dest='scan_recon', action="store_true", required=False, help='recon target')
    parser.add_argument('--maxrate', dest="max_rate", type=str, required=False, default="15000",help='max-rate para nmap')
    parser.add_argument('-v', dest='verbose', action="store_true", required=False, help="verbose")
    return parser.parse_args()

def export_file(name_file,export_data):
    f = open(name_file, "w")
    f.write(export_data)
    f.close()


def download_all_ftp(target,puerto):
    subprocess.Popen(["bash", "-c", "wget -m ftp://anonymous:anonymous:" + puerto + "@" + target + " -P ftp -nH > /dev/null 2>&1"])

def execute_fuzzing(url,puerto,extensiones):
     subprocess.Popen(["bash","-c","gobuster dir -u " + url + " -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -z -q -x "+ extensiones + " -o webs/fuzzing_" + puerto + " > /dev/null 2>&1"])

def execute_silent(ejecuta):
    Popen(ejecuta,shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)


def check_os(target):
    ping = "ping TARGET -c 1 | awk '{print $6}' | sed ':a;N;$!ba;s/\\n//g' | sed 's/ofttl=//g' | sed 's/0%//g'".replace("TARGET",target)
    ping = (os.popen(ping).read()).replace("\n","").replace(" ","")
    operating_system = "Unknown"
    if "127" == ping or "128" == ping :
        operating_system = "Windows"
    if "63" == ping or "64" == ping:
        operating_system = "Linux"
    if "256" == ping or "255" == ping or "254" == ping:
        operating_system = "OpenBSD/Cisco/Oracle"
    informa("Operating system: " + Color.END + operating_system + "\n")


def get_base(target):
    domain = "ldapsearch -h ip -x -s base namingcontexts | grep DC -m 1 | sed 's/namingContexts: //g' | sed 's/namingcontexts: //g'".replace("ip",target)
    if args.verbose == True:
        informa("Query: \n\n" + Color.END + domain + "\n")
    base = (os.popen(domain).read()).replace("\n","")
    dominio = base.replace("DC=","").replace(",",".")
    informa("Domain: " + Color.END + dominio + "\n")
    return dominio


def check_dir(directorio):
    existe = os.path.isdir(directorio)
    if existe == False:
        os.mkdir(directorio)


nmap = "nmap -Pn -sT -T4 --max-retries 1 --max-scan-delay 20 --max-rate=ELMAX TARGET -oA nmap/tipo"
fast = nmap.replace("tipo","fast")
full = nmap.replace("tipo","full -p-")
domain = ""

def informa(msg):
    print (Color.GREEN + "[" + Color.RED + "+" + Color.GREEN + "] " +  msg)

def nmap_fast(target):
    nmap = fast.replace("TARGET",target).replace("ELMAX",args.max_rate)
    if args.verbose == True:
        informa("Query: \n\n" + Color.END + nmap + "\n")
    result = (os.popen(nmap).read())
    informa("Fast Scan:\n")
    print (Color.END + result)
    result = (os.popen("cat nmap/fast.nmap | awk '{print $1}' | sed 's/\/tcp//g' | grep -v Increasing | grep -v Host | grep -v Warning: | grep -v Nmap | grep -v Read | grep -v PORT | sed 's/#//g' | sed 's/Not//g'  | sed ':a;N;$!ba;s/\\n/,/g' | sed 's/,,//g'").read())
    informa("Ports detected: " + Color.END + result)
    result = result.replace("\n","").replace(" ","")
    return result

def nmap_servicios(target,puertos):
    informa("Services Scan:\n" + Color.END)
    nmap = "nmap -sC -sV " + target + " -p " + puertos + " -oA nmap/services -Pn"
    result = (os.popen(nmap).read())
    informa("Services:\n")
    print (Color.END + result)

def nmap_full(target):
    informa("Full Scan:\n" + Color.END)
    result = (os.popen(full.replace("TARGET",target).replace("ELMAX",args.max_rate)).read())
    print(result)
    result = (os.popen("cat nmap/full.nmap | awk '{print $1}' | sed 's/\/tcp//g' | grep -v Increasing | grep -v Host | grep -v Warning: | grep -v Nmap | grep -v Read | grep -v PORT | sed 's/#//g' | sed 's/Not//g'  | sed ':a;N;$!ba;s/\\n/,/g' | sed 's/,,//g'").read())
    result = result.replace("\n","").replace(" ","")
    informa("Ports detected: " + Color.END + result)
    return result


def check_smb(target,puerto):
    informa("SMB check:\n" + Color.END)
    nmap_smb = os.popen("nmap --script vuln -p445 " +  target).read()
    print(nmap_smb)
    informa("Using crackmapexec:\n" + Color.END)
    smb = os.popen("crackmapexec smb " + target + " -u '' -p '' --shares").read()
    print(smb)

def tipical_recon(target,puertos):
    webs_http = os.popen("cat nmap/services.nmap  | grep 'open' | grep 'http' | sed 's/\/tcp//g' |awk '{print $1,$4,$5,$6,$7,$8,$9,$10}'").read()
    webs_https = os.popen("cat nmap/services.nmap | grep 'open' | grep 'ssl/http' | sed 's/\/tcp//g' | awk '{print $1,$4,$5,$6,$7,$8,$9,$10}'").read()
    if len(webs_http) > 1:
        webs_http = webs_http.split("\n")
        informa("Launching Nikto and Gobuster in the background:\n" + Color.END)
        informa("Outputs in webs/files\n" + Color.END)
        for web in webs_http:
            if len(web) > 1:
                puerto = web.split(" ")[0]
                url = ("http://" + target + ":" + puerto)
                check_dir("webs")
                execute_silent("nikto -h " + url + " > webs/nikto_" + puerto)
                server_web_tipo = None
                if "apache" in web.lower():
                    server_web_tipo = "Apache"
                if "nginx" in web.lower():
                    server_web_tipo = "Nginx"
                if "tomcat" in web.lower():
                    server_web_tipo = "Tomcat"
                if "iis" in web.lower():
                    server_web_tipo = "IIS"
                if server_web_tipo == None:
                    server_web_tipo = "Unknown"
                if "Apache" == server_web_tipo:
                    execute_fuzzing(url,puerto,".php,.txt,.html")
                if "Desconocido" == server_web_tipo:
                    execute_fuzzing(url,puerto,".php,.txt,.html,.jsp")
                if "IIS" == server_web_tipo:
                    execute_fuzzing(url,puerto,".asp,.aspx,.txt,.html")
                if "Tomcat" == server_web_tipo:
                    execute_fuzzing(url,puerto,".jsp",".txt",".html")
                if "Nginx" in server_web_tipo:
                    execute_fuzzing(url,puerto,".php,.txt,.html")
                informa("Web detected:\n" + Color.END)
                print(server_web_tipo + "\n")
                informa("Port and services: " + Color.END +  web + "\n")

    if len(webs_https) > 1:
        webs_https = webs_https.split("\n")
        informa("Launch Nikto and Gobuster in the background:\n" + Color.END)
        informa("Outputs in webs/files\n" + Color.END)
        for web in webs_https:
            if len(web) > 1:
                puerto = web.split(" ")[0]
                url = ("https://" + target + ":" + puerto)
                check_dir("webs")
                execute_silent("nikto -h " + url + " > webs/nikto_" + puerto + " -ssl")
                server_web_tipo = None
                if "apache" in web.lower():
                    informa("Web detectada:\n" + Color.END)
                server_web_tipo = None
                if "apache" in web.lower():
                    server_web_tipo = "Apache"
                if "bginx" in web.lower():
                    server_web_tipo = "Nginx"
                if "tomcat" in web.lower():
                    server_web_tipo = "Tomcat"
                if "iis" in web.lower():
                    server_web_tipo = "IIS"
                if server_web_tipo == None:
                    server_web_tipo = "Unknown"
                if "Apache" == server_web_tipo:
                    execute_fuzzing(url,puerto,".php,.txt,.html")
                if "Desconocido" == server_web_tipo:
                    execute_fuzzing(url,puerto,".php,.txt,.html,.jsp")
                if "IIS" == server_web_tipo:
                    execute_fuzzing(url,puerto,".asp,.aspx,.txt,.html")
                if "Tomcat" == server_web_tipo:
                    execute_fuzzing(url,puerto,".jsp",".txt",".html")
                if "Nginx" in server_web_tipo:
                    execute_fuzzing(url,puerto,".php,.txt,.html")
                informa("Web detected:\n" + Color.END)
                print(server_web_tipo + "\n")
                informa("Port and services: " + Color.END + web + "\n")


    ##### foreach en puertos ############
    puertos_array = puertos.split(",")
    for puerto in puertos_array:
        if puerto == "21":
            anonimo = os.popen("cat nmap/services.nmap  | grep -E1 'Anonymous FTP login allowed'  | awk -F ' ' '{print $1}' | sed 's/\/tcp//g'").read()
            if len(anonimo) > 1:
                puerto = anonimo[0]
                informa("Anonymous FTP login allowed\n" + Color.END)
                informa("It proceeds to recursively download all the ftp....\n" + Color.END)
                download_all_ftp(target,puerto)
        if puerto == "389":
            domain = get_base(target)
            informa("We try to extract LDAP users:\n" + Color.END)
            p = Popen("enum4linux -U " + target + " | grep 'user:' | sed 's/user:\[//g' | sed 's/\]//g' | awk '{print $1}' > users.txt", shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
            output = p.stdout.read()
            lista_users = os.popen("wc -l users.txt | awk '{print $1}'").read().replace(" ","").replace("\n","")
            if lista_users != "0":
                informa("Users:\n"+ Color.END)
                users = os.popen("cat users.txt").read()
                print(users)
                if "88" in puertos_array:
                    informa("Kerberos Port Detected.\n" + Color.END)
                    informa("Tried ASREPRoast with the list of users.\n" + Color.END)
                    ASREPRoast =  os.popen("GetNPUsers.py " + domain + "/ -usersfile users.txt -format john -dc-ip " +  target + " -outputfile hash.txt").read()
                    if os.path.isfile("hash.txt") == True:
                        hashes = os.popen("wc -l hash.txt  | awk '{print $1}'").read().replace(" ","").replace("\n","")
                        informa("Hashes obtenidos: " + Color.END + hashes + "\n")
                        if hashes != "0":
                            informa("Hashes:\n" + Color.END)
                            hashes = os.popen("cat hash.txt").read()
                            print(hashes)
                        if hashes == "0":
                            os.popen("rm hash.txt").read()
            if lista_users == "0":
                remove = os.popen("rm users.txt").read()

        if puerto == "445":
            check_smb(target,puerto)
        if puerto == "53":
            bind = os.popen("cat nmap/services.nmap  | grep 'open' | grep 'BIND' | sed 's/\/tcp//g' |awk '{print $1,$4,$5,$6,$7,$8,$9,$10}'").read()
            if "BIND" in bind:
                informa("BIND DNS Detected:" + Color.END)
                dominios = os.popen("dig -x " + args.target + " @" + args.target).read()
                print(dominios)
                informa("Checking transfer zone:" + Color.END)
                transfer_zone = os.popen("dig axfr " + args.target + " @" + args.target).read()
                if "Transfer failed." in transfer_zone:
                    print("\nTransfer zone failed.\n")
                else:
                    print(transfer_zone)






if __name__ == '__main__':
    print(Color.RED + Color.BOLD + banner + Color.END)
    args = get_args()
    nmap_dir = check_dir("nmap")
    check_os(args.target)
    nmap = nmap.replace("ELMAX",args.max_rate)
    if args.scan_recon == True:
        if os.path.isfile("nmap/services.nmap") == True:
            user_input = input(Color.GREEN + "[" + Color.RED + "+" + Color.GREEN + "] services.nmap file exists, you want to use it [Y/N] " + Color.END)
            if "y" in user_input.lower():
                args.enum_services = False
                puertos = (os.popen("cat nmap/services.nmap | awk '{print $1}' | sed 's/\/tcp//g' | grep -v Increasing | grep -v Host | grep -v Warning: | grep -v Nmap | grep -v Read | grep -v PORT | sed 's/#//g' | sed 's/Not//g'  | sed ':a;N;$!ba;s/\\n/,/g' | sed 's/,,//g'").read())
                print("\n")
            if "n" in user_input.lower():
                args.enum_services = True
        if os.path.isfile("nmap/services.nmap") == False:
            args.enum_services = True
    if args.scan_fast == True:
        puertos = nmap_fast(args.target)
    if args.scan_full == True:
        puertos = nmap_full(args.target)
    if args.enum_services == True:
        nmap_servicios(args.target,puertos)
    if args.scan_recon == True:
        tipical_recon(args.target,puertos)





