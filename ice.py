
import nmap
import os

os.system('sudo apt install python3-pip')
os.system('pip3 install python-nmap')
sc = nmap.PortScanner()


def main():
    print("""
    
 ██▓      ▄████ ▓█████▄ 
▓██▒     ██▒ ▀█▒▒██▀ ██▌
▒██░    ▒██░▄▄▄░░██   █▌
▒██░    ░▓█  ██▓░▓█▄   ▌
░██████▒░▒▓███▀▒░▒████▓ 
░ ▒░▓  ░ ░▒   ▒  ▒▒▓  ▒ 
░ ░ ▒  ░  ░   ░  ░ ▒  ▒ 
  ░ ░   ░ ░   ░  ░ ░  ░ 
    ░  ░      ░    ░    
                 ░      
                    by LGDMomo
     """)
    
    n = input(" 1- Scan Network Ports    \n 2- Vulnerabilities Scanning      \n 3- Exploit Vulnerabilities    \n 4- Ping Adress \n 5- Network Scanning device \n Choose an option : ")
    if n == '1':
        nmap()
    if n == '2':
        vuln()
    if n == '3':
        os.system('msfconsole')
    
    if n == '4':
        test()
    if n == '5':
        scan()
    else:
        print("Entrez une bonne option")







def nmap():
        print("Network Scanning")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        sc.scan(ip,arguments='-p 21,80,9500,8080,8082,8001,443,22,143,993,5900,5800')
        for host in sc.all_hosts():
            print("-----------------------------------------------------")
            print('Host : %s (%s)' % (host, sc[host].hostname()))
            print('State : %s' % sc[host].state())
            for proto in sc[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = sc[host][proto].keys()
                for port in lport:
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
        print('-----------------------------------------------------')
        main()



def vuln():
    print("Vulnerabilities Scanning")
    ip = input("Ip bg ? : ")
    os.system('nmap - sV --script vuln '+ip)
    main()

def test():
    print("Ping")
    ip = input("Ip : ")
    os.system('ping '+ip)
    main()

def scan():
        print("Network Scanning")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        sc.scan(ip,arguments='-sn')
        for host in sc.all_hosts():
            print("-----------------------------------------------------")
            print('Device Ip : %s (%s)' % (host, sc[host].hostname()))
            print('State : %s' % sc[host].state())
            print('Name : %s' % sc[host].hostnames)
            
        print('-----------------------------------------------------')
        main()

if __name__ == '__main__':
    main()

