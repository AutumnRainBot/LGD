import webbrowser
import nmap
import os



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
    
    n = input(" 1- Scan Network Port    \n 2- Vulnerabilities Scanning      \n 3- Exploit Vulnerabilities    \n 4- Ping Adresse \n 5- Network Scanning device \n 6- Classic Scan \n Choose an option : ")
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
    if n == '6':
        nmappp()
    
    else:
        print("Entrez une bonne option")







def nmap():
        print("Network Scanning")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        portt = input("Port ? (80 http , 5900 vnc , 433 https , 21 ftp ) : ")
        print("\n\n\n\n\n\n\n\n\n\n\n")
        sc.scan(ip,arguments=('-p '+portt))
        for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                    if sc[host][proto][port]['state'] == "open":
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")
                        if portt == "80"or "443"or "8082"or"8888"or"8080":
                            rep = input("Web page found want to open it  [y/n] ? ")
                            if rep =="y":
                               if  webbrowser.open("http://%s:80"%host):
                                   print("Page succesfully loaded")
                                   main()
                            

    
        



def vuln():
    print("Vulnerabilities Scanning")
    ip = input("Ip ? : ")
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

            
        print('-----------------------------------------------------')
        main()


def nmappp():
    print("Clasic nmap scan")
    ip = input("Ip ? = ")
    sc.scan(ip,arguments='-F')
    for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")


if __name__ == '__main__':
    main()

