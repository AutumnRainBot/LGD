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
    
    n = input(" 1- Scan Network Port    \n 2- Vulnerabilities Scanning      \n 3- Exploit Vulnerabilities    \n 4- Ping Adresse \n 5- Network Scanning device \n 6- Classic Scan \n 7- Hack Automatisation \n 8- Auto Hack Matteo \n 9- List All Device On Network \n Choose an option : ")
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
    if n == '7':
        auto()
    if n == '8':
        matteoice()
    if n == '9':
        liste()
    else:
        print("Entrez une bonne option")







def nmap():
        print("Network Scanning")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        portt = input("Port ? (80 http , 5900 vnc , 433 https , 21 ftp ) : ")
        print("\n\n\n\n\n\n\n\n\n\n\n")
        print("Loading please wait . . .")
        sc.scan(ip,arguments=('-p '+portt))
        print("\n\n\n\n\n")
        
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
                        else:
                            print("No Open Ports Were Found")
                            main()
                            
                                   
                            
                            

    
        

def matteoice():
        print("Matteo Connection")
        ip1 = ("192.168.8.1/24")
        ip2 = ("192.168.9.1/24")
        ip3 = ("192.168.10.1/24")
        ip4 = ("192.168.11.1/24")
        print("\n\n"+ip1+" First Main Router\n")
        print(ip2+" Seconde Main Router\n")
        print(ip3+" Third Main Router\n")
        print(ip4+" Fourth Main Router\n")
        print("\n\n\n")
        print("Loading please wait . . .")
        print("\n\n\n\n\n\n\n")
        sc.scan(ip1,arguments=('-p 80,5900'))
        for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                    if sc[host][proto][port]['state'] == "open":
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")
        sc.scan(ip1,arguments=('-p 80,5900'))
        for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                    if sc[host][proto][port]['state'] == "open":
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")
        sc.scan(ip2,arguments=('-p 80,5900'))
        for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                    if sc[host][proto][port]['state'] == "open":
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")
        sc.scan(ip3,arguments=('-p 80,5900'))
        for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                    if sc[host][proto][port]['state'] == "open":
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")
        sc.scan(ip4,arguments=('-p 80,5900'))
        for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                    if sc[host][proto][port]['state'] == "open":
                        print('Host : %s %s' % (host, sc[host].hostname()))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")


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
        print("\n\n\n\n\n")
        print("Loading please wait . . .")
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
    print("\n\n\n\n\n")
    print("Loading please wait . . .")
    sc.scan(ip)
    for host in sc.all_hosts():
            for proto in sc[host].all_protocols():
                lport = sc[host][proto].keys()
                for port in lport:
                        print('Host : %s ' % (host))
                        print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                        print("---------------------------")
                        print("\n\n\n\n\n\n\n\n\n\n\n")
        
    main()


def auto():
        print("Router / Web Page Finder")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        print("\n\n\n")
        portt = input("Port ? (80 http , 5900 vnc , 433 https , 21 ftp ) : ")
        print("\n\n\n\n\n\n\n\n\n\n\n")
        print("\n\n\n\n\n")
        print("Loading please wait . . .")
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
                               if  webbrowser.open("http://%s:80"%host):
                                   print("Page succesfully loaded")
                                   main()
                        else:
                            print("No Open Ports Were Found")
                            main()
    
        


def liste():
        print("List All Device on Network")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        print("\n\n\n")
        os.system('nmap -sn '+ip)




if __name__ == '__main__':
    main()
