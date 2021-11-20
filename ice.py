
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
    
    n = input(" 1- Scan Network    \n 2- Vulnerabilities Scanning      \n 3- Exploit Vulnerabilities    \n 4- Ping Adress  \n Choose an option : ")
    if n == '1':
        nmap()
    if n == '2':
        vuln()
    if n == '3':
        os.system('msfconsole')
    
    if n == '4':
        test()
    else:
        print("Entrez une bonne option")







def nmap():
        print("Network Scanning")
        ip = input("Ip ? : ")
        print("Network Ip = ",ip)
        sc.scan(ip , '20,53,119,123,143,14,123,143,161,194,21,80,443,22,110,995,143,993,25,26,587,3306,2082,2083,2086,2087,2095,2096,2077,2078,8082,8888,9500,1723', arguments='-Pn')
        for host in sc.all_hosts():
            print("-----------------------------------------------------")
            print('Host : %s (%s)' % (host, sc[host].hostname()))
            print('State : %s' % sc[host].state())
            for proto in sc[host].all_protocols():
               
                lport = sc[host][proto].keys()
                for port in lport:
                    print ('port : %s\tstate : %s' % (port, sc[host][proto][port]['state']))
                
                print('-----------------------------------------------------')
        main()



def vuln():
    print("Vulnerabilities Scanning")
    ip = input("Ip bg ? : ")
    print(os.system('nmap - sV --script vuln '+ip))
    main()

def test():
    print("Ping")
    ip = input("Ip : ")
    os.system('ping '+ip)
    main()



if __name__ == '__main__':
    main()

