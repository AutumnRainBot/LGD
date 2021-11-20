
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
    
    n = input(" 1- Scan Network    \n 2- Vuln Scan      \n 3- Exploit      \n    Quelle option chef : ")
    if n == '1':
        nmap()
    if n == '2':
        vuln()
    if n == '3':
        os.system('msfconsole')
    else:
        print("autre chiffre ")







def nmap():
        print("Scan Menu")
        ip = input("Ip ? : ")
        sc.scan(ip, '1-9500')
        print(sc[ip]['tcp'].keys())
        main()



def vuln():
    print("On veux pas des vuln nous ??")
    ip = input("L'ip bg ? : ")
    print(os.system('nmap - sV --script=vuln'+ip))
    main()



if __name__ == '__main__':
    main()

