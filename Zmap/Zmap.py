from pyfiglet import figlet_format
import socket
import argparse
import requests
from colorama import Fore, init
import subprocess
import sys
import time
import threading

# Inizializza colorama per il colore
init()

def print_title():
    title = "Zmap by Zero-day Smokey"
    smokey = "Best_Team_Ever"
    colored_title = figlet_format(title, font="standard")
    print(Fore.RED + colored_title.center(80))
    print(Fore.BLUE + smokey.center(80))

def ping(host):
    try:
        # Verifica della risposta di DNS
        socket.getaddrinfo(host, None)
        # Tentativo di connessione TCP per confermare la raggiungibilità
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, 80))
            print(Fore.GREEN + f"Host {host} è raggiungibile.")
        return True
    except Exception as e:
        print(Fore.RED + f"Errore: {e}")
        return False

def scan():
    print(Fore.BLUE + "Scanning the network...")
    # Chiedi la subnet mask all'utente
    subnet_mask = input(Fore.WHITE + "Inserisci la subnet mask (es. 192.168.1.0/24): ")
    if not subnet_mask:
        subnet_mask = "192.168.1.0/24"
    
    # Estrai l'indirizzo e il maschera di rete
    address, netmask = subnet_mask.split('/')
    start = 1
    end = 256
    
    print(Fore.BLUE + f"Scanning la subnet {subnet_mask}...")
    for i in range(start, end):
        try:
            # Timeout di 2 secondi per ciascun ping
            socket.create_connection((f"{address}.{i}", 80), timeout=2)
            print(Fore.GREEN + f"{address}.{i} è raggiungibile.")
        except Exception as e:
            print(Fore.RED + f"{address}.{i} non è raggiungibile. [{str(e)}]")
    print("\nScansione del network completata.\n")

def dns_lookup(domain):
    try:
        info = socket.gethostbyname_ex(domain)
        print(Fore.BLUE + "Record DNS:")
        for record in info[4]:
            print(Fore.GREEN + f"{record[0]}: {record[1]}")
        print("\nRicerca DNS completata.\n")
    except Exception as e:
        print(Fore.RED + f"Errore DNS: {e}\n")

def list_interfaces():
    result = subprocess.run(["ip", "a"], capture_output=True, text=True)
    print(result.stdout)
    print("\nElenco interfacce completato.\n")

def port_scan(host, ports):
    try:
        ports_list = ports.split("-")
        start_port = int(ports_list[0])
        end_port = int(ports_list[1]) + 1
        results = {}

        # Codice per l'animazione di attesa
        stop_event = threading.Event()
        spinner_thread = None

        def loading(stop_event):
            loading_chars = ['\\', '|', '/']
            loading_index = 0

            while not stop_event.is_set():
                sys.stdout.write(
                    f'\rScansione in corso {loading_chars[loading_index]}'
                )
                sys.stdout.flush()

                loading_index = (loading_index + 1) % len(loading_chars)
                time.sleep(0.1)

            sys.stdout.write('\r' + ' ' * 40 + '\r')
            sys.stdout.flush()

        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=loading, args=(stop_event,))
        spinner_thread.start()

        try:
            for port in range(start_port, end_port):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        results[port] = "Aperta"
                    else:
                        results[port] = "Chiusa"

        finally:
            stop_event.set()
            spinner_thread.join()

        print("\nElenco porte aperte e chiuse:")
        print(Fore.CYAN + "\nPorta | Stato")
        for port in range(start_port, end_port):
            status = results.get(port, "Non trovata")
            if status == "Aperta":
                print(Fore.GREEN + f"{port} | {status}")
            elif status == "Chiusa":
                print(Fore.RED + f"{port} | {status}")
            else:
                print(Fore.YELLOW + f"{port} | Non trovata")

        print("\nRiassunto: Scansione porte completata.\n")
        return results
    except Exception as e:
        print(Fore.RED + f"Errore durante lo scan delle porte: {e}\n")

def http_test(host):
    try:
        print(Fore.BLUE + "\nTest HTTP su", host)
        print("1. GET")
        print("2. POST")
        print("3. DELETE")
        print("4. HEAD")
        print("5. OPTIONS")
        print("\nSeleziona l'opzione desiderata: ")
        choice = input(Fore.WHITE + "Inserisci il numero dell'opzione: ")

        if choice == "1":
            requests.get(f"http://{host}", timeout=5)
            print(Fore.GREEN + "GET completato con successo.\n")
        elif choice == "2":
            response = requests.post(f"http://{host}/", data="test", timeout=5)
            print(Fore.GREEN + f"POST completato con codice {response.status_code}.\n")
        elif choice == "3":
            response = requests.delete(f"http://{host}/", timeout=5)
            print(Fore.GREEN + f"DELETE completato con codice {response.status_code}.\n")
        elif choice == "4":
            response = requests.head(f"http://{host}", timeout=5)
            print(Fore.GREEN + f"HEAD completato con codice {response.status_code}.\n")
        elif choice == "5":
            response = requests.options(f"http://{host}", timeout=5)
            print(Fore.GREEN + f"OPTIONS completato con codice {response.status_code}.\n")
        else:
            print(Fore.RED + "Scelta non riconosciuta.\n")
    except Exception as e:
        print(Fore.RED + f"Errore HTTP: {e}\n")

if __name__ == "__main__":
    print_title()
    while True:
        print("\n1. Verificare raggiungibilità di un host (ping)")
        print("2. Eseguire uno scan del network")
        print("3. Verificare i record DNS per un dominio")
        print("4. Elencare tutte le interfacce")
        print("5. Scan sulle porte specifiche di un host (Premere 1 prima.)")
        print("6. Testare HTTP su con metodi GET/POST/DELETE/HEAD/OPTIONS")
        print("7. Esci\n")

        choice = input(Fore.BLUE + "Inserisci il numero dell'opzione: ")

        if choice == "1":
            host = input(Fore.WHITE + "Inserisci l'indirizzo del host: ")
            ping(host)
        elif choice == "2":
            scan()
        elif choice == "3":
            domain = input(Fore.WHITE + "Inserisci il dominio: ")
            dns_lookup(domain)
        elif choice == "4":
            list_interfaces()
        elif choice == "5":
            if hasattr(port_scan, "previous_ip"):
                print(Fore.GREEN + "\nVuoi utilizzare l'IP precedente " + port_scan.previous_ip + "? Y/N")
                use_previous = input().lower()
                if use_previous == "y":
                    host = port_scan.previous_ip
                else:
                    host = input(Fore.WHITE + "Inserisci l'indirizzo del host: ")
            ports = input(Fore.WHITE + "Inserisci le porte da scansionare (es. 1-1000): ")
            port_scan(host, ports)
            port_scan.previous_ip = host
        elif choice == "6":
            host = input(Fore.WHITE + "Inserisci l'indirizzo del host: ")
            http_test(host)
        elif choice == "7":
            break
        else:
            print(Fore.RED + "Opzione non riconosciuta. Per favore, scegli un numero valido dall'elenco.")
