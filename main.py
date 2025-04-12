import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import socket
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de Rede Avançado v5.0")
        self.root.geometry("1200x700")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.arp_cache = {}
        self.cache_lock = Lock()
        self.scan_active = False
        self.scan_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X)
        
        ttk.Label(control_frame, text="IP Inicial:").grid(row=0, column=0, padx=5)
        self.ip_start = ttk.Entry(control_frame, width=15)
        self.ip_start.grid(row=0, column=1, padx=5)
        self.ip_start.insert(0, "192.168.1.1")
        
        ttk.Label(control_frame, text="IP Final:").grid(row=0, column=2, padx=5)
        self.ip_end = ttk.Entry(control_frame, width=15)
        self.ip_end.grid(row=0, column=3, padx=5)
        self.ip_end.insert(0, "192.168.1.254")
        
        ttk.Button(control_frame, text="Escanear", command=self.start_scan).grid(row=0, column=4, padx=10)
        ttk.Button(control_frame, text="Parar", command=self.stop_scan).grid(row=0, column=5)
        ttk.Button(control_frame, text="Limpar", command=self.clear_results).grid(row=0, column=6)
        
        columns = ("ip", "hostname", "user", "domain", "os", "mac", "status", "ping")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        
        col_names = ["IPv4", "Hostname", "Usuário", "Domínio", "Sistema", "MAC", "Status", "Ping (ms)"]
        for col, name in zip(columns, col_names):
            self.tree.heading(col, text=name)
            self.tree.column(col, width=100, anchor=tk.CENTER)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        self.status = ttk.Label(self.root, text="Pronto. Defina a faixa de IP e clique em Escanear.", 
                              relief=tk.SUNKEN, padding=5)
        self.status.pack(fill=tk.X, padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
    
    def start_scan(self):
        if self.scan_active:
            messagebox.showwarning("Aviso", "Já existe um escaneamento em andamento!")
            return
            
        start_ip = self.ip_start.get()
        end_ip = self.ip_end.get()
        
        if not self.validate_ip(start_ip) or not self.validate_ip(end_ip):
            messagebox.showerror("Erro", "Formato de IP inválido! Use o padrão: 192.168.1.1")
            return
            
        self.clear_results()
        self.scan_active = True
        self.status.config(text="Escaneando... Clique em Parar para interromper.")
        self.progress['value'] = 0
        
        self.scan_thread = Thread(target=self.scan_network, args=(start_ip, end_ip))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def stop_scan(self):
        self.scan_active = False
        self.status.config(text="Escaneamento interrompido pelo usuário.")
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=1)
    
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        with self.cache_lock:
            self.arp_cache.clear()
    
    def validate_ip(self, ip):
        return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
    
    def scan_network(self, start_ip, end_ip):
        base_ip = ".".join(start_ip.split(".")[:3])
        start = int(start_ip.split(".")[3])
        end = int(end_ip.split(".")[3])
        total = end - start + 1
        
        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {}
                for i, ip in enumerate([f"{base_ip}.{i}" for i in range(start, end + 1)]):
                    if not self.scan_active:
                        break
                    
                    futures[executor.submit(self.scan_ip, ip)] = ip
                    self.root.after(0, self.update_progress, (i+1)/total*100)
                
                for future in as_completed(futures):
                    if not self.scan_active:
                        break
                    
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.root.after(0, self.add_result, *result)
                    except Exception as e:
                        print(f"Erro ao processar {ip}: {str(e)}")
        
        finally:
            if self.scan_active:
                self.root.after(0, self.status.config, 
                              {"text": f"Escaneamento concluído! {len(self.tree.get_children())} hosts encontrados."})
                self.root.after(0, self.progress.config, {'value': 100})
            self.scan_active = False
    
    def update_progress(self, value):
        self.progress['value'] = value
        self.status.config(text=f"Escaneando... {int(value)}% concluído")
    
    def add_result(self, ip, hostname, user, domain, os_info, mac, status, ping_time):
        ping_str = f"{ping_time*1000:.1f}" if ping_time else "N/A"
        self.tree.insert("", tk.END, values=(
            ip, hostname, user, domain, os_info, mac, status, ping_str
        ))
    
    def scan_ip(self, ip):
        if not self.scan_active:
            return None
        
        try:
            ping_time = self.ping(ip)
            if ping_time is not None:
                hostname = self.get_hostname(ip)
                mac = self.get_mac(ip)
                user_info = self.get_logged_user(ip)
                
                if " (DOMÍNIO)" in user_info:
                    user = user_info.replace(" (DOMÍNIO)", "")
                    domain = "DOMÍNIO"
                elif " (RDP)" in user_info:
                    user = user_info.replace(" (RDP)", "")
                    domain = "RDP"
                else:
                    user = user_info
                    domain = "LOCAL"
                
                os_info = self.get_os_info(ip)
                status = "Ativo"
                
                return (ip, hostname, user, domain, os_info, mac, status, ping_time)
            return None
        except Exception as e:
            print(f"Erro ao escanear {ip}: {str(e)}")
            return (ip, "Erro", "", "", "", "", "Erro", "N/A")
    
    def ping(self, ip, timeout=1):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 445))
            sock.close()
            return (time.time() - start) if result == 0 else None
        except:
            return None
    
    def get_hostname(self, ip):
        """Obtém o hostname com fallback para o IP se não conseguir resolver"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname.split('.')[0]  # Retorna apenas o nome sem domínio
        except socket.herror:
            return ip  # Retorna o IP se não conseguir resolver o hostname
        except Exception as e:
            print(f"Erro ao obter hostname para {ip}: {str(e)}")
            return "N/A"
    
    def get_mac(self, ip):
        """Obtém o endereço MAC com múltiplos métodos"""
        with self.cache_lock:
            if ip in self.arp_cache:
                return self.arp_cache[ip]
        
        mac = self._get_mac_arp(ip)
        if mac == "N/A":
            mac = self._get_mac_wmi(ip)
        
        return mac
    
    def _get_mac_arp(self, ip):
        """Obtém MAC via tabela ARP"""
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            arp_result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                timeout=2
            )
            
            if ip in arp_result.stdout:
                lines = arp_result.stdout.splitlines()
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = parts[1].replace("-", ":")
                            if len(mac) == 17:
                                with self.cache_lock:
                                    self.arp_cache[ip] = mac
                                return mac
            return "N/A"
        except:
            return "N/A"
    
    def _get_mac_wmi(self, ip):
        """Obtém MAC via WMI (para Windows)"""
        try:
            cmd = f'wmic /node:"{ip}" nicconfig get macaddress /value'
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=3,
                startupinfo=subprocess.STARTUPINFO()
            )
            
            if "MACAddress=" in result.stdout:
                mac = result.stdout.split("MACAddress=")[1].strip()
                if mac and mac != "":
                    mac = mac.replace(":", "-")  # Padroniza formato
                    with self.cache_lock:
                        self.arp_cache[ip] = mac
                    return mac
            return "N/A"
        except:
            return "N/A"
    
    def get_logged_user(self, ip):
        """Método aprimorado para detectar usuários logados com múltiplas abordagens"""
        try:
            if ip == socket.gethostbyname(socket.gethostname()):
                return os.getlogin() + " (LOCAL)"
            
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            # Tenta diferentes métodos em ordem de preferência
            user_info = self._try_psloggedon(ip, startupinfo)
            if user_info != "N/A":
                return user_info
                
            user_info = self._try_wmi(ip, startupinfo)
            if user_info != "N/A":
                return user_info
                
            user_info = self._try_registry(ip, startupinfo)
            if user_info != "N/A":
                return user_info
                
            user_info = self._try_qwinsta(ip, startupinfo)
            if user_info != "N/A":
                return user_info
                
            return "N/A"
            
        except Exception as e:
            print(f"Erro ao obter usuário em {ip}: {str(e)}")
            return "N/A"

    def _try_psloggedon(self, ip, startupinfo):
        """Tenta obter usuário via PSLoggedOn"""
        try:
            # Verifica se o psloggedon.exe está no mesmo diretório
            if not hasattr(self, '_psloggedon_path'):
                self._psloggedon_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    'psloggedon.exe'
                )
            
            if not os.path.exists(self._psloggedon_path):
                return "N/A"
                
            result = subprocess.run(
                [self._psloggedon_path, '-l', '\\' + ip],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=startupinfo
            )
            
            if "Error" not in result.stdout:
                lines = result.stdout.splitlines()
                for line in lines:
                    if ip.lower() in line.lower():
                        parts = line.split()
                        if len(parts) >= 3 and "\\" in parts[2]:
                            return parts[2].split("\\")[-1] + " (DOMÍNIO)"
                        elif len(parts) >= 2:
                            return parts[-1] + " (LOCAL)"
            return "N/A"
        except Exception as e:
            print(f"Erro no PSLoggedOn para {ip}: {str(e)}")
            return "N/A"

    def _try_wmi(self, ip, startupinfo):
        """Tenta obter usuário via WMI"""
        try:
            cmd = f'wmic /node:"{ip}" computersystem get username /value'
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=3,
                startupinfo=startupinfo
            )
            
            if "Username=" in result.stdout:
                user = result.stdout.split("Username=")[1].strip()
                if '\\' in user:
                    return user.split("\\")[-1] + " (DOMÍNIO)"
                return user + " (LOCAL)"
            return "N/A"
        except Exception as e:
            print(f"Erro no WMI para {ip}: {str(e)}")
            return "N/A"

    def _try_registry(self, ip, startupinfo):
        """Tenta obter usuário via registro remoto"""
        try:
            cmd = f'reg query "\\\\{ip}\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI" /v LastLoggedOnUser'
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=3,
                startupinfo=startupinfo
            )
            if "REG_SZ" in result.stdout:
                user = result.stdout.split("REG_SZ")[1].strip()
                if '\\' in user:
                    return user.split("\\")[-1] + " (DOMÍNIO)"
                return user + " (LOCAL)"
            return "N/A"
        except Exception as e:
            print(f"Erro no registro remoto para {ip}: {str(e)}")
            return "N/A"

    def _try_qwinsta(self, ip, startupinfo):
        """Tenta obter usuário via qwinsta (sessões RDP)"""
        try:
            cmd = f'qwinsta /server:{ip}'
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=3,
                startupinfo=startupinfo
            )
            if "Active" in result.stdout:
                lines = result.stdout.splitlines()
                for line in lines:
                    if "Active" in line:
                        parts = line.split()
                        if len(parts) >= 1:
                            return parts[0] + " (RDP)"
            return "N/A"
        except Exception as e:
            print(f"Erro no qwinsta para {ip}: {str(e)}")
            return "N/A"

    def get_os_info(self, ip):
        """Detecção aprimorada do sistema operacional"""
        try:
            # Primeiro tenta via WMI (para Windows)
            try:
                cmd = f'wmic /node:"{ip}" os get caption /value'
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    shell=True,
                    timeout=3,
                    startupinfo=subprocess.STARTUPINFO()
                )
                if "Caption=" in result.stdout:
                    os_name = result.stdout.split("Caption=")[1].strip()
                    return os_name.split("|")[0]  # Pega a primeira parte se houver múltiplas linhas
            except:
                pass
            
            # Fallback para detecção via ping
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            result = subprocess.run(
                ["ping", "-n", "1", ip],
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                timeout=2
            )
            
            if "TTL=128" in result.stdout:
                return "Windows"
            elif "TTL=64" in result.stdout:
                return "Linux"
            return "SO Desconhecido"
        except Exception as e:
            print(f"Erro ao detectar OS para {ip}: {str(e)}")
            return "N/A"

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()