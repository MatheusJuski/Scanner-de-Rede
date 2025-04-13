import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import socket
import re
import os
import time
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de Rede Avançado v5.2")
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
        ttk.Button(control_frame, text="Exportar CSV", command=self.export_csv).grid(row=0, column=7, padx=10)
        
        columns = ("ip", "hostname", "user", "domain", "os", "mac", "status", "ping")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        
        col_names = ["IPv4", "Hostname", "Usuário", "Domínio", "Sistema", "MAC", "Status", "Ping (ms)"]
        for col, name in zip(columns, col_names):
            self.tree.heading(col, text=name)
            self.tree.column(col, width=100, anchor=tk.CENTER)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.progress_frame = ttk.Frame(self.root)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="Progresso: 0%")
        self.progress_label.pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(
            self.progress_frame, 
            orient=tk.HORIZONTAL, 
            length=600, 
            mode='determinate'
        )
        self.progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        self.status = ttk.Label(self.root, text="Pronto. Defina a faixa de IP e clique em Escanear.", 
                              relief=tk.SUNKEN, padding=5)
        self.status.pack(fill=tk.X, padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
    
    def export_csv(self):
        if not self.tree.get_children():
            messagebox.showwarning("Aviso", "Nenhum dado para exportar!")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Salvar como CSV"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file, delimiter=';')
                
                # Escreve cabeçalho
                headers = [self.tree.heading(col)['text'] for col in self.tree['columns']]
                writer.writerow(headers)
                
                # Escreve dados
                for item in self.tree.get_children():
                    row = self.tree.item(item)['values']
                    writer.writerow(row)
                    
            messagebox.showinfo("Sucesso", f"Dados exportados com sucesso para:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar CSV:\n{str(e)}")
    
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
        self.progress_label.config(text="Progresso: 0%")
        
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
                    progress_value = (i+1)/total*100
                    self.root.after(0, self.update_progress, progress_value)
                
                for i, future in enumerate(as_completed(futures)):
                    if not self.scan_active:
                        break
                    
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.root.after(0, self.add_result, *result)
                        
                        progress_value = ((i+1)/total*100 + (start + i)/total*100) / 2
                        self.root.after(0, self.update_progress, progress_value)
                    except Exception as e:
                        print(f"Erro ao processar {ip}: {str(e)}")
        
        finally:
            if self.scan_active:
                self.root.after(0, self.status.config, 
                              {"text": f"Escaneamento concluído! {len(self.tree.get_children())} hosts encontrados."})
                self.root.after(0, self.progress.config, {'value': 100})
                self.root.after(0, self.progress_label.config, {'text': "Progresso: 100%"})
            self.scan_active = False
    
    def update_progress(self, value):
        self.progress['value'] = value
        self.progress_label.config(text=f"Progresso: {int(value)}%")
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
                    domain = self.get_domain_name() or "DOMÍNIO"
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
    
    def get_domain_name(self):
        """Obtém o nome do domínio atual do computador"""
        try:
            import win32api
            import win32net
            domain_info = win32net.NetGetJoinInformation()
            return domain_info[0] if domain_info[0] else None
        except:
            try:
                return os.environ['USERDOMAIN']
            except:
                return None
    
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
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname.split('.')[0]
        except socket.herror:
            return ip
        except Exception as e:
            print(f"Erro ao obter hostname para {ip}: {str(e)}")
            return "N/A"
    
    def get_mac(self, ip):
        with self.cache_lock:
            if ip in self.arp_cache:
                return self.arp_cache[ip]
        
        mac = self._get_mac_arp(ip)
        if mac == "N/A":
            mac = self._get_mac_wmi(ip)
        
        return mac
    
    def _get_mac_arp(self, ip):
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
                    mac = mac.replace(":", "-")
                    with self.cache_lock:
                        self.arp_cache[ip] = mac
                    return mac
            return "N/A"
        except:
            return "N/A"
    
    def get_logged_user(self, ip):
        try:
            if ip in ['127.0.0.1', socket.gethostbyname(socket.gethostname())]:
                return self.get_current_user() + " (LOCAL)"
            
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            methods = [
                self._try_wmi,
                self._try_registry,
                self._try_qwinsta,
                self._try_psloggedon
            ]
            
            for method in methods:
                user_info = method(ip, startupinfo)
                if user_info != "N/A":
                    return user_info
                    
            return "N/A"
            
        except Exception as e:
            print(f"Erro ao obter usuário em {ip}: {str(e)}")
            return "N/A"
    
    def get_current_user(self):
        """Obtém o usuário atual do sistema, incluindo domínio se aplicável"""
        try:
            username = os.getlogin()
            domain = self.get_domain_name()
            
            if domain and domain.upper() != os.environ['COMPUTERNAME'].upper():
                return f"{domain}\\{username}"
            return username
        except:
            try:
                return os.environ.get('USERNAME', 'N/A')
            except:
                return "N/A"

    def _try_wmi(self, ip, startupinfo):
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
                if not user:
                    return "N/A"
                    
                if '\\' in user:
                    domain, username = user.split('\\', 1)
                    if domain.upper() == os.environ['COMPUTERNAME'].upper():
                        return username + " (LOCAL)"
                    else:
                        return username + " (DOMÍNIO)"
                return user + " (LOCAL)"
            return "N/A"
        except Exception as e:
            print(f"Erro no WMI para {ip}: {str(e)}")
            return "N/A"

    def _try_registry(self, ip, startupinfo):
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
                user_line = result.stdout.split("REG_SZ")[1].strip()
                if not user_line:
                    return "N/A"
                    
                if '\\' in user_line:
                    domain, username = user_line.split('\\', 1)
                    if domain.upper() == os.environ['COMPUTERNAME'].upper():
                        return username + " (LOCAL)"
                    else:
                        return username + " (DOMÍNIO)"
                return user_line + " (LOCAL)"
            return "N/A"
        except Exception as e:
            print(f"Erro no registro remoto para {ip}: {str(e)}")
            return "N/A"

    def _try_qwinsta(self, ip, startupinfo):
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
            
            lines = result.stdout.splitlines()
            for line in lines:
                if "Active" in line and "disc" not in line.lower():
                    parts = line.split()
                    if len(parts) >= 1:
                        username = parts[0]
                        if username.lower() != "console":
                            return username + " (RDP)"
            return "N/A"
        except Exception as e:
            print(f"Erro no qwinsta para {ip}: {str(e)}")
            return "N/A"

    def _try_psloggedon(self, ip, startupinfo):
        try:
            psloggedon_path = os.path.join(os.path.dirname(__file__), 'psloggedon.exe')
            if not os.path.exists(psloggedon_path):
                return "N/A"
                
            result = subprocess.run(
                [psloggedon_path, '-l', '\\' + ip],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=startupinfo
            )
            
            lines = result.stdout.splitlines()
            for line in lines:
                if ip.lower() in line.lower() and "Error" not in line:
                    parts = [p for p in line.split() if p]
                    if len(parts) >= 3 and "\\" in parts[2]:
                        domain, username = parts[2].split("\\", 1)
                        if domain.upper() == os.environ['COMPUTERNAME'].upper():
                            return username + " (LOCAL)"
                        else:
                            return username + " (DOMÍNIO)"
                    elif len(parts) >= 2:
                        return parts[-1] + " (LOCAL)"
            return "N/A"
        except Exception as e:
            print(f"Erro no PSLoggedOn para {ip}: {str(e)}")
            return "N/A"

    def get_os_info(self, ip):
        try:
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
                    return os_name.split("|")[0]
            except:
                pass
            
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