import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import ipaddress

# Função para verificar se o endereço é IPv6 (simples verificação)
def is_ipv6(address: str) -> bool:
    return ':' in address

# Função para converter string de portas em lista de inteiros.
# Aceita intervalos (ex.: "80-90") ou listas separadas por vírgula ("80,443")
def parse_ports(port_input: str):
    ports = set()
    # Se houver hífen, trata como intervalo
    if '-' in port_input:
        try:
            inicio, fim = port_input.split('-')
            inicio, fim = int(inicio.strip()), int(fim.strip())
            ports = set(range(inicio, fim + 1))
        except Exception:
            raise ValueError("Intervalo de portas inválido.")
    else:
        # Divide por vírgula e converte
        try:
            partes = port_input.split(',')
            for p in partes:
                ports.add(int(p.strip()))
        except Exception:
            raise ValueError("Lista de portas inválida.")
    return sorted(list(ports))

# Função para obter a lista de alvos. Se for uma rede (ex.: 192.168.1.0/24), gera todos os hosts.
def get_target_list(target: str):
    targets = []
    try:
        # Se houver '/', trata como rede
        if '/' in target:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                targets.append(str(ip))
        else:
            targets.append(target.strip())
    except Exception as e:
        raise ValueError(f"Alvo inválido: {e}")
    return targets

# Função para tentar identificar o serviço associado à porta
def get_service_name(port: int, protocol: str):
    try:
        # protocol: 'tcp' ou 'udp'
        return socket.getservbyport(port, protocol)
    except Exception:
        return "Desconhecido"

# Função para realizar o banner grabbing (apenas para TCP)
def grab_banner(sock: socket.socket):
    sock.settimeout(1.5)
    try:
        banner = sock.recv(1024)
        return banner.decode(errors='ignore').strip() if banner else ""
    except Exception:
        return ""

# Função que realiza o scan TCP de uma única porta
def scan_tcp_port(target: str, port: int, ipv6: bool):
    # Cria socket com o tipo de IP adequado
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = {"porta": port, "estado": "Filtrado", "servico": get_service_name(port, 'tcp'), "banner": ""}
    try:
        conn = s.connect_ex((target, port))
        if conn == 0:
            result["estado"] = "Aberta"
            # Após conexão, tenta obter o banner
            result["banner"] = grab_banner(s)
        else:
            # Se o retorno for diferente de 0, pode ser recusado ou filtrado.
            # Tentamos distinguir: se a conexão for recusada, geralmente o sistema retorna RST.
            result["estado"] = "Fechada"
    except Exception:
        result["estado"] = "Filtrado"
    finally:
        s.close()
    return result

# Função que realiza o scan UDP de uma única porta
def scan_udp_port(target: str, port: int, ipv6: bool):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    result = {"porta": port, "estado": "Filtrado", "servico": get_service_name(port, 'udp'), "banner": ""}
    try:
        # Envia um pacote vazio (ou algum dado arbitrário)
        s.sendto(b'', (target, port))
        # Tenta receber uma resposta
        data, addr = s.recvfrom(1024)
        # Se receber resposta, a porta pode estar aberta ou em algum caso filtrada
        result["estado"] = "Aberta"
        result["banner"] = data.decode(errors='ignore').strip() if data else ""
    except socket.timeout:
        # UDP é sem conexão e se não há resposta, pode ser aberta ou filtrada.
        # Muitos scanners consideram "sem resposta" como "aberta|filtrada".
        result["estado"] = "Aberta|Filtrada"
    except Exception:
        result["estado"] = "Fechada"
    finally:
        s.close()
    return result

# Classe para a interface gráfica
class PortScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("PortScanner em Python")
        
        # Frame de entrada de dados
        frame_input = ttk.Frame(master, padding="10")
        frame_input.grid(row=0, column=0, sticky="EW")
        
        ttk.Label(frame_input, text="Alvo (IP ou rede CIDR):").grid(row=0, column=0, sticky="W")
        self.entry_target = ttk.Entry(frame_input, width=30)
        self.entry_target.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(frame_input, text="Portas (ex: 80-90 ou 80,443):").grid(row=1, column=0, sticky="W")
        self.entry_ports = ttk.Entry(frame_input, width=30)
        self.entry_ports.grid(row=1, column=1, padx=5, pady=5)
        
        # Seleção do tipo de scan
        ttk.Label(frame_input, text="Tipo de escaneamento:").grid(row=2, column=0, sticky="W")
        self.scan_type = tk.StringVar(value="tcp")
        frame_radio = ttk.Frame(frame_input)
        frame_radio.grid(row=2, column=1, sticky="W")
        ttk.Radiobutton(frame_radio, text="TCP", variable=self.scan_type, value="tcp").pack(side="left")
        ttk.Radiobutton(frame_radio, text="UDP", variable=self.scan_type, value="udp").pack(side="left")
        
        # Botão de início
        self.button_scan = ttk.Button(frame_input, text="Iniciar Scan", command=self.iniciar_scan)
        self.button_scan.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Área de saída (resultados)
        self.text_output = scrolledtext.ScrolledText(master, width=80, height=20)
        self.text_output.grid(row=1, column=0, padx=10, pady=10)
    
    def iniciar_scan(self):
        alvo = self.entry_target.get().strip()
        portas_input = self.entry_ports.get().strip()
        if not alvo or not portas_input:
            messagebox.showwarning("Atenção", "Preencha o alvo e as portas a serem escaneadas.")
            return
        
        # Limpa a saída
        self.text_output.delete(1.0, tk.END)
        
        # Tenta processar os dados de entrada
        try:
            lista_portas = parse_ports(portas_input)
            lista_alvos = get_target_list(alvo)
        except Exception as e:
            messagebox.showerror("Erro", str(e))
            return
        
        # Desabilita o botão durante o scan
        self.button_scan.config(state=tk.DISABLED)
        
        # Inicia o scan em uma thread separada para não travar a interface
        thread = threading.Thread(target=self.executar_scan, args=(lista_alvos, lista_portas, self.scan_type.get()))
        thread.start()
    
    def executar_scan(self, alvos, portas, scan_type):
        for alvo in alvos:
            ipv6 = is_ipv6(alvo)
            self.append_output(f"\nEscaneando {alvo} ({'IPv6' if ipv6 else 'IPv4'})\n" + "-"*50)
            for porta in portas:
                if scan_type == "tcp":
                    resultado = scan_tcp_port(alvo, porta, ipv6)
                elif scan_type == "udp":
                    resultado = scan_udp_port(alvo, porta, ipv6)
                else:
                    resultado = {"porta": porta, "estado": "Erro", "servico": "N/A", "banner": ""}
                
                linha = f"Porta {resultado['porta']:5d} | Estado: {resultado['estado']:<15} | Serviço: {resultado['servico']:<12} | Banner: {resultado['banner']}\n"
                self.append_output(linha)
        
        self.append_output("\nScan concluído.\n")
        # Reabilita o botão
        self.button_scan.config(state=tk.NORMAL)
    
    def append_output(self, texto):
        self.text_output.insert(tk.END, texto)
        self.text_output.see(tk.END)

# Execução da interface
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()
