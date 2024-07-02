import json
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

requests.packages.urllib3.disable_warnings()

api_url = "https://192.168.56.104/restconf/"
headers = {
    "Accept": "application/yang-data+json",
    "Content-type": "application/yang-data+json"
}
basicauth = ("cisco", "cisco123!")

def get_interfaces():
    module = "data/ietf-interfaces:interfaces"
    resp = requests.get(f'{api_url}{module}', auth=basicauth, headers=headers, verify=False)
    if resp.status_code == 200:
        data_json = resp.json()
        result = json.dumps(data_json, indent=4)
        display_result(result)
    else:
        messagebox.showerror("Error", f'Error al realizar la consulta del modulo {module}')

def get_resconf_native():
    module = "data/Cisco-IOS-XE-native:native"
    resp = requests.get(f'{api_url}{module}', auth=basicauth, headers=headers, verify=False)
    if resp.status_code == 200:
        result = json.dumps(resp.json(), indent=4)
        display_result(result)
    else:
        messagebox.showerror("Error", f'Error al consumir la API para el modulo {module}')

def get_banner():
    module = "data/Cisco-IOS-XE-native:native/banner/motd"
    resp = requests.get(f'{api_url}{module}', auth=basicauth, headers=headers, verify=False)
    if resp.status_code == 200:
        result = json.dumps(resp.json(), indent=4)
        display_result(result)
    else:
        messagebox.showerror("Error", f'Error al consumir la API para el modulo {module}')

def post_loopback(name, description, ip, netmask):
    dloopback = {
        "ietf-interfaces:interface": {
            "name": name,
            "description": description,
            "type": "iana-if-type:softwareLoopback",
            "enabled": True,
            "ietf-ip:ipv4": {
                "address": [
                    {
                        "ip": ip,
                        "netmask": netmask
                    }
                ]
            }
        }
    }
    module = f"data/ietf-interfaces:interfaces/interface={name}"
    resp = requests.post(f'{api_url}{module}', auth=basicauth, headers=headers, json=dloopback, verify=False)
    if resp.status_code == 201:
        messagebox.showinfo("Éxito", "Se insertó correctamente la Loopback")
    else:
        messagebox.showerror("Error", f'Error al insertar la Loopback, código de estado: {resp.status_code}')

def put_banner(message):
    banner = {
        "Cisco-IOS-XE-native:banner": {
            "motd": message
        }
    }
    module = "data/Cisco-IOS-XE-native:native/banner/motd"
    resp = requests.put(f'{api_url}{module}', auth=basicauth, headers=headers, json=banner, verify=False)
    if resp.status_code == 201:
        messagebox.showinfo("Éxito", "Se insertó correctamente el banner")
    else:
        messagebox.showerror("Error", f'Error al insertar el banner, código de estado: {resp.status_code}')

def del_loopback(name):
    module = f"data/ietf-interfaces:interfaces/interface={name}"
    resp = requests.delete(f'{api_url}{module}', auth=basicauth, headers=headers, verify=False)
    if resp.status_code == 204:
        messagebox.showinfo("Éxito", "Loopback eliminada correctamente")
    else:
        messagebox.showerror("Error", f'Error al eliminar la Loopback, código de estado: {resp.status_code}')

def display_result(result):
    result_window = tk.Toplevel(root)
    result_window.title("Resultado")
    text_area = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, width=100, height=30)
    text_area.grid(column=0, row=0, padx=10, pady=10)
    text_area.insert(tk.END, result)
    text_area.configure(state='disabled')

# Configuración interfaz gráfica
root = tk.Tk()
root.title("Interfaz RESTCONF")

notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True)

# Pestaña para Get Interfaces
tab1 = ttk.Frame(notebook)
notebook.add(tab1, text='Interfaces')
btn_get_interfaces = tk.Button(tab1, text="Interfaces", command=get_interfaces)
btn_get_interfaces.pack(padx=10, pady=10)

# Pestaña para Get Resconf Native
tab2 = ttk.Frame(notebook)
notebook.add(tab2, text='Get Resconf Native')
btn_get_resconf_native = tk.Button(tab2, text="Get Resconf Native", command=get_resconf_native)
btn_get_resconf_native.pack(padx=10, pady=10)

# Pestaña Get Banner
tab3 = ttk.Frame(notebook)
notebook.add(tab3, text='Get Banner')
btn_get_banner = tk.Button(tab3, text="Get Banner", command=get_banner)
btn_get_banner.pack(padx=10, pady=10)

# Pestaña Post Loopback
tab4 = ttk.Frame(notebook)
notebook.add(tab4, text='Post Loopback')
tk.Label(tab4, text="Name").grid(row=0, column=0, padx=10, pady=5)
tk.Label(tab4, text="Description").grid(row=1, column=0, padx=10, pady=5)
tk.Label(tab4, text="IP").grid(row=2, column=0, padx=10, pady=5)
tk.Label(tab4, text="Netmask").grid(row=3, column=0, padx=10, pady=5)
entry_name = tk.Entry(tab4)
entry_name.grid(row=0, column=1, padx=10, pady=5)
entry_description = tk.Entry(tab4)
entry_description.grid(row=1, column=1, padx=10, pady=5)
entry_ip = tk.Entry(tab4)
entry_ip.grid(row=2, column=1, padx=10, pady=5)
entry_netmask = tk.Entry(tab4)
entry_netmask.grid(row=3, column=1, padx=10, pady=5)
btn_post_loopback = tk.Button(tab4, text="Post Loopback", command=lambda: post_loopback(entry_name.get(), entry_description.get(), entry_ip.get(), entry_netmask.get()))
btn_post_loopback.grid(row=4, columnspan=2, pady=10)

# Pestaña para Put Banner
tab5 = ttk.Frame(notebook)
notebook.add(tab5, text='Put Banner')
tk.Label(tab5, text="Message").grid(row=0, column=0, padx=10, pady=5)
entry_banner_message = tk.Entry(tab5)
entry_banner_message.grid(row=0, column=1, padx=10, pady=5)
btn_put_banner = tk.Button(tab5, text="Put Banner", command=lambda: put_banner(entry_banner_message.get()))
btn_put_banner.grid(row=1, columnspan=2, pady=10)

# Pestaña para Delete Loopback
tab6 = ttk.Frame(notebook)
notebook.add(tab6, text='Delete Loopback')
tk.Label(tab6, text="Name").grid(row=0, column=0, padx=10, pady=5)
entry_del_name = tk.Entry(tab6)
entry_del_name.grid(row=0, column=1, padx=10, pady=5)
btn_del_loopback = tk.Button(tab6, text="Delete Loopback", command=lambda: del_loopback(entry_del_name.get()))
btn_del_loopback.grid(row=1, columnspan=2, pady=10)

root.mainloop()