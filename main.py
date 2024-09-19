import sys
import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox


def convert_hccapx_to_22000(input_file):
    with open(input_file, "rb") as f:
        data = f.read()

    def get_data(fmt, data):
        result = struct.unpack(fmt, data)
        if isinstance(result, tuple) and len(result) == 1:
            result = result[0]
        return result

    signature: str = get_data('4s', data[0:4])  # type:ignore
    if signature != b'HCPX':
        raise ValueError(f"Invalid hccapx file. Signature is {signature}")
    version: int = get_data('I', data[4:8])  # type:ignore
    message_pair: int = get_data('B', data[8:9])  # type:ignore
    essid_len: int = get_data('B', data[9:10])  # type:ignore
    essid: bytes = get_data(f'{essid_len}s', data[10:10+essid_len])  # type:ignore
    keyver: int = get_data('B', data[42:43])  # type:ignore
    keymic: bytes = get_data('16s', data[43:59])  # type:ignore
    mac_ap: bytes = get_data('6s', data[59:65])  # type:ignore
    nonce_ap: bytes = get_data('32s', data[65:97])  # type:ignore
    mac_sta: bytes = get_data('6s', data[97:103])  # type:ignore
    nonce_sta: bytes = get_data('32s', data[103:135])  # type:ignore
    eapol_len: int = get_data('H', data[135:137])  # type:ignore
    eapol: bytes = get_data(f'{eapol_len}s', data[137:137+eapol_len])  # type:ignore

    protocol = "WPA"
    pmkid_mic = keymic.hex()
    type = "02"
    if keyver == 1:
        raise Exception("Version 2 file not supported")
    mac_ap_hex = mac_ap.hex()
    mac_client_hex = mac_sta.hex()
    essid_hex = essid.hex()
    nonce_ap_hex = nonce_ap.hex()
    eapol_hex = eapol.hex()
    message_pair_hex = f"{message_pair:02x}"
    return f"{protocol}*{type}*{pmkid_mic}*{mac_ap_hex}*{mac_client_hex}*{essid_hex}*{nonce_ap_hex}*{eapol_hex}*{message_pair_hex}"


def open_file():
    global input_file_path
    input_file_path = filedialog.askopenfilename(filetypes=[("HCCAPX files", "*.hccapx")])
    if input_file_path:
        try:
            result = convert_hccapx_to_22000(input_file_path)
            result_text.set(result)
            save_button.config(state=tk.NORMAL)  # Enable the save button
        except Exception as e:
            messagebox.showerror("Error", str(e))


def save_file():
    if not input_file_path:
        messagebox.showwarning("Warning", "No file selected for conversion.")
        return

    base_name = os.path.basename(input_file_path)
    default_file_name = os.path.splitext(base_name)[0] + ".hc22000"
    
    save_path = filedialog.asksaveasfilename(
        defaultextension=".hc22000",
        filetypes=[("HC22000 files", "*.hc22000")],
        initialfile=default_file_name
    )
    
    if save_path:
        result = result_text.get()
        if not result:
            messagebox.showwarning("Warning", "No result to save.")
            return

        try:
            with open(save_path, "w") as f:
                f.write(result)
            messagebox.showinfo("Success", f"File saved successfully as '{os.path.basename(save_path)}'!")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# Create the main window
root = tk.Tk()
root.title("HCCAPX to 22000 Converter")

# Create and place widgets
frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=20, pady=20)

open_button = tk.Button(frame, text="Open HCCAPX File", command=open_file, bg="#4CAF50", fg="white")
open_button.grid(row=0, column=0, pady=5, sticky="ew")

save_button = tk.Button(frame, text="Save Result", command=save_file, bg="#2196F3", fg="white", state=tk.DISABLED)
save_button.grid(row=0, column=1, pady=5, padx=5, sticky="ew")

result_text = tk.StringVar()
result_label = tk.Label(frame, textvariable=result_text, wraplength=400, justify="left")
result_label.grid(row=1, column=0, columnspan=2, pady=10)

# Set minimum window size
root.minsize(600, 300)

# Global variable to store the input file path
input_file_path = ""

# Start the GUI event loop
root.mainloop()
