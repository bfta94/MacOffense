#!/usr/bin/env python3
import subprocess
import platform
import argparse
import json
import csv
import os
from datetime import datetime

def run_cmd(cmd, allow_fail=False):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0 and not allow_fail:
            return f"Error: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        if allow_fail:
            return ""
        return f"Error: {e}"

def get_macos_version():
    ver = run_cmd("sw_vers -productVersion")
    print(f"macOS Version: {ver}")
    return ver

def get_architecture():
    arch = platform.machine()
    print(f"Architecture: {arch}")
    return arch

def get_sip_status():
    status = run_cmd("csrutil status", allow_fail=True)
    if "enabled" in status.lower():
        status = "Enabled"
    elif "disabled" in status.lower():
        status = "Disabled"
    else:
        status = "Unknown or unavailable"
    print(f"SIP Status: {status}")
    return status

def get_loaded_kexts():
    output = run_cmd("kextstat | grep -v com.apple", allow_fail=True)
    kexts = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            kexts.append(parts[5])
    print(f"Loaded Kexts ({len(kexts)} found): {', '.join(kexts) if kexts else 'None'}")
    return kexts

def get_launch_agents():
    output = run_cmd("launchctl list", allow_fail=True)
    agents = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            agents.append(parts[2])
    print(f"Launch Agents ({len(agents)} found): {', '.join(agents) if agents else 'None'}")
    return agents

def list_users():
    output = run_cmd("dscl . list /Users", allow_fail=True)
    users = []
    for user in output.splitlines():
        uid = run_cmd(f"id -u {user}", allow_fail=True)
        gid = run_cmd(f"id -g {user}", allow_fail=True)
        shell = run_cmd(f"dscl . -read /Users/{user} UserShell", allow_fail=True).replace("UserShell: ", "")
        home = run_cmd(f"dscl . -read /Users/{user} NFSHomeDirectory", allow_fail=True).replace("NFSHomeDirectory: ", "")
        users.append({
            "username": user,
            "uid": uid,
            "gid": gid,
            "shell": shell,
            "home_directory": home
        })
    print(f"Users ({len(users)} found): {', '.join([u['username'] for u in users])}")
    return users

def list_groups():
    output = run_cmd("dscl . list /Groups", allow_fail=True)
    groups = []
    for group in output.splitlines():
        gid = run_cmd(f"dscl . -read /Groups/{group} PrimaryGroupID", allow_fail=True).replace("PrimaryGroupID: ", "")
        groups.append({
            "groupname": group,
            "gid": gid
        })
    print(f"Groups ({len(groups)} found): {', '.join([g['groupname'] for g in groups])}")
    return groups

def list_cron_jobs():
    cron_jobs = []
    sys_cron = run_cmd("cat /etc/crontab", allow_fail=True)
    if sys_cron and "Error" not in sys_cron:
        cron_jobs.append({"type": "system", "content": sys_cron})
    users = [u['username'] for u in list_users()]
    for user in users:
        user_cron = run_cmd(f"crontab -l -u {user}", allow_fail=True)
        if user_cron and "no crontab" not in user_cron.lower():
            cron_jobs.append({"type": f"user:{user}", "content": user_cron})
    print(f"Cron Jobs ({len(cron_jobs)} found)")
    return cron_jobs

def get_firewall_status():
    pf_status = run_cmd("sudo pfctl -s info", allow_fail=True)
    print(f"Firewall Status:\n{pf_status[:200]}{'...' if len(pf_status) > 200 else ''}")
    return pf_status

def list_applications():
    apps = []
    for path in ["/Applications", os.path.expanduser("~/Applications")]:
        if os.path.isdir(path):
            for item in os.listdir(path):
                fullpath = os.path.join(path, item)
                if os.path.isdir(fullpath) and item.endswith(".app"):
                    apps.append(item)
    print(f"Applications found ({len(apps)}): {', '.join(apps)}")
    return apps

def get_network_info():
    ifconfig = run_cmd("ifconfig", allow_fail=True)
    route = run_cmd("netstat -nr", allow_fail=True)
    dns = run_cmd("scutil --dns", allow_fail=True)
    print("Network Info collected")
    return {
        "ifconfig": ifconfig,
        "route": route,
        "dns": dns
    }

def check_file_permissions(files):
    perms = {}
    for f in files:
        if os.path.exists(f):
            perms[f] = oct(os.stat(f).st_mode & 0o777)
        else:
            perms[f] = "Not found"
    for f, p in perms.items():
        print(f"File Permission - {f}: {p}")
    return perms

def scan_open_ports():
    netstat = run_cmd("netstat -an | grep LISTEN", allow_fail=True)
    lsof = run_cmd("lsof -nP -iTCP -sTCP:LISTEN", allow_fail=True)
    print("Open ports scanned")
    return {"netstat": netstat, "lsof": lsof}

def list_root_processes():
    ps = run_cmd("ps aux | grep '^root'", allow_fail=True)
    print("Root processes listed")
    return ps

def list_suid_files():
    find_cmd = "find / -perm -4000 -type f 2>/dev/null"
    suid_files = run_cmd(find_cmd, allow_fail=True)
    suid_list = suid_files.splitlines() if suid_files else []
    print(f"SUID files found: {len(suid_list)}")
    return suid_list

def list_tcc_profiles():
    tcc_db_path = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
    if not os.path.isfile(tcc_db_path):
        print("TCC database not found or inaccessible")
        return ""
    tcc_db = run_cmd(f"sqlite3 '{tcc_db_path}' \"SELECT * FROM access\"", allow_fail=True)
    print("TCC profiles extracted")
    return tcc_db

def get_gatekeeper_status():
    output = run_cmd("spctl --status", allow_fail=True)
    print(f"Gatekeeper status: {output}")
    return output

def get_kernel_crash_logs():
    logs = run_cmd("log show --predicate 'eventMessage contains \"panic\"' --last 24h", allow_fail=True)
    print("Kernel panic logs retrieved")
    return logs

def list_usb_devices():
    usb = run_cmd("system_profiler SPUSBDataType", allow_fail=True)
    print("USB devices enumerated")
    return usb

def get_time_machine_status():
    tm_status = run_cmd("tmutil status", allow_fail=True)
    print("Time Machine status collected")
    return tm_status

def list_mounted_volumes():
    mount = run_cmd("mount", allow_fail=True)
    print("Mounted volumes listed")
    return mount

def get_ssh_sessions():
    sessions = run_cmd("who", allow_fail=True)
    ssh_sessions = [line for line in sessions.splitlines() if "ssh" in line.lower()]
    print(f"Active SSH sessions: {len(ssh_sessions)}")
    return ssh_sessions


def recent_etc_changes():
    output = run_cmd("find /etc -type f -mtime -7 2>/dev/null", allow_fail=True)
    files = output.splitlines() if output else []
    print(f"Recent /etc changes (last 7 days): {len(files)} files")
    return files

def recent_usr_local_etc_changes():
    output = run_cmd("find /usr/local/etc -type f -mtime -7 2>/dev/null", allow_fail=True)
    files = output.splitlines() if output else []
    print(f"Recent /usr/local/etc changes (last 7 days): {len(files)} files")
    return files

def shell_history_all_users():
    users = [u['username'] for u in list_users()]
    history = {}
    for user in users:
        home = run_cmd(f"dscl . -read /Users/{user} NFSHomeDirectory", allow_fail=True).replace("NFSHomeDirectory: ", "")
        histories = []
        for histfile in ['.bash_history', '.zsh_history', '.history']:
            path = os.path.join(home, histfile)
            if os.path.exists(path):
                try:
                    with open(path, 'r', errors='ignore') as f:
                        lines = f.readlines()[-20:]
                        histories.extend(lines)
                except Exception:
                    continue
        if histories:
            history[user] = [line.strip() for line in histories]
    print(f"Shell history collected for {len(history)} users")
    return history

def system_proxy_settings():
    output = run_cmd("scutil --proxy", allow_fail=True)
    print("System proxy settings fetched")
    return output

def launchd_cron_jobs():
    output = run_cmd("launchctl list", allow_fail=True)
    print("Launchd cron jobs enumerated")
    return output

def active_vpn_connections():
    output = run_cmd("scutil --nc list", allow_fail=True)
    print("VPN connections status fetched")
    return output

def dns_cache():
    output = run_cmd("dscacheutil -cachedump -entries Host", allow_fail=True)
    print("DNS cache entries fetched")
    return output

def brew_installed_packages():
    output = run_cmd("brew list --versions", allow_fail=True)
    print(f"Homebrew packages found")
    return output

def brew_cask_installed():
    output = run_cmd("brew list --cask", allow_fail=True)
    print(f"Homebrew cask applications found")
    return output

def mdm_profiles():
    output = run_cmd("profiles -P", allow_fail=True)
    print("MDM profiles enumerated")
    return output

def suspicious_permissions_usr_local():
    output = run_cmd("find /usr/local/bin /usr/bin -perm -222 -type f 2>/dev/null", allow_fail=True)
    files = output.splitlines() if output else []
    print(f"Suspicious writable files found: {len(files)}")
    return files

def shell_startup_scripts():
    users = [u['username'] for u in list_users()]
    scripts = {}
    for user in users:
        home = run_cmd(f"dscl . -read /Users/{user} NFSHomeDirectory", allow_fail=True).replace("NFSHomeDirectory: ", "")
        found_scripts = []
        for file in ['.bashrc', '.zshrc', '.profile', '.bash_profile']:
            path = os.path.join(home, file)
            if os.path.exists(path):
                found_scripts.append(file)
        if found_scripts:
            scripts[user] = found_scripts
    print(f"Shell startup scripts found for {len(scripts)} users")
    return scripts

def locale_timezone():
    locale = run_cmd("locale", allow_fail=True)
    timezone = run_cmd("systemsetup -gettimezone", allow_fail=True)
    print(f"Locale and timezone fetched")
    return {"locale": locale, "timezone": timezone}

def softwareupdate_cve_list():
    output = run_cmd("softwareupdate --list 2>&1", allow_fail=True)
    print("Available software updates fetched")
    return output

def bluetooth_paired_devices():
    output = run_cmd("system_profiler SPBluetoothDataType", allow_fail=True)
    print("Bluetooth devices enumerated")
    return output

def wifi_saved_networks():
    output = run_cmd("defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences KnownNetworks", allow_fail=True)
    print("WiFi saved networks fetched")
    return output

def check_rootkits():
    output = run_cmd("chkrootkit", allow_fail=True)
    if "command not found" in output.lower():
        output = "chkrootkit not installed"
    print("Rootkit check performed")
    return output

def sudoers_custom_entries():
    output = run_cmd("cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null", allow_fail=True)
    print("Sudoers custom entries fetched")
    return output

def important_logs():
    logs = run_cmd("tail -n 50 /var/log/system.log", allow_fail=True)
    print("Important logs extracted")
    return logs

def unsigned_kexts():
    output = run_cmd("kextstat | grep -v com.apple", allow_fail=True)
    unsigned = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 7:
            if "signed" not in line.lower():
                unsigned.append(parts[5])
    print(f"Unsigned kexts found: {len(unsigned)}")
    return unsigned

def filevault_status():
    output = run_cmd("fdesetup status", allow_fail=True)
    print(f"FileVault status: {output}")
    return output

def launchd_services_status():
    output = run_cmd("launchctl list", allow_fail=True)
    print("Launchd services status fetched")
    return output


def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def generate_report(data, fmt, output_file):
    if fmt == "json":
        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)
    elif fmt == "txt":
        with open(output_file, "w") as f:
            for k, v in data.items():
                f.write(f"{k}:\n{v}\n\n")
    elif fmt == "csv":
        flat_data = flatten_dict(data)
        with open(output_file, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(flat_data.keys())
            writer.writerow(flat_data.values())
    print(f"Report exported to {output_file} ({fmt})")

def main():
    parser = argparse.ArgumentParser(description="macOffense - Advanced macOS Reconnaissance")
    parser.add_argument('-e', '--export', choices=['json','txt','csv'], help='Export report format')
    parser.add_argument('-o', '--output', type=str, help='Output file path')
    args = parser.parse_args()

    print("Starting MacOffense recon...")

    report = {}

    report["macOS_Version"] = get_macos_version()
    report["Architecture"] = get_architecture()
    report["SIP_Status"] = get_sip_status()
    report["Loaded_Kexts"] = get_loaded_kexts()
    report["Launch_Agents"] = get_launch_agents()
    report["Users"] = list_users()
    report["Groups"] = list_groups()
    report["Cron_Jobs"] = list_cron_jobs()
    report["Firewall_Status"] = get_firewall_status()
    report["Installed_Applications"] = list_applications()
    report["Network_Info"] = get_network_info()
    report["Sensitive_File_Permissions"] = check_file_permissions(['/etc/sudoers', '/etc/passwd'])
    report["Open_Ports"] = scan_open_ports()
    report["Root_Processes"] = list_root_processes()
    report["SUID_Files"] = list_suid_files()
    report["TCC_Profiles"] = list_tcc_profiles()
    report["Gatekeeper_Status"] = get_gatekeeper_status()
    report["Kernel_Crash_Logs"] = get_kernel_crash_logs()
    report["USB_Devices"] = list_usb_devices()
    report["Time_Machine_Status"] = get_time_machine_status()
    report["Mounted_Volumes"] = list_mounted_volumes()
    report["Active_SSH_Sessions"] = get_ssh_sessions()
    report["Recent_Etc_Changes"] = recent_etc_changes()
    report["Recent_Usr_Local_Etc_Changes"] = recent_usr_local_etc_changes()
    report["Shell_History_All_Users"] = shell_history_all_users()
    report["System_Proxy_Settings"] = system_proxy_settings()
    report["Launchd_Cron_Jobs"] = launchd_cron_jobs()
    report["Active_VPN_Connections"] = active_vpn_connections()
    report["DNS_Cache"] = dns_cache()
    report["Brew_Installed_Packages"] = brew_installed_packages()
    report["Brew_Cask_Installed"] = brew_cask_installed()
    report["MDM_Profiles"] = mdm_profiles()
    report["Suspicious_Permissions_Usr_Local"] = suspicious_permissions_usr_local()
    report["Shell_Startup_Scripts"] = shell_startup_scripts()
    report["Locale_Timezone"] = locale_timezone()
    report["Softwareupdate_CVE_List"] = softwareupdate_cve_list()
    report["Bluetooth_Paired_Devices"] = bluetooth_paired_devices()
    report["WiFi_Saved_Networks"] = wifi_saved_networks()
    report["Rootkit_Check"] = check_rootkits()
    report["Sudoers_Custom_Entries"] = sudoers_custom_entries()
    report["Important_Logs"] = important_logs()
    report["Unsigned_Kexts"] = unsigned_kexts()
    report["FileVault_Status"] = filevault_status()
    report["Launchd_Services_Status"] = launchd_services_status()

    report["Scan_Timestamp"] = datetime.utcnow().isoformat() + "Z"

    if args.export and args.output:
        generate_report(report, args.export, args.output)
    elif args.export and not args.output:
        print("[!] Export format specified but the output file wasn't provided :(")

if __name__ == "__main__":
    main()
