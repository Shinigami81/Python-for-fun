import os
import platform
import subprocess

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Errore eseguendo il comando: {command}\n{str(e)}"

def enumerate_linux():
    print("=== Linux Enumeration ===")

    commands = {
        "Hostname": "hostname",
        "OS Version": "cat /etc/os-release",
        "Kernel Version": "uname -r",
        "Architecture": "uname -m",
        "Uptime": "uptime",
        "Active Users": "who -a",
        "Users with Shell Access": "cat /etc/passwd | grep -v nologin",
        "Sudo Permissions": "sudo -l",
        "Running Services": "systemctl list-units --type=service --state=running",
        "Processes": "ps aux",
        "Scheduled Tasks (cron jobs)": "ls -la /etc/cron.*",
        "Network Configuration": "ip a",
        "Listening Ports": "ss -tuln",
        "Installed Packages (Debian-based)": "dpkg -l || echo 'dpkg not available'",
        "Installed Packages (RHEL-based)": "rpm -qa || echo 'rpm not available'",
        "Password Policy": "cat /etc/login.defs",
        "PAM Configuration": "cat /etc/pam.d/common-auth"
    }

    for desc, cmd in commands.items():
        print(f"\n[{desc}]:\n{execute_command(cmd)}")

def enumerate_windows():
    print("=== Windows Enumeration ===")

    commands = {
        "Hostname": "hostname",
        "OS Version": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
        "System Architecture": "systeminfo | findstr /C:\"System Type\"",
        "System Uptime": "net statistics workstation | find \"Statistics since\"",
        "Active Users": "query user",
        "All Users": "net user",
        "Local Groups": "net localgroup",
        "Users in Administrators Group": "net localgroup Administrators",
        "Running Services": "net start",
        "Running Processes": "tasklist",
        "Scheduled Tasks": "schtasks /query /fo LIST /v",
        "Network Configuration": "ipconfig /all",
        "Active Network Connections": "netstat -ano",
        "Shared Folders": "net share",
        "Installed Software": "wmic product get name,version",
        "Installed Patches": "wmic qfe get Description,HotFixID,InstalledOn",
        "Password Policy": "net accounts",
        "User Access Control Settings": "secedit /export /cfg secedit.inf"
    }

    for desc, cmd in commands.items():
        print(f"\n[{desc}]:\n{execute_command(cmd)}")

def main():
    current_os = platform.system()
    if current_os == "Linux":
        enumerate_linux()
    elif current_os == "Windows":
        enumerate_windows()
    else:
        print(f"Sistema operativo non supportato: {current_os}")

if __name__ == "__main__":
    main()
