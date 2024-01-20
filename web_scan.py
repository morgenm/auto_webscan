# Script for scanning web apps
import argparse
import subprocess
import os
from multiprocessing import Process
import time

# Constants
FEROX_OUTPUT = "/ferox.txt"
NIKTO_OUTPUT = "/nikto.html"
WHATWEB_OUTPUT = "/whatweb.txt"
NMAP_OUTPUT = "/nmap.txt"
NIKTO_ERROR = "Invalid argument at /var/lib/nikto/plugins/LW2.pm line 5254"

def feroxbuster(target, scan_dir, proxy, cookies, threaded):
    # Run feroxbuster
    ferox_args = ["feroxbuster", "-u", target, "-o", f"{scan_dir}/{FEROX_OUTPUT}"]

    if proxy is not None: # Use proxy
        ferox_args += ["-p", proxy, "--insecure"]
    if cookies is not None: # Set cookies
        ferox_args += ["-b", cookies]

    ferox_args.append("--no-state") # Don't use state files for now at least.
    if threaded:
        subprocess.run(ferox_args, capture_output=True)
    else:
        subprocess.run(ferox_args)

def nikto_scan(target, scan_dir, proxy, cookies, threaded):
    # Run nikto
    nikto_args = ["nikto", "-h", target, "-Format", "html", "-o", f"{scan_dir}/{NIKTO_OUTPUT}"]

    if proxy is not None: # Use proxy
        nikto_args += ["-useproxy", proxy, "-O", "LW_SSL_ENGINE=SSLeay"]
    if cookies is not None: # Set cookies
        nikto_args += ["-O", f"STATIC-COOKIE=\"{cookies}\""]
    
    nikto_proc = None
    if threaded:
        nikto_proc = subprocess.run(nikto_args, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    else:
        nikto_proc = subprocess.run(nikto_args, stderr=subprocess.PIPE)

    if NIKTO_ERROR in nikto_proc.stderr.decode():
        print("[!] Nikto proxy error. Try adding \"LW_SSL_ENGINE=SSLeay\" to the nikto.conf file.")

def what_web(target, scan_dir, proxy, cookies, threaded):
    # Run whatweb
    whatweb_args = ["whatweb", "-a", "4", f"--log-verbose={scan_dir}/{WHATWEB_OUTPUT}"]

    # PROXY ERROR: https://github.com/urbanadventurer/WhatWeb/issues/389
    #if proxy is not None: # Use proxy
    #whatweb_args += ["--proxy", proxy.split("//")[1]]
    if cookies is not None: # Set cookies
        whatweb_args += ["-c", cookies]

    whatweb_args.append(target)

    whatweb_proc = None
    if threaded:
        whatweb_proc = subprocess.run(whatweb_args, capture_output=True)
    else:
        whatweb_proc = subprocess.run(whatweb_args, stdout=subprocess.PIPE)
        print(whatweb_proc.stdout.decode())

# No proxying or cookies with nmap.
def nmap_web_scan(target, scan_dir, proxy, cookies, threaded):
    # Run nmap
    nmap_args = ["nmap", "-sV", "-p", "443,80", "-v", "--script=vuln", "-oN", f"{scan_dir}/{NMAP_OUTPUT}", target.split("//")[1]]

    nmap_proc = None
    if threaded:
        nmap_proc = subprocess.run(nmap_args, capture_output=True)
    else:
        nmap_proc = subprocess.run(nmap_args)


def main(args):
    # Make output dirs
    try:
        os.mkdir("web_app_scans") # Top level dir
    except FileExistsError:
        print("[~] web_app_scans dir already exists. Not creating it.")

    # Full scan dir based on target host
    scan_dir = args.target
    if "https://" in scan_dir:
        scan_dir = scan_dir.split("https://")[1]
    elif "http://" in scan_dir:
        scan_dir = scan_dir.split("http://")[1]
    if '/' in scan_dir:
        scan_dir = scan_dir.split('/')[0]
    scan_dir = f"web_app_scans/{scan_dir}"

    try:
        os.mkdir(scan_dir)
    except FileExistsError:
        print(f"[~] {scan_dir} dir already exists. Not creating it.")
    

    if args.threads is not None and args.threads > 1:
        procs = []
        ferox_proc = Process(target=feroxbuster, args=(args.target, scan_dir, args.proxy, args.cookies,True))
        procs.append(("Ferox", ferox_proc))
        nikto_proc = Process(target=nikto_scan, args=(args.target, scan_dir, args.proxy, args.cookies, True))
        procs.append(("Nikto", nikto_proc))
        whatweb_proc = Process(target=what_web, args=(args.target, scan_dir, args.proxy, args.cookies, True))
        procs.append(("WhatWeb", whatweb_proc))
        nmap_proc = Process(target=nmap_web_scan, args=(args.target, scan_dir, args.proxy, args.cookies, True))
        procs.append(("Nmap", nmap_proc))

        running_procs = []
        finished_procs = []
        while len(finished_procs) != len(procs):
            for i in range(len(procs)):
                if i not in running_procs and len(running_procs) < args.threads and i not in finished_procs:
                    procs[i][1].start()
                    running_procs.append(i)
                    print(f"[~] {procs[i][0]} started running.")
                elif i in running_procs:
                    if not procs[i][1].is_alive():
                        finished_procs.append(i)
                        running_procs.remove(i)
                        print(f"[~] {procs[i][0]} finished running.")

            time.sleep(1)
    
    else: # Run consecutively.
        feroxbuster(args.target, scan_dir, args.proxy, args.cookies, False)
        nikto_scan(args.target, scan_dir, args.proxy, args.cookies, False)
        what_web(args.target, scan_dir, args.proxy, args.cookies, False)
        nmap_web_scan(args.target, scan_dir, args.proxy, args.cookies, False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple script for automating web app scans.")
    parser.add_argument("target", type=str, help="URL of target.")
    parser.add_argument("-p", "--proxy", type=str, help="HTTP Proxy. Example: http://localhost:8080")
    parser.add_argument("-c", "--cookies", type=str, help="HTTP Cookies. Example: --cookies \"auth=token;cool=wow\"")
    parser.add_argument("-t", "--threads", type=int, default=None, help="Number of processes (threads). Run multiple processes simulatenously for faster scans.")

    args = parser.parse_args()


    main(args)