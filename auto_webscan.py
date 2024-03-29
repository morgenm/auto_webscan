# Script for scanning web apps
import argparse
import subprocess
import os
from multiprocessing import Process
import time
import logging

# Constants
FEROX_OUTPUT = "ferox.txt"
NIKTO_OUTPUT = "nikto.html"
WHATWEB_OUTPUT = "whatweb.txt"
NMAP_OUTPUT = "nmap.txt"
NIKTO_ERROR = "Invalid argument at /var/lib/nikto/plugins/LW2.pm line 5254"

# Function to handle proxy and cookies flags.
def handle_proxy_cookies(args, proxy, cookies, proxy_flag, cookie_flag, extra_flags=[]):
    if proxy is not None: # Use proxy
        args += [proxy_flag, proxy]
    if cookies is not None: # Set cookies
        args += [cookie_flag, cookies]
    args += extra_flags
    return args

def run_feroxbuster(target, scan_dir, proxy, cookies, threaded):
    # Run feroxbuster
    ferox_args = ["feroxbuster", "-u", target, "-o", f"{scan_dir}/{FEROX_OUTPUT}"]
    ferox_args = handle_proxy_cookies(ferox_args, proxy, cookies, "-p", "-b", ["--insecure",])

    ferox_args.append("--no-state") # Don't use state files for now at least.
    if threaded:
        subprocess.run(ferox_args, capture_output=True)
    else:
        subprocess.run(ferox_args)

def run_nikto_scan(target, scan_dir, proxy, cookies, threaded):
    # Run nikto
    nikto_args = ["nikto", "-h", target, "-Format", "html", "-o", f"{scan_dir}/{NIKTO_OUTPUT}"]
    nikto_args = handle_proxy_cookies(nikto_args, proxy, f"STATIC-COOKIE=\"{cookies}\"", "-useproxy", "-O")

    nikto_proc = None
    if threaded:
        nikto_proc = subprocess.run(nikto_args, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    else:
        nikto_proc = subprocess.run(nikto_args, stderr=subprocess.PIPE)

    if NIKTO_ERROR in nikto_proc.stderr.decode():
        logging.error("Nikto proxy error. Try adding \"LW_SSL_ENGINE=SSLeay\" to the nikto.conf file.")

def run_whatweb(target, scan_dir, proxy, cookies, threaded):
    # Run whatweb
    whatweb_args = ["whatweb", "-a", "4", f"--log-verbose={scan_dir}/{WHATWEB_OUTPUT}"]

    # PROXY ERROR: https://github.com/urbanadventurer/WhatWeb/issues/389
    whatweb_args = handle_proxy_cookies(whatweb_args, None, cookies, "", "-c") # Set cookies.
    
    whatweb_args.append(target)

    whatweb_proc = None
    if threaded:
        whatweb_proc = subprocess.run(whatweb_args, capture_output=True)
    else:
        whatweb_proc = subprocess.run(whatweb_args, stdout=subprocess.PIPE)
        logging.info(whatweb_proc.stdout.decode())

# No proxying or cookies with nmap.
def run_nmap_web_scan(target, scan_dir, proxy, cookies, threaded):
    # Run nmap
    nmap_args = ["nmap", "-sV", "-p", "443,80", "-v", "--script=vuln", "-oN", f"{scan_dir}/{NMAP_OUTPUT}", target.split("//")[1]]

    nmap_proc = None
    if threaded:
        nmap_proc = subprocess.run(nmap_args, capture_output=True)
    else:
        nmap_proc = subprocess.run(nmap_args)

def main(args):
    tools_funcs = {"ferox" : run_feroxbuster, "nikto" : run_nikto_scan, "whatweb" : run_whatweb, "nmap" : run_nmap_web_scan}

    # Ensure arguments are valid.
    for tool in args.scan_tools:
        if tool not in tools_funcs:
            logging.error("%s is not a valid tool. Valid tools: %s.", tool, ",".join(tools_funcs.keys()))
            exit(1)

    # Set logging level and format.
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Make output dirs
    try:
        os.mkdir("web_app_scans") # Top level dir
    except FileExistsError:
        logging.warning("web_app_scans dir already exists. Not creating it.")

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
        logging.warning("%s dir already exists. Not creating it.", scan_dir)

    if args.threads is not None and args.threads > 1:
        procs = []
        for tool in args.scan_tools:
            procs.append((tool, Process(target=tools_funcs[tool], args=(args.target, scan_dir, args.proxy, args.cookies, True))))

        running_procs = []
        finished_procs = []
        while len(finished_procs) != len(procs):
            for i in range(len(procs)):
                if i not in running_procs and len(running_procs) < args.threads and i not in finished_procs:
                    procs[i][1].start()
                    running_procs.append(i)
                    logging.info("%s started running.", procs[i][0])
                elif i in running_procs:
                    if not procs[i][1].is_alive():
                        finished_procs.append(i)
                        running_procs.remove(i)
                        logging.info("%s finished running.", procs[i][0])

            time.sleep(1)
    
    else: # Run consecutively.
        for tool in args.scan_tools:
            tools_funcs[tool](args.target, scan_dir, args.proxy, args.cookies, False)

def comma_separated_strings(input_string):
    return input_string.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple script for automating web app scans.")
    parser.add_argument("target", type=str, help="URL of target.")
    parser.add_argument("-p", "--proxy", type=str, help="HTTP Proxy. Example: http://localhost:8080")
    parser.add_argument("-c", "--cookies", type=str, help="HTTP Cookies. Example: --cookies \"auth=token;cool=wow\"")
    parser.add_argument("-t", "--threads", type=int, default=None, help="Number of processes (threads). Run multiple processes simulatenously for faster scans.")
    parser.add_argument("-s", "--scan-tools", type=comma_separated_strings, default=["ferox", "nikto", "whatweb", "nmap"], help="Comma separated list of scan tools to run. Default: ferox,nikto,whatweb,nmap")

    args = parser.parse_args()


    main(args)