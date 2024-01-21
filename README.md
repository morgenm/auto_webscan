# auto_webscan

This is a Python script for streamlining web application scanning. It integrates several popular scanning tools: Feroxbuster, Nikto, WhatWeb, and Nmap. This project was inspired by the absence of HTTP proxy support in [AutoRecon](https://github.com/Tib3rius/AutoRecon). **auto_webscan** incorporates HTTP proxy support where possible, enabling tools like Burp or ZAP to view and log requests. In addition, this is useful for letting Burp and ZAP construct a site-map of the target site(s). 

## Requirements

* Required tools: Feroxbuster, Nikto, WhatWeb, and Nmap.
* `Python 3.x` installation. 

## Using auto_webscan

To use this tool, clone this repo and run the python script.

```bash
python3 auto_webscan.py <target> [-p <proxy>] [-c <cookies>] [-t <threads>] [-s <scan-tools>]
```

For additional help, use:
```bash
python3 auto_webscan.py --help
```

## HTTP Proxy Support
Proxy support is available for the following tools:
* feroxbuster
* nikto

Proxies are not supported for:
* nmap
* whatweb (See [this issue](https://github.com/urbanadventurer/WhatWeb/issues/389))

## License
This project is licensed under the MIT license. See the LICENSE.md file.