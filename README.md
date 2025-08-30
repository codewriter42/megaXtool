# megaXtool

MegaXTool

MegaXTool is a comprehensive Cybersecurity Installer Tool that allows you to quickly install 210+ security tools in 7 main categories using a menu-driven interface. Designed for Termux and Linux environments, it provides easy access to reconnaissance, network scanning, Wi-Fi testing, password cracking, defensive monitoring, and more.

Features

210 tools included across 7 categories:

1. 🌐 IP / Network Lookup


2. 🔍 Recon & OSINT


3. ⚡ Exploit / Vulnerability


4. 🕵 MITM & Packet Sniffing


5. 🔐 Password Cracking


6. 📡 Wi-Fi Tools


7. 🛡 Defensive / Monitoring



Menu-driven interface for easy navigation

Automatic installation via pkg install or git clone

Runs directly on Termux or compatible Linux systems

Requirements

Termux (or any Debian/Ubuntu based Linux)

Python 3 installed

Git installed (pkg install git -y)

Installation

1. Update Termux packages



<code>pkg update && pkg upgrade -y
pkg install python git -y</code>

2. Clone MegaXTool repository



<code>git clone https://github.com/codewriter42/megaXtool.git
cd megaXtool</code>

3. Run the tool



<code>python3 megaxtool.py</code>


Usage

1. When you start MegaXTool, a menu will appear with 7 main categories.


2. Enter the number of the category you want to explore.


3. A list of tools for that category will appear (each with a number).


4. Enter the number of the tool you want to install.


5. The tool will automatically download and install via pkg install or git clone.


6. Type q to go back to the main menu at any time.


Example

=== Cyber Security Installer Menu ===
1. 🌐 IP / Network Lookup
2. 🔍 Recon & OSINT
3. ⚡ Exploit / Vulnerability
4. 🕵 MITM & Packet Sniffing
5. 🔐 Password Cracking
6. 📡 Wi-Fi Tools
7. 🛡 Defensive / Monitoring
8. ❌ Exit

Category select: 1
=== 🌐 IP / Network Lookup ===
1. ipinfo
2. nmap
3. whois
...
Select tool to install (q to go back): 2

The selected tool (nmap) will now install automatically.

Notes

Some tools may require additional configuration after installation.

GUI-based tools like Maltego, Burp Suite, or Wireshark require a GUI environment.

Always use these tools ethically and legally.

