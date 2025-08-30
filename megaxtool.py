import os

def install_tool(tool_name, install_cmd):
    print(f"\n[+] Installing {tool_name} ...\n")
    os.system(install_cmd)
    print(f"\n[✓] {tool_name} installed!\n")

def show_menu(title, tools):
    while True:
        print(f"\n=== {title} ===")
        for key, val in tools.items():
            print(f"{key}. {val[0]}")
        choice = input("\nSeç (q: geri): ")
        if choice in tools:
            install_tool(tools[choice][0], tools[choice][1])
        elif choice.lower() == "q":
            break
        else:
            print("Geçersiz seçim!")

# 🌐 IP / Network Lookup (30 tool)
ip_lookup_tools = {
    "1": ("ipinfo", "pkg install curl -y && curl ipinfo.io"),
    "2": ("nmap", "pkg install nmap -y"),
    "3": ("whois", "pkg install whois -y"),
    "4": ("dnsutils", "pkg install dnsutils -y"),
    "5": ("traceroute", "pkg install traceroute -y"),
    "6": ("masscan", "git clone https://github.com/robertdavidgraham/masscan.git"),
    "7": ("hping3", "pkg install hping3 -y"),
    "8": ("netcat", "pkg install netcat -y"),
    "9": ("mtr", "pkg install mtr -y"),
    "10": ("arp-scan", "git clone https://github.com/royhills/arp-scan.git"),
    "11": ("ipcalc", "pkg install ipcalc -y"),
    "12": ("dig", "pkg install dnsutils -y"),
    "13": ("ping", "pkg install iputils -y"),
    "14": ("curl", "pkg install curl -y"),
    "15": ("wget", "pkg install wget -y"),
    "16": ("sslscan", "git clone https://github.com/rbsec/sslscan.git"),
    "17": ("p0f", "git clone https://github.com/p0f/p0f.git"),
    "18": ("zmap", "git clone https://github.com/zmap/zmap.git"),
    "19": ("fping", "pkg install fping -y"),
    "20": ("ike-scan", "git clone https://github.com/royhills/ike-scan.git"),
    "21": ("nbtscan", "pkg install nbtscan -y"),
    "22": ("tcping", "git clone https://github.com/cloverstd/tcping.git"),
    "23": ("httpie", "pkg install httpie -y"),
    "24": ("whatweb", "git clone https://github.com/urbanadventurer/WhatWeb.git"),
    "25": ("httprobe", "git clone https://github.com/tomnomnom/httprobe.git"),
    "26": ("asnmap", "git clone https://github.com/projectdiscovery/asnmap.git"),
    "27": ("naabu", "git clone https://github.com/projectdiscovery/naabu.git"),
    "28": ("mapcidr", "git clone https://github.com/projectdiscovery/mapcidr.git"),
    "29": ("ipscan", "git clone https://github.com/angryip/ipscan.git"),
    "30": ("subnetcalc", "git clone https://github.com/mahrlund/subnetcalc.git")
}

# 🔍 Recon & OSINT (30 tool)
recon_tools = {
    "1": ("theHarvester", "git clone https://github.com/laramies/theHarvester.git"),
    "2": ("amass", "pkg install amass -y"),
    "3": ("subfinder", "git clone https://github.com/projectdiscovery/subfinder.git"),
    "4": ("recon-ng", "git clone https://github.com/lanmaster53/recon-ng.git"),
    "5": ("dmitry", "pkg install dmitry -y"),
    "6": ("fierce", "git clone https://github.com/mschwager/fierce.git"),
    "7": ("maltego", "echo 'Install manually (GUI)'"),
    "8": ("spiderfoot", "git clone https://github.com/smicallef/spiderfoot.git"),
    "9": ("ghunt", "git clone https://github.com/mxrch/GHunt.git"),
    "10": ("shodan", "pkg install shodan -y"),
    "11": ("metagoofil", "git clone https://github.com/laramies/metagoofil.git"),
    "12": ("dnsenum", "pkg install dnsenum -y"),
    "13": ("crt.sh", "echo 'Use via website'"),
    "14": ("urlscan", "git clone https://github.com/pielco11/urlscan.git"),
    "15": ("hunter.io", "echo 'Use via website'"),
    "16": ("linkedin2username", "git clone https://github.com/initstring/linkedin2username.git"),
    "17": ("twint", "git clone https://github.com/twintproject/twint.git"),
    "18": ("socialscan", "git clone https://github.com/iojw/socialscan.git"),
    "19": ("phoneinfoga", "git clone https://github.com/sundowndev/phoneinfoga.git"),
    "20": ("ghrepo", "git clone https://github.com/ethicalhackingplayground/ghrepo.git"),
    "21": ("gitrob", "git clone https://github.com/michenriksen/gitrob.git"),
    "22": ("trufflehog", "git clone https://github.com/trufflesecurity/trufflehog.git"),
    "23": ("datasploit", "git clone https://github.com/DataSploit/datasploit.git"),
    "24": ("pwndb", "git clone https://github.com/davidtavarez/pwndb.git"),
    "25": ("leakcheck", "git clone https://github.com/kitabisa/leakcheck.git"),
    "26": ("holehe", "git clone https://github.com/megadose/holehe.git"),
    "27": ("sherlock", "git clone https://github.com/sherlock-project/sherlock.git"),
    "28": ("maigret", "git clone https://github.com/soxoj/maigret.git"),
    "29": ("osintgram", "git clone https://github.com/Datalux/Osintgram.git"),
    "30": ("tinfoleak", "git clone https://github.com/vaguileradiaz/tinfoleak.git")
}

# ⚡ Exploit / Vulnerability (30 tool)
exploit_tools = {
    "1": ("sqlmap", "pkg install sqlmap -y"),
    "2": ("nikto", "git clone https://github.com/sullo/nikto.git"),
    "3": ("nuclei", "git clone https://github.com/projectdiscovery/nuclei.git"),
    "4": ("wpscan", "git clone https://github.com/wpscanteam/wpscan.git"),
    "5": ("xsstrike", "git clone https://github.com/s0md3v/XSStrike.git"),
    "6": ("commix", "git clone https://github.com/commixproject/commix.git"),
    "7": ("dirb", "pkg install dirb -y"),
    "8": ("gobuster", "pkg install gobuster -y"),
    "9": ("dirsearch", "git clone https://github.com/maurosoria/dirsearch.git"),
    "10": ("arachni", "git clone https://github.com/Arachni/arachni.git"),
    "11": ("skipfish", "git clone https://github.com/spinkham/skipfish.git"),
    "12": ("joomscan", "git clone https://github.com/OWASP/joomscan.git"),
    "13": ("cmsmap", "git clone https://github.com/Dionach/CMSmap.git"),
    "14": ("davtest", "git clone https://github.com/cldrn/davtest.git"),
    "15": ("wafw00f", "git clone https://github.com/EnableSecurity/wafw00f.git"),
    "16": ("fuxploider", "git clone https://github.com/almandin/fuxploider.git"),
    "17": ("payloadsallthethings", "git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git"),
    "18": ("exploitdb", "git clone https://gitlab.com/exploit-database/exploitdb.git"),
    "19": ("searchsploit", "pkg install exploitdb -y"),
    "20": ("routersploit", "git clone https://github.com/threat9/routersploit.git"),
    "21": ("beef-xss", "git clone https://github.com/beefproject/beef.git"),
    "22": ("sqliv", "git clone https://github.com/the-robot/sqliv.git"),
    "23": ("xsssniper", "git clone https://github.com/gbrindisi/xsssniper.git"),
    "24": ("brutespray", "git clone https://github.com/x90skysn3k/brutespray.git"),
    "25": ("hydra", "pkg install hydra -y"),
    "26": ("medusa", "pkg install medusa -y"),
    "27": ("crackmapexec", "git clone https://github.com/Porchetta-Industries/CrackMapExec.git"),
    "28": ("legion", "git clone https://github.com/carlospolop/legion.git"),
    "29": ("acccheck", "git clone https://github.com/cytopia/acccheck.git"),
    "30": ("jwt_tool", "git clone https://github.com/ticarpi/jwt_tool.git")
}

# 🕵 MITM & Packet Sniffing (30 tool)
mitm_tools = {
    "1": ("wireshark", "pkg install wireshark -y"),
    "2": ("tcpdump", "pkg install tcpdump -y"),
    "3": ("bettercap", "git clone https://github.com/bettercap/bettercap.git"),
    "4": ("ettercap", "pkg install ettercap -y"),
    "5": ("dsniff", "pkg install dsniff -y"),
    "6": ("mitmproxy", "pkg install mitmproxy -y"),
    "7": ("arpspoof", "pkg install dsniff -y"),
    "8": ("sslstrip", "git clone https://github.com/moxie0/sslstrip.git"),
    "9": ("driftnet", "git clone https://github.com/deiv/driftnet.git"),
    "10": ("urlsnarf", "pkg install dsniff -y"),
    "11": ("webmitm", "pkg install dsniff -y"),
    "12": ("hamster", "git clone https://github.com/d0c-s4vage/hamster.git"),
    "13": ("ferret", "git clone https://github.com/seifreed/ferret.git"),
    "14": ("kickthemout", "git clone https://github.com/k4m4/kickthemout.git"),
    "15": ("lanmap2", "git clone https://github.com/raviagarwal7/lanmap2.git"),
    "16": ("pyrit", "git clone https://github.com/JPaulMora/Pyrit.git"),
    "17": ("sslscan", "git clone https://github.com/rbsec/sslscan.git"),
    "18": ("netsniff-ng", "git clone https://github.com/netsniff-ng/netsniff-ng.git"),
    "19": ("dsniff-tools", "pkg install dsniff -y"),
    "20": ("macchanger", "pkg install macchanger -y"),
    "21": ("iptraf", "pkg install iptraf-ng -y"),
    "22": ("paros", "git clone https://github.com/zaproxy/zaproxy.git"),
    "23": ("zaproxy", "git clone https://github.com/zaproxy/zaproxy.git"),
    "24": ("burpsuite", "echo 'Manual install (GUI)'"),
    "25": ("netsed", "pkg install netsed -y"),
    "26": ("proxychains", "pkg install proxychains-ng -y"),
    "27": ("redsocks", "git clone https://github.com/darkk/redsocks.git"),
    "28": ("mitmf", "git clone https://github.com/byt3bl33d3r/MITMf.git"),
    "29": ("chaosreader", "git clone https://github.com/brendangregg/chaosreader.git"),
    "30": ("netsniffer", "git clone https://github.com/netsniff-ng/netsniff-ng.git")
}

# 🔐 Password Cracking (30 tool)
password_tools = {
    "1": ("john", "pkg install john -y"),
    "2": ("hashcat", "git clone https://github.com/hashcat/hashcat.git"),
    "3": ("hydra", "pkg install hydra -y"),
    "4": ("medusa", "pkg install medusa -y"),
    "5": ("cewl", "pkg install cewl -y"),
    "6": ("crunch", "pkg install crunch -y"),
    "7": ("maskprocessor", "git clone https://github.com/hashcat/maskprocessor.git"),
    "8": ("rsmangler", "git clone https://github.com/digininja/RSMangler.git"),
    "9": ("wordlister", "git clone https://github.com/3ndG4me/wordlister.git"),
    "10": ("brutespray", "git clone https://github.com/x90skysn3k/brutespray.git"),
    "11": ("hashid", "git clone https://github.com/psypanda/hashID.git"),
    "12": ("rainbowcrack", "git clone https://github.com/bit4woo/RainbowCrack.git"),
    "13": ("ophcrack", "git clone https://github.com/ophcrack/ophcrack.git"),
    "14": ("chntpw", "pkg install chntpw -y"),
    "15": ("samdump2", "pkg install samdump2 -y"),
    "16": ("fgdump", "git clone https://github.com/haircut/fgdump.git"),
    "17": ("pwdump", "git clone https://github.com/Neohapsis/creddump.git"),
    "18": ("l0phtcrack", "echo 'Manual install'"),
    "19": ("ophcrack-tables", "echo 'Manual download required'"),
    "20": ("hashpump", "git clone https://github.com/bwall/HashPump.git"),
    "21": ("thc-pptp-bruter", "git clone https://github.com/vanhauser-thc/thc-pptp-bruter.git"),
    "22": ("smbmap", "git clone https://github.com/ShawnDEvans/smbmap.git"),
    "23": ("enum4linux", "git clone https://github.com/CiscoCXSecurity/enum4linux.git"),
    "24": ("kerbrute", "git clone https://github.com/ropnop/kerbrute.git"),
    "25": ("impacket", "git clone https://github.com/fortra/impacket.git"),
    "26": ("pipal", "git clone https://github.com/digininja/pipal.git"),
    "27": ("crowbar", "git clone https://github.com/galkan/crowbar.git"),
    "28": ("medusa", "pkg install medusa -y"),
    "29": ("ncrack", "pkg install ncrack -y"),
    "30": ("wordlists", "pkg install wordlists -y")
}

# 📡 Wi-Fi Tools (30 tool)
wifi_tools = {
    "1": ("aircrack-ng", "pkg install aircrack-ng -y"),
    "2": ("kismet", "pkg install kismet -y"),
    "3": ("wifite", "git clone https://github.com/derv82/wifite2.git"),
    "4": ("reaver", "pkg install reaver -y"),
    "5": ("bully", "git clone https://github.com/aanarchyy/bully.git"),
    "6": ("fern-wifi-cracker", "git clone https://github.com/savio-code/fern-wifi-cracker.git"),
    "7": ("cowpatty", "git clone https://github.com/joswr1ght/cowpatty.git"),
    "8": ("asleap", "git clone https://github.com/joswr1ght/asleap.git"),
    "9": ("mdk3", "git clone https://github.com/wi-fi-analyzer/mdk3-master.git"),
    "10": ("mdk4", "git clone https://github.com/aircrack-ng/mdk4.git"),
    "11": ("airodump-ng", "pkg install aircrack-ng -y"),
    "12": ("aireplay-ng", "pkg install aircrack-ng -y"),
    "13": ("airolib-ng", "pkg install aircrack-ng -y"),
    "14": ("wifi-honey", "git clone https://github.com/arnydo/wifi-honey.git"),
    "15": ("roguehostapd", "git clone https://github.com/wifiphisher/roguehostapd.git"),
    "16": ("wifiphisher", "git clone https://github.com/wifiphisher/wifiphisher.git"),
    "17": ("hostapd", "pkg install hostapd -y"),
    "18": ("hcxtools", "git clone https://github.com/ZerBea/hcxtools.git"),
    "19": ("hcxkeys", "git clone https://github.com/ZerBea/hcxkeys.git"),
    "20": ("pyrit", "git clone https://github.com/JPaulMora/Pyrit.git"),
    "21": ("wifi-pump", "git clone https://www.github.com/savio-code/wifi-pump.git"),
    "22": ("wash", "pkg install reaver -y"),
    "23": ("pixiewps", "git clone https://github.com/wi-fi-analyzer/pixiewps.git"),
    "24": ("wifijammer", "git clone https://github.com/DanMcInerney/wifijammer.git"),
    "25": ("airmon-ng", "pkg install aircrack-ng -y"),
    "26": ("netdiscover", "pkg install netdiscover -y"),
    "27": ("kismet-drone", "pkg install kismet -y"),
    "28": ("airolib-ng-cracker", "pkg install aircrack-ng -y"),
    "29": ("wifi-hacker-tools", "git clone https://github.com/xdavidhu/wi-fi-hacker-tools.git"),
    "30": ("fern-wifi-report", "git clone https://github.com/savio-code/fern-wifi-report.git")
}

# 🛡 Defensive / Monitoring (30 tool)
defense_tools = {
    "1": ("fail2ban", "pkg install fail2ban -y"),
    "2": ("ufw", "pkg install ufw -y"),
    "3": ("iptables", "pkg install iptables -y"),
    "4": ("psad", "pkg install psad -y"),
    "5": ("tripwire", "pkg install tripwire -y"),
    "6": ("rkhunter", "pkg install rkhunter -y"),
    "7": ("chkrootkit", "pkg install chkrootkit -y"),
    "8": ("logwatch", "pkg install logwatch -y"),
    "9": ("snort", "pkg install snort -y"),
    "10": ("suricata", "pkg install suricata -y"),
    "11": ("ossec", "pkg install ossec-hids -y"),
    "12": ("wazuh", "git clone https://github.com/wazuh/wazuh.git"),
    "13": ("bro", "pkg install zeek -y"),
    "14": ("clamav", "pkg install clamav -y"),
    "15": ("lynis", "pkg install lynis -y"),
    "16": ("aide", "pkg install aide -y"),
    "17": ("chkconfig", "pkg install chkconfig -y"),
    "18": ("netstat", "pkg install net-tools -y"),
    "19": ("iftop", "pkg install iftop -y"),
    "20": ("htop", "pkg install htop -y"),
    "21": ("vnstat", "pkg install vnstat -y"),
    "22": ("nethogs", "pkg install nethogs -y"),
    "23": ("tcpflow", "pkg install tcpflow -y"),
    "24": ("bandwhich", "git clone https://github.com/imsnif/bandwhich.git"),
    "25": ("glances", "pkg install glances -y"),
    "26": ("monit", "pkg install monit -y"),
    "27": ("collectd", "pkg install collectd -y"),
    "28": ("netdata", "git clone https://github.com/netdata/netdata.git"),
    "29": ("prometheus", "git clone https://github.com/prometheus/prometheus.git"),
    "30": ("grafana", "git clone https://github.com/grafana/grafana.git")
}

# Main Menu
def main_menu():
    while True:
        print("\n=== megaXtool ===")
        print("1. 🌐 IP / Network Lookup")
        print("2. 🔍 Recon & OSINT")
        print("3. ⚡ Exploit / Vulnerability")
        print("4. 🕵 MITM & Packet Sniffing")
        print("5. 🔐 Password Cracking")
        print("6. 📡 Wi-Fi Tools")
        print("7. 🛡 Defensive / Monitoring")
        print("8. ❌ Exit")

        choice = input("\nKategori seç: ")

        if choice == "1":
            show_menu("🌐 IP / Network Lookup", ip_lookup_tools)
        elif choice == "2":
            show_menu("🔍 Recon & OSINT", recon_tools)
        elif choice == "3":
            show_menu("⚡ Exploit / Vulnerability", exploit_tools)
        elif choice == "4":
            show_menu("🕵 MITM & Packet Sniffing", mitm_tools)
        elif choice == "5":
            show_menu("🔐 Password Cracking", password_tools)
        elif choice == "6":
            show_menu("📡 Wi-Fi Tools", wifi_tools)
        elif choice == "7":
            show_menu("🛡 Defensive / Monitoring", defense_tools)
        elif choice == "8":
            break
        else:
            print("Geçersiz seçim!")

if __name__ == "__main__":
    main_menu()
