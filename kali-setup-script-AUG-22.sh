#!/bin/bash

# ===================================================
#
#  --------------------------------------------------
#  Bash Script to Setup a Kali VM on Windows 10 Non Scanner
#  --------------------------------------------------
#
#  Author:    Brian McGinn
#  Created:   March 2020
#  Last Edit: August 18 2022
#  Editor:    Akash Zatakia
# ====================================================

	# logging in as root user and changing the directory
	# sudo su -
	# cd /root

	# Make sure your root
	 if [ "$HOME" != "/root" ]
	 then
     	printf "Run while logged in as root\n"
     	exit 1
	 fi

	# Enable Command Aliasing
	shopt -s expand_aliases

	# Skip prompts in apt-upgrade, etc.
	export DEBIAN_FRONTEND=noninteractive
	alias apt-get='yes "" | apt-get -o Dpkg::Options::="--force-confdef" -y'

	# Update Repositories
	printf '\n============================================================\n'
	printf  '=========Update/Kali-Everything/Update/Upgrade\n'
	printf '============================================================\n\n'
	apt update
	apt install kali-linux-everything
	apt update
	apt upgrade
	apt full-upgrade

	apt install \
    	python3-virtualenv \
    	python3-dev \
    	python3-pip \
    	zmap \
    	htop \
    	zip \
    	terminator \
    	virtualenv \
    	python3-venv \
    	python3-shodan \
    	python3-censys \
    	jq \
    	sublist3r \
    	parallel

	pip install poetry
	python3 -m pip install lsassy
	python3 -m pip install pipenv
	python3 -m pip install apachetomcatscanner
	git clone https://github.com/ipc-security/bypass-url-parser.git
	git clone https://github.com/ipc-security/adfsbrute.git
	git clone https://github.com/ipc-security/zphisher.git
	git clone https://github.com/ipc-security/18-plus-Facebook-Phishing.git
	git clone https://github.com/ipc-security/Shhhloader.git
	git clone https://github.com/ipc-security/ScareCrow-CobaltStrike.git
	git clone https://github.com/ipc-security/youtube-phishing-page.git
	git clone https://github.com/ipc-security/http2smugl.git
	git clone https://github.com/ipc-security/365-Stealer.git
	git clone https://github.com/ipc-security/dehashQuery.git
	git clone https://github.com/ipc-security/o365creeper.git
	git clone https://github.com/ipc-security/cansina.git
	git clone https://github.com/ipc-security/favicon_hash_shodan.git
	git clone https://github.com/ipc-security/commix.git
	git clone https://github.com/ipc-security/ShellShockHunter.git
	git clone https://github.com/ipc-security/fireprox.git
	git clone https://github.com/ipc-security/procrustes.git

	# Install Docker/Docker Compose
	apt-get remove docker docker-engine docker.io containerd runc
	sudo apt-get install \
    	ca-certificates \
    	curl \
    	gnupg \
    	lsb-release
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \ "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \ $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
	apt-get update
	sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

	# Install Golang
	wget https://go.dev/dl/go1.19.linux-amd64.tar.gz
	tar -xzf go1.19.linux-amd64.tar.gz
	rm go1.19.linux-amd64.tar.gz
	printf '\nexport PATH=$PATH:/root/go/bin' >> ~/.zshrc
	source ~/.zshrc

	# Install Golang scripts
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/tomnomnom/assetfinder@latest
	go install github.com/OWASP/Amass/v3/...@latest
	go install github.com/bp0lr/gauplus@latest
	go install github.com/lc/gau/v2/cmd/gau@latest
	go install github.com/tomnomnom/waybackurls@latest
	go install github.com/gwen001/github-subdomains@latest
	go install github.com/cgboal/sonarsearch/cmd/crobat@latest
	go install github.com/glebarez/cero@latest
	go install github.com/tomnomnom/httprobe@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/tomnomnom/gf@latest
	go install github.com/tomnomnom/qsreplace@latest
	go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

	# Install Findomain
	printf '\n============================================================\n'
	printf  '=========Installing Findomain\n'
	printf '============================================================\n\n'
	curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
	unzip findomain-linux.zip
	rm findomain-linux.zip
	chmod +x findomain
	sudo mv findomain /bin

    # Install CTFR
	printf '\n============================================================\n'
	printf  '=========Installing CTFR\n'
	printf '============================================================\n\n'
	git clone https://github.com/UnaPibaGeek/ctfr.git
	cd ctfr
	pip3 install -r requirements.txt
	sudo chmod +x ctfr.py
	sudo mv ctfr.py /bin
	rm -r ctfr
	cd

    # Install Sudomy
	printf '\n============================================================\n'
	printf  '=========Installing Sudomy\n'
	printf '============================================================\n\n'
	git clone --recursive https://github.com/screetsec/Sudomy.git
    cd Sudomy
    python3 -m pip install -r requirements.txt
    sudo cp sudomy /usr/local/bin
    cd

    # Install Shodomain
	printf '\n============================================================\n'
	printf  '=========Installing Shodomain\n'
	printf '============================================================\n\n'
	git clone https://github.com/SmoZy92/Shodomain
    cd Shodomain
    pip install -r requirements.txt
    sudo chmod +x shodomain.py
    sudo mv shodomain.py /bin
    rm -r Shodamin
    cd

    # Install Censys-Subdomain-Finder
	printf '\n============================================================\n'
	printf  '=========Installing Censys-Subdomain-Finder\n'
	printf '============================================================\n\n'
	git clone https://github.com/christophetd/censys-subdomain-finder.git
    cd censys-subdomain-finder
    pip3 install -r requirements.txt
    sudo chmod +x censy-subdomain-finder.py
    sudo mv censy-subdomain-finder.py /bin
    rm -r censys-subdomain-finder
    cd

    # Install Pinkerton
	printf '\n============================================================\n'
	printf  '=========Installing Pinkerton\n'
	printf '============================================================\n\n'
	git clone https://github.com/oppsec/pinkerton.git
    cd pinkerton
    pip3 install -r requirements.txt
    cd

	# Install Sublime Text
	printf '\n============================================================\n'
	printf  '=========Installing Sublime Text\n'
	printf '============================================================\n\n'
	wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
	apt-get install apt-transport-https
	printf "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
	apt-get update
	apt-get install sublime-text

	# Install Bloodhound
	printf '\n============================================================\n'
	printf  '=========Installing Bloodhound\n'
	printf '============================================================\n\n'
	git clone https://github.com/fox-it/BloodHound.py.git
	cd BloodHound.py
	python3 setup.py install
	cd
	apt install bloodhound
	curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json"
	apt install neo4j
	neo4j console
	sleep 30
	echo -e "Open Browser to localhost:7474 login with user: neo4j pass: neo4j change password to IP20bmrbpz!"

	# Install Brute Shark
	printf '\n============================================================\n'
	printf  '=========Installing Brute Shark\n'
	printf '============================================================\n\n'
	wget https://github.com/odedshimon/BruteShark/releases/latest/download/BruteSharkCli

	#Download Cobalt Strike
	printf '\n============================================================\n'
	printf  '=========Downloading Cobalt Strike\n'
	printf '============================================================\n\n'
	wget --header 'Authorization: token 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' https://github.com/ipc-security/DownloadCobalt/archive/refs/heads/main.zip
	unzip main.zip
	rm main.zip
	cd DownloadCobalt-main
	chmod +x download-cobalt.sh
	mv download-cobalt.sh /root/
	cd DownloadCobalt-main
	rm -r 
	./download-cobalt.sh

	# Install CloudBrute
	printf '\n============================================================\n'
	printf  '=========Installing CloudBrute\n'
	printf '============================================================\n\n'
	wget wget https://github.com/0xsha/CloudBrute/releases/download/v1.0.7/cloudbrute_1.0.7_Linux_x86_64.tar.gz
	tar -xf cloudbrute_1.0.7_Linux_x86_64.tar.gz
	rm cloudbrute_1.0.7_Linux_x86_64.tar.gz
	mv cloudbrute /usr/bin/
	
	# Start Docker with system
	systemctl enable docker --now

	# Install ffuff
	go install github.com/ffuf/ffuf@latest

	# Install Arjun
	pip3 install arjun

	# Install Golang
	wget https://go.dev/dl/go1.18.1.linux-amd64.tar.gz
	rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz
	export PATH=$PATH:/usr/local/go/bin
	. "$HOME/.profile"

	# Install Cloud_Enum
	printf '\n============================================================\n'
	printf  '=========Installing CloudEnum\n'
	printf '============================================================\n\n'
	git clone https://github.com/ipc-security/cloud_enum.git
	cd cloud_enum
	pip3 install -r ./requirements.txt
	cd

	# Install Tor/Tor Browser
	printf '\n============================================================\n'
	printf  '=========Installing Tor/Tor Browser\n'
	printf '============================================================\n\n'
	apt install tor torbrowser-launcher -y
	tor --hash-password recon6
	sleep 30
	echo In the file /etc/tor/torrc, uncomment the variable ControlPort and the variable HashedControlPassword, and in this last one add the hash: ControlPort 9051 HashedControlPassword 16:7F314CAB402A81F860B3EE449B743AEC0DED9F27FA41831737E2F08F87
	service tor restart
	torbrowser-launcher

	# Install BeefAuto
	printf '\n============================================================\n'
	printf  '=========Installing BeefAuto\n'
	printf '============================================================\n\n'
	git clone https://github.com/ipc-security/BeefAuto.git
	cd BeefAuto
	pip3 install -r requirements.txt
	cd

	# Install Eyewitness
	printf '\n============================================================\n'
	printf  '=========Installing Eyewitness\n'
	printf '============================================================\n\n'
	git clone https://github.com/ipc-security/EyeWitness.git
	cd EyeWitness/Python/setup/
	./setup.sh
	cd

	# Install website-passive-reconnaissance
	printf '\n============================================================\n'
	printf  '=========Installing website-passive-reconnaissance\n'
	printf '============================================================\n\n'
	git clone https://github.com/ipc-security/website-passive-reconnaissance.git
	cd website-passive-reconnaissance
	pip install -r requirements.txt
	pip uninstall --yes dnsdumpster
	pip install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip
	pipreqs --force .
	tldextract --update
	cd

	# Install Duplicut
	printf '\n============================================================\n'
	printf  '=========Installing duplicut\n'
	printf '============================================================\n\n'
	git clone https://github.com/nil0x42/duplicut
	cd duplicut
	make
	cd
	ln -s ~/duplicat/duplicat /usr/local/bin/duplicat

	# Install Spring4shell
	printf '\n============================================================\n'
	printf  '=========Installing Spring4shell\n'
	printf '============================================================\n\n'
	git clone https://github.com/ipc-security/spring4shell-scan.git
	cd spring4shell-scan
	sudo docker build -t spring4shell-scan .
	cd

	# Install IMAP Sprayer
	printf '\n============================================================\n'
	printf  '=========IMAP Sprayer\n'
	printf '============================================================\n\n'
	https://github.com/yok4i/imapsprayer.git
	cd imapsprayer
	poetry install
	cd

	# Install SprayCannon
	printf '\n============================================================\n'
	printf  '=========SprayCannon\n'
	printf '============================================================\n\n'
	https://github.com/CausticKirbyZ/SprayCannon.git
	cd SprayCannon
	make init
	make
	make install
	cd

	# Install SprayCharles
	pip3 install pipx
	pipx ensurepath
	pipx install spraycharles
	
	# Install ssb
	printf '\n============================================================\n'
	printf  '=========Installing ssb\n'
	printf '============================================================\n\n'
	sudo curl -sSfL 'https://git.io/kitabisa-ssb' | sh -s -- -b /usr/local/bin
	
	# Unzip Rockyou.txt.gz
	printf '\n============================================================\n'
	printf  '=========Unzip copy rockyou\n'
	printf '============================================================\n\n'
	gzip -d /usr/share/wordlists/rockyou.txt.gz
	cp /usr/share/wordlists/rockyou.txt /root/

	# Installing BScripts
	mkdir BScripts
	cd BScripts
	wget --header 'Authorization: token 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' https://github.com/ipc-security/Kali-Setup/archive/refs/heads/main.zip
	unzip main.zip
	rm main.zip
	mv Kali-Setup-main Kali-Setup
	cd Kali-Setup
	chmod +x *.sh *.py
	cd ..
	wget --header 'Authorization: token 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' https://github.com/ipc-security/IPC-Recon-Script/archive/refs/heads/main.zip
	unzip main.zip
	rm main.zip
	mv IPC-Recon-Script-main IPC-Recon-Script
	cd IPC-Recon-Script
	chmod +x *.sh
	bash install.sh
	cd
	
	# Upgrade System
	printf '\n============================================================\n'
	printf  '=========Updating & Upgrading\n'
	printf '============================================================\n\n'
	apt-get update && apt-get full-upgrade
	
	# The End
	printf '\n============================================================\n'
	printf  '=========All Tools Installed\n'
	printf '============================================================\n\n'

	# Rebooting Sytem
	printf '\n============================================================\n'
	printf  '=========Rebooting System\n'
	printf '============================================================\n\n'
	reboot now
