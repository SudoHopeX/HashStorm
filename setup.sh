#!/bin/bash

set -e

TARGET_HOME=$(eval echo ~$(logname))
INSTALLED_DIR=$(find "$TARGET_HOME" -type d -name "HashStorm" -print -quit)
INSTALL_DIR="/opt"
BIN_PATH="/usr/local/bin/hashstorm"

echo " "
echo "               ######      ######        ###############################################"
echo "              ######      ######         ###  BY KRISHNA DWIVEDI [ @sudo-hope0529 ]  ###"
echo "             ######      ######          ###############################################"
echo "        ###########################"
echo "       ###########################   #######   ############   #######   ########    ##    ###"
echo "          ######      ######       #########  ############  #########  ###    ###  ###   ####"
echo "         ######      ######       ###             ###      ##    ###  ###   ###   ####  ## ##"
echo "        ######      ######       ###             ###      ##    ###  ### ###     ### ####  ##"
echo "   ###########################   ########       ###      ##    ###  ######      ###  ##    ##"
echo "  ###########################          ###     ###      ##    ###  ######      ###         ##"
echo "     ######      ######               ###     ###      ##    ###  ###  ###    ###          ##"
echo "    ######      ######        ##########     ###      #########  ###    ###  ###           ##"
echo "   ######      ######         ########      ###       #######   ###      ## ###    v1.2    ##"
echo " "

echo "[>_] Updating system.."
sudo apt-get update

# checking for python installation & installing if not found
echo "[>_] Checking python Installation..."

if ! dpkg -s python3 >/dev/null 2>&1; then
   	echo "[!] Python3 Installation not found. Installating it..."
   	sudo apt-get install python3 -y
   	echo "[✔] Python3 Installation successfully Done.."
else
	echo "[✔] Python3 Installation Found."
fi


# checking for py venv installation & installing if not found
echo "[>_] Checking python3 venv Installation..."
if ! dpkg -s python3-venv >/dev/null 2>&1; then
	echo "[!] Python3 venv Installation not found. Installing it..."
	sudo apt install python3-venv
	echo "[✔] Python3 venv Installation Successfully Done..."
else
	echo "[✔] Python3 venv Installation found."
fi

# creating a venv named hashstorm_venv
python3 -m venv "$TARGET_HOME"/hashstorm_venv

# starting venv
source "$TARGET_HOME"/hashstorm_venv/bin/activate

# Installing HashStorm required libraries or packages
echo "[>_] Installing required HashStorm dependencies & pkgs...."
pip3 install hashid bcrypt scrypt blake3

# deactivating venv after installation
deactivate

# Checking for existence of Installed dir for HashStorm
if ! [[ -d "$INSTALLED_DIR" ]] ; then
	echo "[!] HashStorm Installation Not found. Installing it..."
	git clone https://github.com/sudo-hope0529/HashStorm.git "$INSTALL_DIR/"
else
	# Copying Installed hashStorm dir to Opt dir
	sudo cp -r "$INSTALLED_DIR" "$INSTALL_DIR/"
fi

# creating hashstorm launcher
echo "[*] Creating launcher at $BIN_PATH..."
sudo tee "$BIN_PATH" > /dev/null << EOF
#!/bin/bash
source $TARGET_HOME/hashstorm_venv/bin/activate
python3 $INSTALL_DIR/HashStorm/hashstorm.py "\$@"
deactivate
EOF

# Make hashstorm launcher executable
sudo chmod +x "$BIN_PATH"

echo "[✔] HashStorm Setup Successfully Done..."
echo "[>_] Now you can use HashStorm using the command: hashstorm [options]"
