#!/bin/bash

set -e

TARGET_HOME=$(eval echo ~$(logname))
INSTALLED_DIR=$(find "$TARGET_HOME" -type d -name "HashStorm" -print -quit)
INSTALL_DIR="/opt"
BIN_PATH="/usr/local/bin/hashstorm"

# Bold/Bright colors
RED="\e[1;31m"
GREEN="\e[1;32m"
BLUE="\e[1;34m"
MAGENTA="\e[1;35m"
YELLOW="\e[1;33m"

# Reset
RESET="\e[0m"

echo -e "${YELLOW}
               ######      ######        ###############################################
              ######      ######         ###    ${RED}BY KRISHNA DWIVEDI [ @SudoHopeX ]    ${YELLOW}###
             ######      ######          ###############################################
        ###########################
       ###########################   #######   ############   #######   ########    ##    ###
          ######      ######       #########  ############  #########  ###    ###  ###   ####
         ######      ######       ###             ###      ##    ###  ###   ###   ####  ## ##
        ######      ######       ###             ###      ##    ###  ### ###     ### ####  ##
   ###########################   ########       ###      ##    ###  ######      ###  ##    ##
  ###########################          ###     ###      ##    ###  ######      ###         ##
     ######      ######               ###     ###      ##    ###  ###  ###    ###          ##
    ######      ######        ##########     ###      #########  ###    ###  ###           ##
   ######      ######         ########      ###       #######   ###      ## ###    ${BLUE}v2.2    ${YELLOW}##
${RESET}"

# function to install mission dependencies
function install_missing() {
    local pkg="$1"

	echo -e "${BLUE}[>_] Checking ${pkg} Installation...${RESET}"

	if ! dpkg -s $pkg >/dev/null 2>&1; then
	   	echo -e "${YELLOW}[!] ${pkg} Installation not found. Installating it...${RESET}"
	   	sudo apt-get install $pkg -y
	   	echo -e "${GREEN}[✔] ${pkg} Installation successfully Done..${RESET}"
	else
		echo -e "${BLUE}[✔] ${pkg} Installation Found.${RESET}"
	fi
}


echo -e "${MAGENTA}[>_] Updating system...${RESET}"
# sudo apt-get update >/dev/null 2>&1
echo -e "${GREEN}[✔] System Updated...${RESET}"

# checking for dependencies installation & installing if not found
install_missing python3
install_missing python3-venv

# creating a venv named hashstorm_venv
python3 -m venv "$TARGET_HOME"/hashstorm_venv

# starting venv
source "$TARGET_HOME"/hashstorm_venv/bin/activate

# Installing HashStorm required libraries or packages
echo -e "${MAGENTA}[>_] Installing required HashStorm dependencies & pkgs....${RESET}"
pip3 install hashid bcrypt scrypt blake3

# deactivating venv after installation
deactivate

# Checking for existence of Installed dir for HashStorm
if ! [[ -d "$INSTALLED_DIR" ]] ; then
	echo -e "${YELLOW}[!] HashStorm Installation Not found. Installing it..."
	git clone https://github.com/SudoHopeX/HashStorm.git "$INSTALL_DIR/"
else
	# Copying Installed hashStorm dir to Opt dir
	sudo cp -r "$INSTALLED_DIR" "$INSTALL_DIR/"
fi

# creating hashstorm launcher
echo -e "${MAGENTA}[*] Creating launcher at $BIN_PATH...${RESET}"
sudo tee "$BIN_PATH" > /dev/null << EOF
#!/bin/bash

RED="\e[1;31m"
GREEN="\e[1;32m"
BLUE="\e[1;34m"
MAGENTA="\e[1;35m"
YELLOW="\e[1;33m"
RESET="\e[0m"
MODE="\$1"

case "\$MODE" in

  identify|crack|icrack)

      source $TARGET_HOME/hashstorm_venv/bin/activate
      python3 $INSTALL_DIR/HashStorm/hashstorm.py "\$@"
      deactivate
        ;;

	--help|-h|*)

		echo -e "${YELLOW}
               ######      ######        ###############################################
              ######      ######         ###    ${RED}BY KRISHNA DWIVEDI [ @SudoHopeX ]    ${YELLOW}###
             ######      ######          ###############################################
        ###########################
       ###########################   #######   ############   #######   ########    ##    ###
          ######      ######       #########  ############  #########  ###    ###  ###   ####
         ######      ######       ###             ###      ##    ###  ###   ###   ####  ## ##
        ######      ######       ###             ###      ##    ###  ### ###     ### ####  ##
   ###########################   ########       ###      ##    ###  ######      ###  ##    ##
  ###########################          ###     ###      ##    ###  ######      ###         ##
     ######      ######               ###     ###      ##    ###  ###  ###    ###          ##
    ######      ######        ##########     ###      #########  ###    ###  ###           ##
   ######      ######         ########      ###       #######   ###      ## ###    ${BLUE}v2.2    ${YELLOW}##

${RESET}"

      echo -e "${MAGENTA}HashStorm:  A Python Tool to identify and crack multiple hashes quickly.${RESET}
	  "

      echo -e "${GREEN}USAGES:
            ${BLUE}hashstorm [Options] [Arguments]${RESET}
		"

      echo -e "${GREEN}OPTIONS:${RESET}
   > --help                    print tool usages
   > identify                  identify the hash-type of specified hash-value
   > crack                     crack the hash-value (!NOTE: hash-type must be passed)
   > icrack [Default]          automatically identify hash-type and crack the hash-value specified
	"

      echo -e "${GREEN}ARGUMENTS:${RESET}
   > -h <hash-value(s)>        add one or more hash-value to crack or identify followed by ','
   > -hf <hashes file>         pass a hash file
   > -H <hash-type(s)>         pass hash-type to crack
   > -w <wordlist-path>        specify wordlist to use 4 cracking hash
   > -o <output-file>          save result in specified file
   > -v                        verbose mode ( show detailed info while cracking ) [in update]
   > -g                        perform a google search if hash not cracked [in update]
   > -brute                    Crack hashes using self defined charset and length [in update]
   > -charset <charset>        Specify character set for bruteforccing like "a-z0-9" [in update]
   > -length <pass-max-length> Specify hash word's maximum value [in update]
	"

      echo -e "${GREEN}EXAMPLES:${RESET}
   > hashstorm identify -h 5d41402abc4b2a76b9719d911017c592
   > hashstorm identify -hf hash-file.txt
   > hashstorm identify -h ae3274d5bfa170ca69bb534be5a22467,5d41402abc4b2a76b9719d911017c592
   > hashstorm crack -H MD5 -h 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o output.txt
   > hashstorm crack -H MD5,MD5 -h 5d41402abc4b2a76b9719d911017c592,5d41402abc4b2a76b9719d911017c592 -w wordlist.txt
   > hashstorm -h 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o output.txt
	"

      echo -e "${GREEN}NOTE:${RESET}
   > Tool usages format must be followed
   > Atleast 'hash-value' OR 'hashes-file' must be passed as argument
	"
   		;;
esac
EOF

# Make hashstorm launcher executable
sudo chmod +x "$BIN_PATH"

echo -e "${GREEN}[✔] HashStorm Setup Successfully Done...${RESET}"
echo -e "${BLUE}[>_] Now you can use HashStorm using the command: ${MAGENTA}hashstorm [options]${RESET}"
