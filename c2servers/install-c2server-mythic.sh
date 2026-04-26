#!/bin/sh
#
# Part of RedELK
# Script to install RedELK connector for Mythic C2 servers
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="redelk-install.log"
INSTALLER="RedELK Mythic C2 installer"
ELKVERSION="7.17.9"

echoerror() {
    printf "$(date +'%b %e %R') $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >>$LOGFILE 2>&1
}

preinstallcheck() {
    echo "Starting pre installation checks"

    if [ ! -f /etc/debian_version ]; then
        echo "[X] This system does not seem to be Debian/APT-based. RedELK installer only supports Debian/APT based systems."
        echoerror "System is not Debian/APT based. Not supported. Quitting."
        exit 1
    fi

    if [ -n "$(dpkg -s filebeat 2>/dev/null | grep Status)" ]; then
        INSTALLEDVERSION=$(dpkg -s filebeat | grep Version | awk '{print $2}') >>$LOGFILE 2>&1
        if [ "$INSTALLEDVERSION" != "$ELKVERSION" ]; then
            echo "[X] Filebeat: installed version $INSTALLEDVERSION, required version $ELKVERSION. Please fix manually."
            echoerror "Filebeat version mismatch. Please fix manually."
            exit 1
        else
            echo "[!] Filebeat: required version is installed ($INSTALLEDVERSION). Should be good. Stopping service now before continuing installation."
            service filebeat stop
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echoerror "[X] Could not stop filebeat (Error Code: $ERROR)."
            fi
        fi
    fi
}

printf "$(date +'%b %e %R') $INSTALLER - Starting installer\n" >$LOGFILE 2>&1
echo ""
echo ""
echo ""
echo "    ____            _  _____  _      _  __"
echo "   |  _ \  ___   __| || ____|| |    | |/ /"
echo "   | |_) |/ _ \ / _  ||  _|  | |    | ' / "
echo "   |  _ <|  __/| (_| || |___ | |___ | . \ "
echo "   |_| \__\___| \____||_____||_____||_|\_\\"
echo ""
echo ""
echo ""
echo "This script will install and configure necessary components for RedELK on Mythic C2 servers"
echo ""
echo ""

if ! [ $# -eq 3 ]; then
    echo "[X] ERROR Incorrect amount of parameters"
    echo "[X] require 1st parameter: identifier of this machine to set in filebeat config."
    echo "[X] require 2nd parameter: attackscenario name."
    echo "[X] require 3rd parameter: IP/DNS:port where to ship logs to (enter 5044 if you are using default logstash port)."
    echoerror "Incorrect amount of parameters"
    exit 1
fi

preinstallcheck

echo "[*] Setting locale" | tee -a $LOGFILE
export LC_ALL="en_US.UTF-8"
printf 'LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8\n' >/etc/default/locale >>$LOGFILE 2>&1
locale-gen >>$LOGFILE 2>&1

echo "[*] Adding GPG key of Elastic" | tee -a $LOGFILE
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not add GPG key (Error Code: $ERROR)."
fi

echo "[*] Installing apt-transport-https" | tee -a $LOGFILE
apt-get install -y apt-transport-https >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not install apt-transport-https (Error Code: $ERROR)."
fi

echo "[*] Adding Elastic APT repository" | tee -a $LOGFILE
if [ ! -f /etc/apt/sources.list.d/elastic-7.x.list ]; then
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list >>$LOGFILE 2>&1
fi
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not add APT repository (Error Code: $ERROR)."
fi

echo "[*] Updating APT" | tee -a $LOGFILE
apt-get update >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not update APT (Error Code: $ERROR)."
fi

echo "[*] Installing filebeat" | tee -a $LOGFILE
apt-get install -y filebeat=$ELKVERSION >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not install filebeat (Error Code: $ERROR)."
fi

echo "[*] Setting filebeat to auto start after reboot" | tee -a $LOGFILE
systemctl enable filebeat >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not change auto boot settings (Error Code: $ERROR)."
fi

echo "[*] Making backup of original filebeat config" | tee -a $LOGFILE
mv /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.ori >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not make backup (Error Code: $ERROR)."
fi

echo "[*] Copying new main config file" | tee -a $LOGFILE
cp ./filebeat/filebeat_redelk_main.yml /etc/filebeat/filebeat.yml >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not copy filebeat config (Error Code: $ERROR)."
fi

echo "[*] Copying Mythic input file" | tee -a $LOGFILE
mkdir -p /etc/filebeat/inputs.d >>$LOGFILE 2>&1
cp ./filebeat/inputs.d/filebeat_mythic.yml /etc/filebeat/inputs.d/ >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not copy Mythic input config (Error Code: $ERROR)."
fi

echo "[*] Copying ca file" | tee -a $LOGFILE
cp ./filebeat/redelkCA.crt /etc/filebeat/ >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not copy ca file (Error Code: $ERROR)."
fi

echo "[*] Altering hostname field in filebeat config" | tee -a $LOGFILE
sed -i s/'@@HOSTNAME@@'/$1/g /etc/filebeat/filebeat.yml >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not change hostname field in filebeat config (Error Code: $ERROR)."
fi

echo "[*] Altering attackscenario field in Mythic filebeat config" | tee -a $LOGFILE
sed -i s/'@@ATTACKSCENARIO@@'/$2/g /etc/filebeat/inputs.d/filebeat_mythic.yml >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not change attackscenario field in Mythic input config (Error Code: $ERROR)."
fi

echo "[*] Altering log destination field in filebeat config" | tee -a $LOGFILE
sed -i s/'@@HOSTANDPORT@@'/$3/g /etc/filebeat/filebeat.yml >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not change log destination field in filebeat config (Error Code: $ERROR)."
fi

echo "[*] Creating RedELK log directory" | tee -a $LOGFILE
mkdir -p /var/log/redelk >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not create RedELK log directory (Error Code: $ERROR)."
fi

echo "[*] Restarting filebeat" | tee -a $LOGFILE
service filebeat restart >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not restart filebeat (Error Code: $ERROR)."
fi

grep -i error $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit
fi

echo ""
echo ""
echo "Done with automated setup of RedELK on Mythic C2 server."
echo ""
echo ""
echo "The default Mythic SIEM log path in this installer is /root/Mythic/mythic-docker/redelk.log."
echo "If Mythic writes RedELK-compatible JSON to a different path, update /etc/filebeat/inputs.d/filebeat_mythic.yml."
echo ""
echo ""
