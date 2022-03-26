#!/bin/bash
cat << EOF >> /etc/bash.bashrc
#VARIAVEIS DO SERVIDOR:
export _NOME_SERVIDOR="FSX"
export _IPV4_SERVIDOR="192.168.1.107"


#VARIAVEIS DE REDE
export _INTERFACE_LAN="enp0s3"
export _INTERFACE_DMZ=""
export _NETWORK="192.168.1.0"
export _BROADCAST="192.168.1.255"
export _MASCARA="255.255.255.0"
export _GATEWAY="192.168.1.1"

#VARIAVEIS DA INFRAESTRUTURA
export _IPV4_DC_PRIMARIO=""
export _IPV4_DC_BACKUP=""
export _NOME_DOMINIO="cwb.systech.com.br"
export _NOME_FQDN=$_NOME_SERVIDOR.$NOME_DOMINIO
export _SENHA_ADMINISTRATOR="Casado#55"
export _USUARIO_DEFAULT="jensyg"

#VARIAVLES DOS SCRIPTS
export HORAINICIAL=$(date +%T)
export USUARIO=$(id -u)
export UBUNTU=$(lsb_release -rs)
export LOGSCRIPT="/var/log/$(echo $0 | cut -d'/' -f2)"
export DEBIAN_FRONTEND="noninteractive"
export _NETPLAN="/etc/netplan/00-installer-config.yaml"
export SSHDEP="openssh-server openssh-client"
export SSHINSTALL="net-tools traceroute ipcalc nmap tree pwgen neofetch shellinabox"
export PORTSSH="22"
export PORTSHELLINABOX="4200"



EOF
reboot