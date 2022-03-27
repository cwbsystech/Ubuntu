#!/bin/bash


echo "Configurando o Arquivo HOSTNAME"
sleep 2
cat <<EOF > /etc/hostname
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
$_NOME_SERVIDOR

EOF


echo "Configurando o Arquivo HOSTS"
sleep 2
cat << EOF > /etc/hosts
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
#
# Configuração do Banco de Dados de DNS Estático IPv4 do Servidor Local
# IPv4		FQDN                    CNAME	
127.0.0.1 	localhost.localdomain	localhost
127.0.1.1 	$_NOME_SERVIDOR.$_NOME_DOMINIO	$_NOME_SERVIDOR
$_IPV4_SERVIDOR	$_NOME_SERVIDOR.$_NOME_DOMINIO	$_NOME_SERVIDOR
#
# Configuração do Banco de Dados de DNS Estático IPv6 do Servidor Local
# OBSERVAÇÃO: por padrão nesse curso não será utilizando o suporte ao IPv6
# IPV6	    FQDN                    CNAME
::1 	    ip6-localhost           ip6-loopback
fe00::0     ip6-localnet
ff00::0     ip6-mcastprefix
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF


echo "Configurando o Arquivo HOSTS.ALLOW"
sleep 2
cat << EOF > /etc/hosts.allow
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
#
# Comando utilizado para verificar se o serviço (daemon) de rede tem suporte ao 
# TCPWrappers: ldd /usr/sbin/sshd | grep libwrap (Biblioteca LibWrap)
# Logando todas as informações de acesso nos arquivos de Log's de cada serviço
# em: /var/log/tcpwrappers-allow-*.log (* nome do serviço)
#
# Permitindo a Rede $_NETWORK/$_MASCARA se autenticar remotamente no Servidor de OpenSSH
# DAEMON   CLIENT     OPTION
sshd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-ssh.log
#
# Permitindo a Rede $_NETWORK/$_MASCARA se autenticar remotamente no Servidor de MySQL
# DAEMON   CLIENT     OPTION
mysqld: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-mysql.log
#
# Permitindo a Rede $_NETWORK/$_MASCARA se autenticar remotamente no Servidor de Telnet
# DAEMON   CLIENT     OPTION
in.telnetd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-telnet.log
#
# Permitindo a Rede $_NETWORK/$_MASCARA se autenticar remotamente no Servidor de FTP
# DAEMON   CLIENT     OPTION
vsftpd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-vsftpd.log
#
# Permitindo a Rede $_NETWORK/$_MASCARA se conectar remotamente no Servidor de TFTP
# DAEMON   CLIENT     OPTION
in.tftpd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-tftpd.log
#
# Permitindo a Rede $_NETWORK/$_MASCARA se autenticar remotamente no Servidor de NFS
# DAEMON   CLIENT     OPTION
portmap: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-nfs.log
lockd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-nfs.log
rquotad: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-nfs.log
mountd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-nfs.log
statd: $_NETWORK/$_MASCARA: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-nfs.log
#
# Permitindo que todas as redes acesse os serviços remotos do Servidor Bacula
# DAEMON   CLIENT     OPTION
bacula-fd: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-bacula.log
bacula-sd: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-bacula.log
bacula-dir: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-bacula.log
$_NOME_FQDN-fd: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-bacula.log
$_NOME_FQDN-mon: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-bacula.log
$_NOME_FQDN-dir: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-allow-bacula.log
#
EOF


echo "Configurando o Arquivo HOSTS.DENY"
sleep 2
cat << EOF > /etc/hosts.deny
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
#
# Comando utilizado para verificar se o serviço (daemon) de rede tem suporte 
# ao TCPWrappers: ldd /usr/sbin/sshd | grep libwrap (Biblioteca LibWrap)
# Negando todas as redes acessarem os serviços remotamente do Ubuntu Server, 
# somente os serviços e redes configuradas no arquivo host.allow estão liberados 
# para acessar o servidor.
# Logando todas as informações de acesso negado de todos os serviços no arquivos 
# de Log em: /var/log/tcpwrappers-deny-.log
#
# Negando todas as Redes de acessar remotamente os serviços no Servidor Ubuntu
# DAEMON   CLIENT     OPTION
ALL: ALL: spawn /bin/echo "$(date -u) | Serviço Remoto %d | Host Remoto %c | Porta Remota %r | Processo Local %p" >> /var/log/tcpwrappers-deny.log
#
EOF


echo "Configurando o Arquivo NSSWITCH.CONF"
sleep 2
cat << EOF > /etc/nsswitch.conf
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
#
# Configuração do acesso a informações de usuários, grupos e senhas.
# Padrão consultar primeiro os arquivos (files) depois o sistema (systemd)
# DATABASE       SERVICE
passwd:          files systemd
group:           files systemd
shadow:          files
gshadow:         files
#
# Configuração da forma de resolução de nomes de computadores.
# Padrão consultar primeiro os arquivos (files) depois o serviço de DNS
# DATABASE       SERVICE
hosts:           files dns
networks:        files
#
# Configuração da consultada dos serviços de rede
# Padrão consultar primeiro o banco de dados local (db) depois os arquivos (files)
# DATABASE       SERVICE
protocols:       db files
services:        db files
ethers:          db files
rpc:             db files
#
# Configuração da consulta de resolução do serviço de Grupos de Rede
# Padrão consultar primeiro os serviço de rede NIS (Network Information Service)
# DATABASE       SERVICE
netgroup:        nis
EOF



echo "Configurando o Arquivo SSHD_CONFIG"
sleep 2
cat << EOF > /etc/ssh/sshd_config
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
# Testado e homologado para a versão do OpenSSH Server v8.2.x
#
# Incluindo o diretório de configuração personalizada do OpenSSH Server
Include /etc/ssh/sshd_config.d/*.conf
#
# Porta de conexão padrão do Servidor de OpenSSH, por segurança é recomendado mudar 
# o número da porta. Caso você mude o número da porta, no cliente você precisa usar 
# o comando: ssh -p $_PORTSSH $_USUARIO_DEFAUL@$_IPV4_SERVIDOR
Port $_PORTSSH
#
# Versão do protocolo padrão do Servidor de OpenSSH
Protocol 2

ListenAddress $_IPV4_SERVIDOR

AuthenticationMethods password

PubkeyAuthentication yes

PasswordAuthentication yes

AuthorizedKeysFile .ssh/authorized_keys

StrictModes yes

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

Ciphers aes128-ctr,aes192-ctr,aes256-ctr

SyslogFacility AUTH
LogLevel INFO

PermitRootLogin no

AllowUsers $_USUARIO_DEFAULT

AllowGroups $_USUARIO_DEFAULT

DenyUsers root

DenyGroups root

Banner /etc/issue.net

LoginGraceTime 60

ClientAliveInterval 1800
ClientAliveCountMax 3

MaxAuthTries 3

MaxSessions 3

MaxStartups 5:60:10

AddressFamily inet

IgnoreRhosts yes
HostbasedAuthentication no

PermitEmptyPasswords no

PermitUserEnvironment no

AllowTcpForwarding no

X11Forwarding no

X11DisplayOffset 10

ChallengeResponseAuthentication no

UsePAM yes

PrintMotd no

PrintLastLog yes

AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

TCPKeepAlive yes

KerberosAuthentication no
GSSAPIAuthentication no

Compression delayed

UseDNS no
EOF


echo "Configurando o Arquivo SHELLINABOX"
sleep 2
cat <<EOF > /etc/default/shellinabox
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
# Testado e homologado para a versão do OpenSSH Server v8.2.x
# Testado e homologado para a versão do Shell-In-a-Box v2.x
#
# Configuração do inicialização automática do Shell-In-a-Box como serviço
SHELLINABOX_DAEMON_START=1
#
# Porta padrão utilizada pelo Webservice do Shell-In-a-Box
SHELLINABOX_PORT=$_PORTSHELLINABOX
#
# Configuração do Usuário e Grupo padrão do serviço do Shell-In-a-Box
SHELLINABOX_USER=shellinabox
SHELLINABOX_GROUP=shellinabox
#
# Localização padrão do diretório de informações de acesso do Shell-In-a-Box
SHELLINABOX_DATADIR=/var/lib/shellinabox
#
# Configurações dos argumentos utilizados pelo Shell-In-a-Box
# --no-beep: bipes são desativados devido a relatos de falha do plug-in VLC no Firefox
# --service=/:SSH: configuração do endereço IPv4 do servidor de OpenSSH Server
# Mais opções de argumentos veja a documentação oficial do Shell-In-a-Box no Link:
# https://manpages.debian.org/unstable/shellinabox/shellinaboxd.1.en.html
SHELLINABOX_ARGS="--no-beep --service=/:SSH:$_IPV4_SERVIDOR"
EOF

	

echo "Configurando o Arquivo NETPLAN"
sleep 2
cat <<EOF > /etc/netplan/00-installer-config.yaml
# Gerado:       cwb.systech.com.br -- Soluçoes em TI
# Autor:        Jensy Gregorio Gomez
# Bio:          Têcnico em Informatica e Eletronica
# WhatsApp:     (41) 99896-2670    /    99799-3164
# Date:         01/01/2022
# Versão:       0.01
#
# Mais informações veja o arquivo: scripts/settings/04-ConfiguracaoDoNetplan.sh
# Após as configuração do endereço IPv4 digitar o comando: netplan --debug apply
#
# Configuração do Endereço IPv4 do Ubuntu Server
network:
  #
  # Configuração do Protocolo Ethernet do Ubuntu Server
  ethernets:
    #
    # Configuração do Nome da Placa de Rede do Ubuntu Server
    $_INTERFACE_LAN:
      #
      # Configuração do Endereço IPv4 Dinâmico via DHCP do Ubuntu Server
      # OBSERVAÇÃO: por padrão o endereço IPv4 dinâmico em servidores não é utilizado
      #dhcp4: true
      #
      # Configuração do Endereço IPv4 e CIDR Estático do Ubuntu Server
      addresses:
      - $_IPV4_SERVIDOR/$_MASCARA
      #
      # Configuração do Endereço de Gateway IPv4 do Ubuntu Server
      gateway4: $_GATEWAY
      #
      # Configuração dos Endereços de DNS Server IPv4 do Ubuntu Server
      nameservers:
        addresses:
        - $_IPV4_SERVIDOR
        - $_GATEWAY
        - 8.8.8.8
        #- 8.8.8.8
        #
        # Configuração do Nome de Pesquisa DNS do Ubuntu Server
        search:
        - $_NOME_DOMINIO
        #
  # Configuração da versão do Protocolo Ethernet do Ubuntu Server
  version: 2
EOF