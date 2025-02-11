# Table of contents

## Recon

* [Scanning](README.md)
* [Enumeration](recon/enumeration.md)
* [Stuck Checklist](recon/stuck-checklist.md)

## Services

* [(21) FTP](services/21-ftp.md)
* [(22) SSH](services/22-ssh.md)
* [(25) SMTP](services/25-smtp.md)
* [(53) DNS](services/53-dns.md)
* [(69) TFTP](services/69-tftp.md)
* [(110) POP3](services/110-pop3.md)
* [(111) SUN RPC](services/111-sun-rpc.md)
* [(119) NNTP](services/119-nntp.md)
* [(135) RPC](services/135-rpc.md)
* [(139,445) SMB](services/139-445-smb.md)
* [(161,162) SNMP](services/161-162-snmp.md)
* [(873) RSYNC](services/873-rsync.md)
* [(1541) Oracle TNS Listener](services/1541-oracle-tns-listener.md)
* [(1433) MSSQL](services/1433-mssql.md)
* [(2049) NFS](services/2049-nfs.md)
* [(3000) NodeJS](services/3000-nodejs.md)
* [(3306) MYSQL](services/3306-mysql.md)
* [(3389) RDP](services/3389-rdp.md)
* [(5800|5801|5900|5901) VNC](services/5800-or-5801-or-5900-or-5901-vnc.md)
* [(5985) WinRM](services/5985-winrm.md)
* [(6379) Redis](services/6379-redis.md)
* [(27017) Mongodb](services/27017-mongodb.md)
* [VoIP](services/voip.md)
* [GraphQL](services/graphql.md)

## Exploitation

* [LFI/RFI](exploitation/lfi-rfi.md)
* [XXE](exploitation/xxe.md)
* [SSRF](exploitation/ssrf.md)
* [SSTI](exploitation/ssti.md)
* [SQLi](exploitation/sqli.md)
* [Type Juggling](exploitation/type-juggling.md)
* [Command Injection](exploitation/command-injection.md)
* [Bypass IP Restrictions](exploitation/bypass-ip-restrictions.md)
* [WebDav](exploitation/webdav.md)

## Exploitation Tools

* [Msfvenom](exploitation-tools/msfvenom.md)
* [Reverse Shells](exploitation-tools/reverse-shells.md)
* [Default Creds](exploitation-tools/default-creds.md)
* [Bruteforce](exploitation-tools/bruteforce.md)
* [Macro Word Doc](exploitation-tools/macro-word-doc.md)
* [Library files + lnk Rev Shell](exploitation-tools/library-files-+-lnk-rev-shell.md)
* [OpenDocument Text Macro/ Obtain NTLMv2 Hash](exploitation-tools/opendocument-text-macro-obtain-ntlmv2-hash.md)

## Privilege Escalation

* [Privilege Escalation (Linux)](privilege-escalation/privilege-escalation-linux.md)
* [Privilege Escalation (Windows)](privilege-escalation/privilege-escalation-windows.md)

## Post-exploitation

* [Disable Firewall & Defender](post-exploitation/disable-firewall-and-defender.md)
* [Stabilize Shell](post-exploitation/stabilize-shell.md)
* [Transfer Files](post-exploitation/transfer-files.md)
* [Writable Locations](post-exploitation/writable-locations.md)
* [Finding Files](post-exploitation/finding-files.md)
* [Getting Out of Restrictive Shells](post-exploitation/getting-out-of-restrictive-shells.md)
* [Port Forwarding / Pivoting](post-exploitation/port-forwarding-pivoting.md)
* [Enable RDP](post-exploitation/enable-rdp.md)
* [Proof.txt](post-exploitation/proof.txt.md)

## Active Directory

* [Enumeration](active-directory/enumeration.md)
* [Authentication](active-directory/authentication.md)
* [Lateral Movement](active-directory/lateral-movement.md)
* [Persistence](active-directory/persistence.md)

## Misc

* [Useful Commands](misc/useful-commands.md)
* [Useful Code](misc/useful-code.md)
* [Cross-Compiling Exploit Code](misc/cross-compiling-exploit-code.md)
* [Tcpdump](misc/tcpdump.md)
* [Good Cheatsheets](misc/good-cheatsheets.md)
* [Spawning a Ubuntu 16.04 Container](misc/spawning-a-ubuntu-16.04-container.md)
* [VMware LAN](misc/vmware-lan.md)
* [Configuring NordVPN to VM](misc/configuring-nordvpn-to-vm.md)

## Buffer Overflow

* [BOF Cheatsheet](buffer-overflow/bof-cheatsheet.md)

## Bypassing AV

* [Powershell PE Reflective Injection](bypassing-av/powershell-pe-reflective-injection.md)
* [Veil](bypassing-av/veil.md)
* [Shellter](bypassing-av/shellter.md)

## Automated Tools

* [Metasploit](automated-tools/metasploit.md)
* [Empire](automated-tools/empire.md)

## HTB

* [OSCP-Like Boxes](htb/oscp-like-boxes/README.md)
  * [Blue](htb/oscp-like-boxes/blue.md)
  * [Legacy](htb/oscp-like-boxes/legacy.md)
  * [Jerry](htb/oscp-like-boxes/jerry.md)
  * [Squashed](htb/oscp-like-boxes/squashed.md)
  * [Lame](htb/oscp-like-boxes/lame.md)
  * [Shoppy](htb/oscp-like-boxes/shoppy.md)
  * [Access](htb/oscp-like-boxes/access.md)
  * [Jeeves](htb/oscp-like-boxes/jeeves.md)
  * [Optimum](htb/oscp-like-boxes/optimum.md)
  * [Arctic](htb/oscp-like-boxes/arctic.md)
  * [Bastard](htb/oscp-like-boxes/bastard.md)
  * [Bastion](htb/oscp-like-boxes/bastion.md)
  * [Querier](htb/oscp-like-boxes/querier.md)
  * [Netmon](htb/oscp-like-boxes/netmon.md)
  * [Grandma](htb/oscp-like-boxes/grandma.md)
  * [Grandpa](htb/oscp-like-boxes/grandpa.md)
  * [Silo](htb/oscp-like-boxes/silo.md)
  * [AD](htb/oscp-like-boxes/ad/README.md)
    * [Sauna](htb/oscp-like-boxes/ad/sauna.md)

## Interesting exercises

* [Finding flag in DNS server](interesting-exercises/finding-flag-in-dns-server.md)

## Configurations

* [Fix Kali Not Booting Properly](configurations/fix-kali-not-booting-properly.md)
* [Config File Locations](configurations/config-file-locations.md)
* [Setting up Pure-FTPD server](configurations/setting-up-pure-ftpd-server.md)
* [Vsftpd](configurations/vsftpd.md)
* [SMB Share](configurations/smb-share.md)
* [Burpsuite (HTTPS Config)](configurations/burpsuite-https-config.md)
* [Burpsuite (Upstream Proxy)](configurations/burpsuite-upstream-proxy.md)
* [Docker](configurations/docker.md)
* [Unable to view HTTPS sites](configurations/unable-to-view-https-sites.md)
* [PsExec](configurations/psexec.md)
* [Adding SSH key to Victim](configurations/adding-ssh-key-to-victim.md)
* [Create new SSH root user](configurations/create-new-ssh-root-user.md)
* [Symbolic Link (Linux)](configurations/symbolic-link-linux.md)
* [Fixing ModuleNotFoundError after Linux Update](configurations/fixing-modulenotfounderror-after-linux-update.md)
* [32 Bits vs 64 Bits Windows Binaries](configurations/32-bits-vs-64-bits-windows-binaries.md)
* [Managing users on Windows](configurations/managing-users-on-windows.md)
* [Troubleshooting Neo4j & BloodHound](configurations/troubleshooting-neo4j-and-bloodhound.md)
