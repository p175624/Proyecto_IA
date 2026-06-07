"""
================================================================================
SISTEMA DE AUDITORÍA DE SEGURIDAD PARA SERVIDORES LINUX
================================================================================
Este script realiza una auditoría automática de seguridad en un servidor Linux
accesible vía SSH. Extrae información del sistema (usuarios, puertos abiertos),
la analiza con IA (Gemini) y genera un reporte profesional en PDF y Markdown.

Autor: Sistema de Auditoría Automatizada
Versión: 1.0
Requisitos: Python 3.8+, conexión SSH al servidor, API Key de Gemini
================================================================================
"""

# ============================================================================
# IMPORTACIÓN DE LIBRERÍAS
# ============================================================================
import os               # Operaciones con el sistema de archivos y variables de entorno
import json             # Manejo de datos en formato JSON
import paramiko         # Cliente SSH para conexión remota segura
import markdown         # Conversión de Markdown a HTML
from xhtml2pdf import pisa  # Conversión de HTML a PDF
from google import genai     # Cliente oficial de la API de Gemini (IA)
import hashlib          # Funciones hash para anonimización de datos sensibles
from datetime import datetime  # Generación de timestamps para nombres de archivo
from dotenv import load_dotenv # Carga de variables desde archivo .env


# ============================================================================
# CONFIGURACIÓN INICIAL - CARGA DE VARIABLES DE ENTORNO
# ============================================================================
# Carga las variables definidas en el archivo .env del proyecto
load_dotenv()

# Configuración de conexión SSH (obligatorias)
IP_VM = os.environ["SSH_HOST"]                    # Dirección IP del servidor objetivo
USUARIO_SSH = os.environ["SSH_USER"]              # Usuario para la conexión SSH
RUTA_LLAVE = os.environ["SSH_KEY_PATH"]           # Ruta a la clave privada SSH

# Configuración opcional: archivo known_hosts para verificar la identidad del servidor
RUTA_KNOWN_HOSTS = os.environ.get(
    "SSH_KNOWN_HOSTS_PATH",
    os.path.expanduser("~/.ssh/known_hosts")      # Por defecto usa el archivo del usuario
)


# ============================================================================
# FUNCIONES DE SEGURIDAD Y UTILIDADES
# ============================================================================

def anonimizar(texto):
    """
    Convierte un texto en su hash SHA-256 para anonimizar datos sensibles.
    
    Args:
        texto (str): Texto original (ej: nombre de usuario, IP)
    
    Returns:
        str: Hash SHA-256 hexadecimal del texto original
        
    Propósito: Cumplir con normativas de privacidad (GDPR, LOPD) al no almacenar
    datos identificables directamente en los reportes.
    """
    return hashlib.sha256(texto.encode()).hexdigest()


# ============================================================================
# FASE 1.5: EXTRACCIÓN DE PUERTOS ABIERTOS
# ============================================================================

def fase_1_5_extraer_puertos(ssh):
    """
    Escanea los puertos en estado LISTEN en el servidor remoto.
    
    Args:
        ssh (paramiko.SSHClient): Conexión SSH activa al servidor
    
    Returns:
        list: Lista de diccionarios con formato [{"puerto": int, "protocolo": str}]
        
    Nota técnica: 
        - Prioriza el comando 'ss -tuln' (moderno, más rápido)
        - Fallback a 'netstat -tuln' si 'ss' no está disponible
        - Filtra solo puertos en estado LISTEN
        - Elimina duplicados usando un conjunto (set) de tuplas (puerto, protocolo)
    """
    print("[*] Extrayendo puertos abiertos...")

    puertos_vistos = set()    # Para evitar duplicados
    puertos = []              # Lista resultado

    try:
        # Intento 1: Usar 'ss' (parte de iproute2, más moderno)
        comando = "ss -tuln"
        stdin, stdout, stderr = ssh.exec_command(comando)
        salida = stdout.read().decode("utf-8")

        # Si 'ss' no devuelve datos, intentar con 'netstat'
        if not salida.strip():
            comando = "netstat -tuln"
            stdin, stdout, stderr = ssh.exec_command(comando)
            salida = stdout.read().decode("utf-8")

        # Procesar línea por línea
        for linea in salida.splitlines():
            # Solo nos interesan líneas con "LISTEN" (estado escuchando)
            if "LISTEN" not in linea:
                continue

            # Dividir la línea en columnas (separador: espacios o tabs)
            partes = linea.split()
            if len(partes) <= 4:
                continue

            # La dirección y puerto suelen estar en la columna 4 (índice 4)
            direccion = partes[4]
            if ":" not in direccion:
                continue

            # Extraer el número de puerto (último elemento después del :)
            puerto_str = direccion.split(":")[-1]

            try:
                puerto = int(puerto_str)
            except ValueError:
                continue    # Si no es número válido, ignorar

            # Crear clave única para evitar duplicados
            clave = (puerto, partes[0])  # partes[0] contiene el protocolo (tcp/udp)
            if clave in puertos_vistos:
                continue

            puertos_vistos.add(clave)
            puertos.append({
                "puerto": puerto,
                "protocolo": partes[0]
            })

    except Exception as e:
        print(f"[-] Error extrayendo puertos: {e}")

    return puertos


# ============================================================================
# FASE 1: EXTRACCIÓN DE DATOS DEL SERVIDOR
# ============================================================================

def fase_1_extraer_datos():
    """
    Se conecta al servidor remoto vía SSH y extrae información de seguridad.
    
    Pasos realizados:
        1. Establece conexión SSH con clave Ed25519
        2. Lee el archivo /etc/passwd para obtener usuarios del sistema
        3. Identifica usuarios con capacidad de login interactivo
        4. Extrae puertos abiertos mediante fase_1_5_extraer_puertos()
        5. Anonimiza datos sensibles (IP, nombres de usuario)
        6. Estructura los hallazgos en formato JSON
    
    Returns:
        dict: Diccionario estructurado con:
            - metadata_auditoria: Información sobre la auditoría
            - servidor_auditado: Datos anonimizados del servidor
            - hallazgos_seguridad: Usuarios encontrados
            - superficie_expuesta: Puertos abiertos
        None: Si ocurre un error crítico durante la extracción
    
    Consideraciones de seguridad:
        - Usa RejectPolicy() para rechazar hosts desconocidos
        - Cierra la conexión SSH siempre (finally block)
        - Maneja errores para no exponer información interna
    """
    print("\n[*] FASE 1: Extrayendo datos del servidor...")

    # Crear cliente SSH
    ssh = paramiko.SSHClient()

    try:
        # Intentar cargar el archivo known_hosts para verificación del host
        try:
            ssh.load_host_keys(RUTA_KNOWN_HOSTS)
        except FileNotFoundError:
            print(f"[-] Advertencia: no se encontró {RUTA_KNOWN_HOSTS}. Agrega el host manualmente con ssh-keyscan.")
        
        # Política: rechazar cualquier host no conocido (máxima seguridad)
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

        usuarios_encontrados = []

        # Conexión SSH usando clave Ed25519 (formato moderno y seguro)
        llave = paramiko.Ed25519Key.from_private_key_file(RUTA_LLAVE)
        ssh.connect(hostname=IP_VM, username=USUARIO_SSH, pkey=llave, timeout=10)

        # === EXTRACCIÓN DE PUERTOS ===
        puertos_abiertos = fase_1_5_extraer_puertos(ssh)

        # === EXTRACCIÓN DE USUARIOS ===
        # Leer el archivo /etc/passwd que contiene todos los usuarios del sistema
        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd")
        salida = stdout.read().decode("utf-8")

        for linea in salida.splitlines():
            if not linea.strip():
                continue

            # Formato /etc/passwd: usuario:contraseña:UID:GID:descripción:home:shell
            datos = linea.split(":")
            if len(datos) < 7:
                continue

            nombre_real = datos[0]    # Nombre de usuario
            shell = datos[-1]          # Shell asignada (ej: /bin/bash, /usr/sbin/nologin)

            try:
                uid = int(datos[2])    # User ID
            except ValueError:
                continue

            # Determinar si el usuario puede iniciar sesión interactivamente
            # Un usuario tiene login si su shell NO es nologin ni false
            tiene_login = (
                not shell.endswith("nologin")
                and not shell.endswith("false")
            )

            # Criterio de inclusión:
            # - UID >= 1000 (usuarios humanos/creados por admin)
            # - O tiene capacidad de login (shell válida)
            if uid >= 1000 or tiene_login:
                usuarios_encontrados.append({
                    "usuario_hash": anonimizar(nombre_real),  # Anonimizado
                    "uid": uid,
                    "shell": shell,
                    "tiene_login": tiene_login
                })

        # Estructurar los datos en formato JSON para la IA
        return {
            "metadata_auditoria": {
                "origen": "Script Python",
                "estandar": "CIS Benchmarks"      # Referencia a estándar de hardening
            },
            "servidor_auditado": {
                "ip_hash": anonimizar(IP_VM),      # IP anonimizada
                "sistema_operativo": "Ubuntu Server"  # Nota: se podría detectar dinámicamente
            },
            "hallazgos_seguridad": {
                "modulo": "Control de Cuentas",
                "total_usuarios": len(usuarios_encontrados),
                "usuarios": usuarios_encontrados
            },
            "superficie_expuesta": {
                "total_puertos": len(puertos_abiertos),
                "puertos_abiertos": puertos_abiertos
            }
        }

    except Exception as e:
        print(f"[-] Error en extracción: {e}")
        return None

    finally:
        # Garantizar que la conexión SSH se cierre siempre
        ssh.close()
        print("[*] Conexión SSH cerrada.")


# ============================================================================
# FASE 2: ANÁLISIS CON INTELIGENCIA ARTIFICIAL (GEMINI)
# ============================================================================

def fase_2_analizar_con_ia(datos_json):
    """
    Envía los datos extraídos a Gemini API para análisis de seguridad.
    
    Args:
        datos_json (dict): Datos estructurados de la auditoría (Fase 1)
    
    Returns:
        str: Reporte en formato Markdown generado por la IA
    
    El prompt de IA está diseñado para que Gemini actúe como:
        - Consultor Senior en Ciberseguridad
        - Especialista en servidores Linux y CIS Benchmarks
    
    La IA analiza:
        - Usuarios con acceso interactivo
        - Configuraciones inseguras
        - Superficie de ataque (puertos expuestos)
        - Correlación de riesgos (ej: SSH + múltiples usuarios)
    
    El reporte generado incluye:
        1. Resumen Ejecutivo con score de seguridad
        2. Hallazgos prioritarios
        3. Tabla de riesgos
        4. Recomendaciones técnicas con comandos ejecutables
    """
    print("[*] FASE 2: Analizando con IA...")

    # Inicializar cliente de Gemini con API key
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

    # Construcción del prompt (instrucciones detalladas para la IA)
    prompt = f"""
Eres un Consultor Senior en Ciberseguridad especializado en sistemas Linux.

Analiza el siguiente JSON que contiene:
- Usuarios del sistema (anonimizados)
- Puertos abiertos detectados

Objetivos:
- Detectar cuentas con acceso interactivo
- Identificar configuraciones inseguras
- Analizar la exposición de servicios en red
- Correlacionar riesgos (ej: SSH abierto + múltiples usuarios)

Genera un reporte en Markdown profesional con:
1. Resumen Ejecutivo con score de seguridad
2. Hallazgos prioritarios
3. Tabla de riesgos
4. Recomendaciones técnicas con comandos

JSON:
{json.dumps(datos_json, indent=2)}
"""

    # Llamada a la API de Gemini
    # Modelo usado: gemini-2.5-flash (rápido y eficiente para tareas analíticas)
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )

    return response.text


# ============================================================================
# FASE 3: GENERACIÓN DE REPORTES (PDF y MARKDOWN)
# ============================================================================

def fase_3_generar_pdf(texto_markdown):
    """
    Convierte el reporte Markdown a PDF y también guarda el Markdown original.
    
    Args:
        texto_markdown (str): Reporte en formato Markdown (generado por la IA)
    
    Proceso:
        1. Genera timestamp para nombres de archivo únicos
        2. Convierte Markdown a HTML usando extensiones (tablas, código)
        3. Aplica estilos CSS profesionales para el PDF
        4. Genera PDF usando xhtml2pdf (pisa)
        5. Guarda también el archivo Markdown como respaldo
    
    Archivos generados:
        - Reporte_Auditoria_YYYYMMDD_HHMMSS.pdf
        - Reporte_Auditoria_YYYYMMDD_HHMMSS.md
    
    Los estilos CSS incluidos mejoran la legibilidad:
        - Fuente Helvetica/Arial para claridad
        - Tablas con cabeceras azules y filas alternadas
        - Bloques de código con fondo gris claro
        - Jerarquía visual clara para títulos
    """
    print("[*] FASE 3: Generando PDF...")

    # Generar timestamp único para identificar el reporte
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"Reporte_Auditoria_{timestamp}.pdf"

    # Convertir Markdown a HTML (habilitando tablas y código formateado)
    texto_html = markdown.markdown(texto_markdown, extensions=["tables", "fenced_code"])

    # Estilos CSS profesionales para el PDF
    estilos = """
    <style>
        body { font-family: Helvetica, Arial, sans-serif; color: #333; padding: 20px; }
        h1 { color: #1a365d; border-bottom: 2px solid #2b6cb0; padding-bottom: 8px; }
        h2 { color: #2b6cb0; margin-top: 20px; border-bottom: 1px solid #e2e8f0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background-color: #2b6cb0; color: white; padding: 8px; font-size: 12px; }
        td { padding: 8px; border: 1px solid #e2e8f0; font-size: 11px; }
        tr:nth-child(even) { background-color: #f7fafc; }
        pre { background-color: #edf2f7; padding: 10px; border-left: 3px solid #4a5568; font-family: monospace; font-size: 10px; }
    </style>
    """

    # Ensamblar HTML completo con los estilos
    html_final = f"<html><head>{estilos}</head><body>{texto_html}</body></html>"

    # Generar archivo PDF usando xhtml2pdf
    with open(nombre_archivo, "wb") as f:
        pisa.CreatePDF(html_final, dest=f)

    # Guardar también el Markdown original como respaldo/editable
    nombre_md = nombre_archivo.replace(".pdf", ".md")
    with open(nombre_md, "w", encoding="utf-8") as f:
        f.write(texto_markdown)

    # Notificar al usuario los archivos generados
    print(f"[+] Reporte PDF:      {nombre_archivo}")
    print(f"[+] Reporte Markdown: {nombre_md}")


# ============================================================================
# PUNTO DE ENTRADA PRINCIPAL (MAIN)
# ============================================================================

if __name__ == "__main__":
    """
    Ejecución principal del script de auditoría.
    
    Flujo de trabajo:
        1. Validar que todas las variables de entorno necesarias estén presentes
        2. Fase 1: Conectar al servidor y extraer datos
        3. Fase 2: Analizar datos con Gemini IA
        4. Fase 3: Generar reportes PDF y Markdown
    
    Variables de entorno requeridas:
        - GEMINI_API_KEY: Clave API de Google Gemini
        - SSH_HOST: IP o hostname del servidor objetivo
        - SSH_USER: Usuario para conexión SSH
        - SSH_KEY_PATH: Ruta a la clave privada SSH (formato Ed25519)
    
    Variables opcionales:
        - SSH_KNOWN_HOSTS_PATH: Ruta al archivo known_hosts (defecto: ~/.ssh/known_hosts)
    
    Salidas:
        - Archivo PDF con reporte formateado profesionalmente
        - Archivo Markdown con el reporte en texto plano
    
    El script está diseñado para ser ejecutado como:
        python main.py
        
    Asegúrate de tener un archivo .env en el mismo directorio con las variables.
    """
    
    # Lista de variables de entorno obligatorias
    vars_requeridas = ["GEMINI_API_KEY", "SSH_HOST", "SSH_USER", "SSH_KEY_PATH"]
    faltantes = [v for v in vars_requeridas if not os.environ.get(v)]

    # Validación pre-ejecución
    if faltantes:
        print(f"[-] Error: Faltan las siguientes variables de entorno: {', '.join(faltantes)}")
        print("    Revisa tu archivo .env o configúralas manualmente.")
    else:
        # Ejecutar las 3 fases de la auditoría
        datos = fase_1_extraer_datos()
        if datos:
            reporte = fase_2_analizar_con_ia(datos)
            fase_3_generar_pdf(reporte)