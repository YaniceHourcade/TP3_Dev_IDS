import os
import hashlib
import json
import time
import subprocess
import platform
import logging

# Configuration du système de log
LOG_FILE = "ids.log"

logging.basicConfig(
    filename=LOG_FILE,                  # Fichier où les logs seront écrits
    level=logging.DEBUG,                # Niveau de log (INFO, WARNING, ERROR)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format des messages de log
    datefmt="%Y-%m-%d %H:%M:%S"         # Format de la date
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

# Liste des fichiers à surveiller
FILES_TO_MONITOR = [r"C:\Windows\System32\drivers\etc\hosts", r"C:\Windows\System32\config\SAM"]

# Chemin de sortie
OUTPUT_FILE = r"C:\Users\yanic\Desktop\Yanice_Ynov_B2\TP3_Dev_IDS\db.json"

# Fonction pour calculer les hashes d'un fichier
def compute_hashes(file_path):
    try:
        hashes = {"MD5": None, "SHA256": None, "SHA512": None}
        with open(file_path, "rb") as f:
            data = f.read()
            hashes["MD5"] = hashlib.md5(data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(data).hexdigest()
            hashes["SHA512"] = hashlib.sha512(data).hexdigest()
        return hashes
    except (FileNotFoundError, PermissionError) as e:
        logging.error(f"Error computing hashes for {file_path}: {e}")
        return {"error": str(e)}

# Fonction pour obtenir les propriétés d'un fichier
def get_file_properties(file_path):
    try:
        stats = os.stat(file_path)
        properties = {
            "path": file_path,
            "size": stats.st_size,
            "last_modified": time.ctime(stats.st_mtime),
            "created": time.ctime(stats.st_ctime),
            "owner": get_owner(file_path),
            "group": get_group(file_path),
        }
        properties.update(compute_hashes(file_path))
        logging.info(f"Properties retrieved for {file_path}")
        return properties
    except (FileNotFoundError, PermissionError) as e:
        logging.error(f"Error retrieving properties for {file_path}: {e}")
        return {"error": str(e)}

# Fonction pour obtenir le propriétaire d'un fichier (compatible Windows)
def get_owner(file_path):
    if platform.system() == "Windows":
        return os.getlogin()
    else:
        import pwd
        return pwd.getpwuid(os.stat(file_path).st_uid).pw_name

# Fonction pour obtenir le groupe d'un fichier (compatible Windows)
def get_group(file_path):
    if platform.system() == "Windows":
        return "N/A"  # Les groupes ne sont pas directement accessibles sous Windows sans modules supplémentaires
    else:
        import grp
        return grp.getgrgid(os.stat(file_path).st_gid).gr_name

# Fonction pour obtenir les ports TCP/UDP en écoute
def get_open_ports():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("netstat -an", text=True, shell=True)
        else:
            result = subprocess.check_output(["ss", "-tuln"], text=True)
            logging.info("Open ports retrieved successfully")
        return result.strip().split("\n")
    except Exception as e:
        logging.error(f"Error retrieving open ports: {e}")
        return {"error": str(e)}

# Fonction principale
def generate_report():
    logging.info("Starting report generation")
    report = {
        "build_time": time.ctime(),
        "files": [],
        "open_ports": get_open_ports(),
    }

    for file_path in FILES_TO_MONITOR:
        report["files"].append(get_file_properties(file_path))

     # Sauvegarder dans le fichier JSON
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, "w") as json_file:
            json.dump(report, json_file, indent=4)
        logging.info(f"Report saved to {OUTPUT_FILE}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")

# Exécution
if __name__ == "__main__":
    generate_report()
