import os
import subprocess
import sys

def build():
    # Comandos para construir o executável
    commands = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--windowed",
        "--clean",
        "--name=NetworkScanner",
        f"--add-data=psloggedon.exe{os.pathsep}.",
        "--icon=icon.ico" if os.path.exists("icon.ico") else "",
        "main.py"
    ]
    
    # Remove argumentos vazios
    commands = [c for c in commands if c]
    
    # Executa o comando
    subprocess.run(commands, check=True)

if __name__ == "__main__":
    build()
    print("\nBuild concluído com sucesso! Verifique a pasta 'dist'")