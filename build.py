import subprocess
import sys
import os

def build():
    try:
        # Verifica se o psloggedon.exe está no diretório
        if not os.path.exists('psloggedon.exe'):
            print("Erro: psloggedon.exe não encontrado no diretório atual!")
            return

        # Comando PyInstaller
        commands = [
            sys.executable,
            '-m', 'PyInstaller',
            '--onefile',
            '--windowed',
            '--clean',
            '--name=NetworkScanner',
            '--add-data=psloggedon.exe;.',
            'main.py'
        ]
        
        print("Iniciando compilação...")
        subprocess.run(commands, check=True)
        print("Compilação concluída com sucesso!")
        
    except subprocess.CalledProcessError as e:
        print(f"Erro durante a compilação: {e}")
        print("Verifique se todos os arquivos necessários estão no diretório.")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    build()