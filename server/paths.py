import sys, os

def bundle_dir() -> str:
    """directorul temporar unde PyInstaller extrage resursele read-only (client/, CSV)"""
    return getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))

def app_dir() -> str:
    """directorul unde sta EXECUTABILUL aici merg fisierele writable (config, db, .env)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    # dev mode: radacina server/
    return os.path.dirname(os.path.abspath(__file__))