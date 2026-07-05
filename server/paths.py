import sys, os

def bundle_dir() -> str:
    #read-only resources for pyinstaller
    return getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))

def app_dir() -> str:
    #writable files
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    #root server
    return os.path.dirname(os.path.abspath(__file__))