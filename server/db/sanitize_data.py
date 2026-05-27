import regex


CTRL_CHARACTERS = regex.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
 
def sanitize_ip(ip: str) -> str:
    """192.168.1.1 → 192[.]168[.]1[.]1"""
    ip = CTRL_CHARACTERS.sub('', str(ip))
    return ip.replace('.', '[.]')[:64]
 
def sanitize_path(path: str) -> str:
    """
    /api/search?q=<script> → /api/search?q=[<]script[>]
    http://evil.com        → hxxp://evil[.]com
    """
    path = CTRL_CHARACTERS.sub('', str(path))
    path = regex.sub(r'(?i)https://', 'hxxps://', path)
    path = regex.sub(r'(?i)http://',  'hxxp://',  path)
    path = path.replace('<', '[<]').replace('>', '[>]')
    return path[:1024]