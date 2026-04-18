# SecureBootCA2023Check

Win11 x64 Win32-GUI-Tool (ohne Konsole) zum Prüfen, ob die Secure-Boot-Datenbanken (`db`/`KEK`) ein Zertifikat enthalten, dessen DER-Bytes den ASCII-String **"Microsoft UEFI CA 2023"** enthalten.

## Run
Run from an elevated (Admin) console.

Exit codes:
- 0: present
- 1: not present
- 2: secure boot off (unknown)
- 3: error
