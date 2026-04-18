# SecureBootCA2023Check

Win11 x64 console tool to check whether the system Secure Boot databases (`db`/`KEK`) contain a certificate whose DER bytes include the ASCII string **"Microsoft UEFI CA 2023"**.

## Run
Run from an elevated (Admin) console.

Exit codes:
- 0: present
- 1: not present
- 2: secure boot off (unknown)
- 3: error
