import sys
import socket
from impacket.smbconnection import SMBConnection

def parse_smb_version(dialect):
    """ Map SMB dialects to readable versions """
    SMB_VERSIONS = {
        0x0202: "SMB 2.0.2",
        0x0210: "SMB 2.1",
        0x0300: "SMB 3.0",
        0x0302: "SMB 3.0.2",
        0x0311: "SMB 3.1.1",
    }
    return SMB_VERSIONS.get(dialect, "Unknown SMB Version")

def smb_scan(target_ip):
    """ Scan SMB service on target and gather version, security, shares, and vulnerabilities """
    print(f"\n[+] Scanning SMB on {target_ip}...")

    try:
        # Connect to SMB Service (Port 445)
        conn = SMBConnection(target_ip, target_ip, timeout=5)

        # Attempt anonymous login
        try:
            conn.login('', '')
            guest_access = True
        except Exception as e:
            print("[!] Anonymous access denied. Some features will be skipped.")
            guest_access = False

        # Extract SMB details
        dialect = conn.getDialect()
        smb_version = parse_smb_version(dialect)
        signing_required = conn.isSigningRequired()
        os_version = conn.getServerOS()
        domain_name = conn.getServerDomain()

        # Display results
        print(f"[*] SMB Version: {smb_version}")
        print(f"[*] SMB Signing Required: {'Yes' if signing_required else 'No'}")
        print(f"[*] OS Version: {os_version if os_version else 'Unknown'}")
        print(f"[*] Authentication Domain: {domain_name if domain_name else 'Unknown'}")

        # Check SMB Encryption (Only for SMB 3.0+)
        if smb_version in ["SMB 3.0", "SMB 3.1.1"]:
            print("[*] SMB Encryption is supported in this version. Checking if it's enabled...")
            if not signing_required:
                print("[!] SMB Encryption is likely DISABLED (encryption requires signing).")
            else:
                print("[+] SMB Encryption might be enabled. Verify manually.")

        # List Available Shares (Only if guest access is allowed)
        if guest_access:
            print("\n[+] Enumerating SMB Shares:")
            try:
                shares = conn.listShares()
                for share in shares:
                    share_name = share['shi1_netname'].decode().strip()
                    print(f"    - {share_name}")
                    try:
                        conn.connectTree(share_name)
                        print("      [✔] Anonymous access: Allowed")
                    except:
                        print("      [✖] Anonymous access: Denied")
            except Exception as e:
                print("[!] Failed to list shares:", str(e))
        else:
            print("[!] Skipping share enumeration due to lack of guest access.")

        # Check for Null Session Vulnerability (Only if guest access is allowed)
        if guest_access:
            print("\n[+] Checking for Null Session Vulnerability...")
            try:
                conn.listPath("IPC$", "*")  # Attempt to list files in IPC$
                print("[✔] Null Session Vulnerability DETECTED! Server allows anonymous enumeration.")
            except:
                print("[✖] Null Session Not Allowed. Server is more secure.")
        else:
            print("[!] Skipping null session test due to lack of guest access.")

        # Security Warning if SMB Signing is Disabled
        if not signing_required:
            print("[!] SMB Signing is NOT required. This is a security risk!")

        # Close connection
        conn.close()

    except Exception as e:
        print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python smb_advanced_scanner.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    smb_scan(target_ip)
# This is a port of the metasploit aux smb version scanner I made to understand how SMB enumeration works