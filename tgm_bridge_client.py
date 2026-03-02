import os
import json
import time
import string
import getpass
import requests
from datetime import datetime, timezone

from colorama import init, Fore, Style
from dotenv import load_dotenv

APP_NAME = "TGM Bridge"
PIN_FILE = "pin.json"
DEFAULT_PIN = "9847"
USERNAME_DOMAIN = "tgmbridge.local"  # internal-only fake domain


# --------------------------
# Encoding map (A–Z)
# --------------------------
ALPHABET = string.ascii_uppercase
CODES = [
    "*.", "-*", "**", "--", "*-*", "-**", "*--", "***", "--*", "-*-*",
    "*--*", "-*-", "---", ".*-", ".--", "..-", "...-", ".-..", "-..-",
    "--.-", "...*", "*..*", "..-*", "*.-*", "-..-", ".**", "*.*"
]
ENCODE_MAP = dict(zip(ALPHABET, CODES))
DECODE_MAP = {v: k for k, v in ENCODE_MAP.items()}


def encode_message(msg: str) -> str:
    msg = msg.upper()
    out = []
    for ch in msg:
        if ch in ENCODE_MAP:
            out.append(ENCODE_MAP[ch])
        elif ch == " ":
            out.append("/")
        else:
            out.append("?")
    return " ".join(out)


def decode_message(code_msg: str) -> str:
    parts = code_msg.split()
    out = []
    for token in parts:
        if token == "/":
            out.append(" ")
        else:
            out.append(DECODE_MAP.get(token, "?"))
    return "".join(out)


# --------------------------
# PIN storage
# --------------------------
def save_pin(pin: str) -> None:
    data = {"pin": pin, "updated_at": datetime.now(timezone.utc).isoformat()}
    with open(PIN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_pin() -> str:
    if not os.path.exists(PIN_FILE):
        save_pin(DEFAULT_PIN)
        return DEFAULT_PIN
    try:
        with open(PIN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        pin = str(data.get("pin", DEFAULT_PIN)).strip()
        if len(pin) == 4 and pin.isdigit():
            return pin
    except Exception:
        pass
    save_pin(DEFAULT_PIN)
    return DEFAULT_PIN


def verify_pin() -> bool:
    stored = load_pin()
    attempts = 3
    while attempts > 0:
        entered = input(Fore.GREEN + "Enter 4-digit PIN: " + Style.RESET_ALL).strip()
        if entered == stored:
            return True
        attempts -= 1
        print(Fore.RED + f"Wrong PIN. Attempts left: {attempts}")
    return False


def change_pin() -> None:
    while True:
        new_pin = input(Fore.YELLOW + "New 4-digit PIN: " + Style.RESET_ALL).strip()
        if not (len(new_pin) == 4 and new_pin.isdigit()):
            print(Fore.RED + "PIN must be exactly 4 digits.")
            continue
        confirm = input(Fore.YELLOW + "Confirm PIN: " + Style.RESET_ALL).strip()
        if confirm != new_pin:
            print(Fore.RED + "PINs do not match.")
            continue
        save_pin(new_pin)
        print(Fore.CYAN + "PIN updated.")
        return


# --------------------------
# UI
# --------------------------
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    clear_screen()
    eye = r"""
                 /\                
                /  \               
               / /\ \              
              / /__\ \             
             /  ____  \            
            /__/    \__\           
               \  /               
                \/                
              ( o o )             
               \_=_/              
    """
    title = r"""
████████╗  ██████╗  ███╗   ███╗
╚══██╔══╝ ██╔════╝  ████╗ ████║
   ██║    ██║  ███╗ ██╔████╔██║
   ██║    ██║   ██║ ██║╚██╔╝██║
   ██║    ╚██████╔╝ ██║ ╚═╝ ██║
   ╚═╝     ╚═════╝  ╚═╝     ╚═╝
    """
    print(Fore.YELLOW + eye)
    print(Fore.CYAN + Style.BRIGHT + title)
    print(Fore.MAGENTA + Style.BRIGHT + "                 Powered by TGM\n")
    print(Fore.BLUE + f"                 {APP_NAME}\n")


# --------------------------
# Firebase REST helpers
# --------------------------
def load_env():
    load_dotenv(".env")
    api_key = os.getenv("FIREBASE_API_KEY", "").strip()
    project_id = os.getenv("FIREBASE_PROJECT_ID", "").strip()
    if not api_key or not project_id:
        raise RuntimeError("Missing FIREBASE_API_KEY or FIREBASE_PROJECT_ID in .env")
    return api_key, project_id


def firebase_sign_in(api_key: str, email_addr: str, password: str) -> dict:
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    payload = {"email": email_addr, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()  # idToken, localId(uid)


def firestore_base(project_id: str) -> str:
    return f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"


def fs_headers(id_token: str) -> dict:
    return {"Authorization": f"Bearer {id_token}", "Content-Type": "application/json"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_iso(ts: str) -> float:
    if not ts:
        return 0.0
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0.0


def pretty_firebase_http_error(prefix: str, e: requests.HTTPError):
    try:
        msg = e.response.json().get("error", {}).get("message", "UNKNOWN")
        print(Fore.RED + f"{prefix}: {msg}")
    except Exception:
        print(Fore.RED + f"{prefix}: {e}")


# --------------------------
# Firestore operations (client)
# --------------------------
def ensure_user_profile(project_id: str, id_token: str, uid: str, username: str):
    """
    Creates/updates the users/{uid} document so it exists in Firestore UI.
    This avoids confusion where subcollections exist but parent doc does not.
    """
    base = firestore_base(project_id)
    url = f"{base}/users/{uid}"
    body = {
        "fields": {
            "username": {"stringValue": username},
            "updatedAt": {"stringValue": now_iso()},
        }
    }
    r = requests.patch(url, headers=fs_headers(id_token), json=body, timeout=20)
    r.raise_for_status()


def send_to_admin(project_id: str, id_token: str, uid: str, text: str):
    base = firestore_base(project_id)
    doc_id = str(int(time.time() * 1000))
    url = f"{base}/users/{uid}/outbox?documentId={doc_id}"
    body = {
        "fields": {
            "text": {"stringValue": text},
            "createdAt": {"stringValue": now_iso()},
        }
    }
    r = requests.post(url, headers=fs_headers(id_token), json=body, timeout=20)
    r.raise_for_status()


def list_inbox_no_index(project_id: str, id_token: str, uid: str, limit: int = 50):
    """
    No orderBy -> avoids index requirements.
    We fetch and sort locally by createdAt.
    """
    base = firestore_base(project_id)
    url = f"{base}/users/{uid}/inbox?pageSize={limit}"
    r = requests.get(url, headers=fs_headers(id_token), timeout=20)
    r.raise_for_status()
    return r.json().get("documents", [])


def mark_read(id_token: str, doc_name: str):
    url = f"https://firestore.googleapis.com/v1/{doc_name}?updateMask.fieldPaths=read"
    body = {"fields": {"read": {"booleanValue": True}}}
    r = requests.patch(url, headers=fs_headers(id_token), json=body, timeout=20)
    r.raise_for_status()


def show_replies(project_id: str, id_token: str, uid: str):
    try:
        docs = list_inbox_no_index(project_id, id_token, uid, limit=80)
    except requests.HTTPError as e:
        pretty_firebase_http_error("Inbox fetch failed (Firebase)", e)
        return
    except Exception as e:
        print(Fore.RED + f"Inbox fetch failed: {e}")
        return

    if not docs:
        print(Fore.YELLOW + "No replies yet.")
        return

    def sort_key(d):
        fields = d.get("fields", {})
        created = fields.get("createdAt", {}).get("stringValue", "")
        return parse_iso(created)

    docs.sort(key=sort_key, reverse=True)

    printed = 0
    for d in docs:
        fields = d.get("fields", {})
        text = fields.get("text", {}).get("stringValue", "")
        created = fields.get("createdAt", {}).get("stringValue", "")
        read = fields.get("read", {}).get("booleanValue", False)
        name = d.get("name")

        if not text:
            continue

        status = "READ" if read else "NEW"
        print(Fore.CYAN + "-" * 52)
        print(Fore.GREEN + f"[{status}] " + Style.RESET_ALL + created)
        print(Fore.YELLOW + text)

        if not read and name:
            try:
                mark_read(id_token, name)
            except Exception:
                pass

        printed += 1

    if printed == 0:
        print(Fore.YELLOW + "Replies exist but none were readable (missing fields).")


def auto_check(project_id: str, id_token: str, uid: str):
    try:
        interval = int(input(Fore.YELLOW + "Auto-check interval seconds (min 5): " + Style.RESET_ALL).strip())
        if interval < 5:
            interval = 5
    except Exception:
        interval = 10

    print(Fore.MAGENTA + f"Auto-check ON (every {interval}s). Ctrl+C to stop.\n")
    try:
        while True:
            show_replies(project_id, id_token, uid)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(Fore.CYAN + "\nAuto-check stopped.")


# --------------------------
# Main
# --------------------------
def main():
    init(autoreset=True)
    banner()

    if not verify_pin():
        print(Fore.RED + "Access denied.")
        return

    try:
        api_key, project_id = load_env()
    except Exception as e:
        print(Fore.RED + f"Config error: {e}")
        return

    print(Fore.BLUE + "Login")
    username = input(Fore.GREEN + "Username: " + Style.RESET_ALL).strip().replace(" ", "")
    password = getpass.getpass("Password (hidden): ").strip()

    if not username or not password:
        print(Fore.RED + "Username and password required.")
        return

    email_addr = f"{username}@{USERNAME_DOMAIN}"

    # Login with professional error output
    try:
        auth_data = firebase_sign_in(api_key, email_addr, password)
        id_token = auth_data["idToken"]
        uid = auth_data["localId"]
    except requests.HTTPError as e:
        pretty_firebase_http_error("Login failed (Firebase)", e)
        return
    except Exception as e:
        print(Fore.RED + f"Login failed: {e}")
        return

    # IMPORTANT: show UID so admin can reply correctly, and avoid username-vs-uid mistakes.
    print(Fore.CYAN + f"\n✅ Logged in successfully.")
    print(Fore.CYAN + f"Your UID (share this with admin if needed): {uid}\n")

    # Ensure user profile doc exists (avoids Firestore UI confusion)
    try:
        ensure_user_profile(project_id, id_token, uid, username)
    except Exception:
        # best-effort; app can work without this
        pass

    while True:
        print(Fore.BLUE + "\n=== TGM Bridge Menu ===")
        print(Fore.MAGENTA + "1) Encode a message")
        print(Fore.MAGENTA + "2) Decode a message")
        print(Fore.MAGENTA + "3) Send message to Admin")
        print(Fore.MAGENTA + "4) Check replies")
        print(Fore.MAGENTA + "5) Auto-check replies")
        print(Fore.MAGENTA + "6) Change PIN")
        print(Fore.MAGENTA + "7) Exit")

        choice = input(Fore.CYAN + "Choose (1-7): " + Style.RESET_ALL).strip()

        if choice == "1":
            msg = input(Fore.GREEN + "Enter message: " + Style.RESET_ALL)
            print(Fore.YELLOW + "\nEncoded:\n" + Style.RESET_ALL + encode_message(msg))

        elif choice == "2":
            code_msg = input(Fore.GREEN + "Enter code (use / for spaces): " + Style.RESET_ALL)
            print(Fore.YELLOW + "\nDecoded:\n" + Style.RESET_ALL + decode_message(code_msg))

        elif choice == "3":
            msg = input(Fore.GREEN + "Message to Admin: " + Style.RESET_ALL).strip()
            if not msg:
                print(Fore.YELLOW + "Cancelled (empty message).")
                continue
            try:
                send_to_admin(project_id, id_token, uid, msg)
                print(Fore.CYAN + "Sent to admin.")
            except requests.HTTPError as e:
                pretty_firebase_http_error("Send failed (Firebase)", e)
            except Exception as e:
                print(Fore.RED + f"Send failed: {e}")

        elif choice == "4":
            show_replies(project_id, id_token, uid)

        elif choice == "5":
            auto_check(project_id, id_token, uid)

        elif choice == "6":
            change_pin()

        elif choice == "7":
            print(Fore.CYAN + "Goodbye.")
            return

        else:
            print(Fore.RED + "Invalid option.")


if __name__ == "__main__":
    main()
