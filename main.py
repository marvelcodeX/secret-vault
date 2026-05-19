"""
main.py
-------
Secret Vault — CLI entry point.

Commands available after login:
  [1] List notes
  [2] Add note
  [3] Read note
  [4] Update note
  [5] Delete note
  [0] Exit
"""

import sys
import textwrap

from vault.auth  import authenticate, session
from vault.notes import add_note, read_note, update_note, remove_note, get_all_notes
from vault.storage import get_vault_path


# ── Terminal helpers ───────────────────────────────────────────────────────────

WIDTH = 60

def banner():
    print("\n" + "═" * WIDTH)
    print("  🔐  S E C R E T   V A U L T".center(WIDTH))
    print("  AES-256-GCM · PBKDF2 · Per-note keys".center(WIDTH))
    print("═" * WIDTH)

def divider():
    print("─" * WIDTH)

def success(msg: str):
    print(f"\n  ✅  {msg}\n")

def error(msg: str):
    print(f"\n  ❌  {msg}\n")

def info(msg: str):
    print(f"\n  ℹ️   {msg}\n")

def prompt(label: str) -> str:
    return input(f"  {label}: ").strip()

def multiline_prompt(label: str) -> str:
    """Read multi-line input until the user types END on its own line."""
    print(f"  {label} (type END on a new line to finish):")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


# ── Menu actions ───────────────────────────────────────────────────────────────

def cmd_list():
    notes = get_all_notes()
    divider()
    if not notes:
        info("No notes in your vault yet.")
        return

    print(f"  {'ID':<10} {'Title':<28} {'Updated'}")
    divider()
    for n in notes:
        title_short = n["title"][:27] + "…" if len(n["title"]) > 27 else n["title"]
        print(f"  {n['id']:<10} {title_short:<28} {n['updated_at']}")
    divider()


def cmd_add():
    divider()
    title = prompt("Note title")
    if not title:
        error("Title cannot be empty.")
        return

    body = multiline_prompt("Note body")
    if not body.strip():
        error("Note body cannot be empty.")
        return

    note_id = add_note(title, body)
    success(f"Note saved!  ID: {note_id}")


def cmd_read():
    divider()
    note_id = prompt("Note ID to read")
    try:
        note = read_note(note_id)
    except KeyError as e:
        error(str(e))
        return
    except ValueError as e:
        error(str(e))
        return

    print()
    print(f"  ┌── {note['title']} " + "─" * max(0, WIDTH - 6 - len(note['title'])))
    print(f"  │  Created : {note['created_at']}")
    print(f"  │  Updated : {note['updated_at']}")
    print(f"  ├" + "─" * (WIDTH - 3))
    # Wrap body at WIDTH-6 chars
    for raw_line in note["body"].splitlines():
        wrapped = textwrap.wrap(raw_line, width=WIDTH - 6) or [""]
        for wline in wrapped:
            print(f"  │  {wline}")
    print(f"  └" + "─" * (WIDTH - 3))
    print()


def cmd_update():
    divider()
    note_id = prompt("Note ID to update")

    try:
        existing = read_note(note_id)
    except KeyError as e:
        error(str(e))
        return

    print(f"\n  Current title : {existing['title']}")
    new_title = prompt("New title (leave blank to keep)")
    new_title = new_title if new_title else None

    print(f"\n  Current body (first line): {existing['body'].splitlines()[0][:50]}…")
    change_body = prompt("Replace body? [y/N]").lower()
    new_body = None
    if change_body == "y":
        new_body = multiline_prompt("New body")

    try:
        update_note(note_id, new_title, new_body)
        success("Note updated and re-encrypted.")
    except Exception as e:
        error(str(e))


def cmd_delete():
    divider()
    note_id = prompt("Note ID to delete")

    try:
        note = read_note(note_id)
    except KeyError as e:
        error(str(e))
        return

    confirm = prompt(f"Delete '{note['title']}'? This cannot be undone. [yes/N]")
    if confirm.lower() != "yes":
        info("Cancelled.")
        return

    try:
        remove_note(note_id)
        success("Note deleted.")
    except Exception as e:
        error(str(e))


# ── Main loop ──────────────────────────────────────────────────────────────────

MENU = """
  ┌─────────────────────────────┐
  │  [1]  List notes            │
  │  [2]  Add note              │
  │  [3]  Read note             │
  │  [4]  Update note           │
  │  [5]  Delete note           │
  │  [0]  Exit                  │
  └─────────────────────────────┘"""

COMMANDS = {
    "1": cmd_list,
    "2": cmd_add,
    "3": cmd_read,
    "4": cmd_update,
    "5": cmd_delete,
}


def main():
    banner()
    print(f"\n  Vault location: {get_vault_path()}\n")

    if not authenticate():
        sys.exit(1)

    while True:
        print(MENU)
        choice = input("  Choose [0-5]: ").strip()

        if choice == "0":
            session.clear()
            print("\n  🔒  Vault locked. Goodbye.\n")
            break
        elif choice in COMMANDS:
            try:
                COMMANDS[choice]()
            except KeyboardInterrupt:
                print("\n  (cancelled)\n")
        else:
            print("  ⚠  Invalid choice. Enter a number from 0 to 5.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  🔒  Vault locked. Goodbye.\n")
        sys.exit(0)