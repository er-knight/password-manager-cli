import sqlite3

from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

from rich.console import Console
from rich.style import Style
from rich.table import Table


def encrypt_database(database_path: Path, encrypted_database_path: Path) -> bool:

    try:
        with database_path.open("rb") as f:
            database_content = f.read()

        password = prompt("Password: ", is_password=True)
        key = SHA256.new(data=password.encode("utf-8")).digest() # len(key) = 32 (bytes)
        nonce = get_random_bytes(12) # len(nonce) = 12 (bytes)
        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(database_content) # len(tag) = 16 (bytes)

        with encrypted_database_path.open("wb") as f:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)

        return True

    except Exception as e:
        print(e)
    
    return False

def decrypt_database(encrypted_database_path: Path, database_path: Path) -> bool:

    try:
        with encrypted_database_path.open("rb") as f:
            nonce, tag = f.read(12), f.read(16)
            encrypted_database_content = f.read()

        password = prompt("Password: ", is_password=True)
        key = SHA256.new(data=password.encode("utf-8")).digest() # len(key) = 32 (bytes)
        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
        database_content = cipher.decrypt_and_verify(encrypted_database_content, tag).decode("utf-8")

        with database_path.open("wb") as f:
            f.write(database_content)

        return True

    except Exception as e:
        print(e)
    
    return False


def make_table(
    index: int, website: str, username: str | None, 
    email: str | None, password: str | None, notes: str | None
) -> Table:

    table = Table(
        title=f"Record {index}", 
        title_style=Style(underline=True), 
        title_justify="left", 
        show_header=False, 
        show_lines=True
    )
    
    table.add_column(justify="right")
    table.add_column(justify="left")

    table.add_row("website", website)
    if username: 
        table.add_row("username", username)
    if email: 
        table.add_row("email", email)
    table.add_row("password", password)
    if notes: 
        table.add_row("notes", notes)

    return table


def main(database_path: Path) -> None:

    console = Console()

    option_list = ["Show", "Add", "Update", "Delete"]
    
    option_completer = WordCompleter(
        option_list, ignore_case=True
    )

    option = prompt(
        "Select Option\nShow/Add/Update/Delete: ",
        completer=option_completer,
        complete_while_typing=True,
        placeholder=option_list[0]
    )    

    console.log(option)

    with sqlite3.connect(str(database_path)) as connection:

        cursor = connection.cursor()
        
        match option:
        
            case "Show":
        
                cursor.execute("""
                    SELECT DISTINCT website FROM records
                """)

                website_list = list(sorted(row[0] for row in cursor.fetchall()))
        
                website_completer = WordCompleter(
                    website_list, ignore_case=True
                )

                website = prompt(
                    "Select Website: ",
                    completer=website_completer,
                    complete_while_typing=True,
                    placeholder=website_list[0]
                )
                
                console.log(website)

                cursor.execute("""
                    SELECT website, username, email, password, notes 
                    FROM records WHERE website == ?
                """, (website,))

                records = cursor.fetchall()

                console.line()

                for index, record in enumerate(records, start=1):
                    website, username, email, password, notes = record
                    console.print(make_table(
                        index, website, username, email, password, notes
                    ))
                    console.line()
                
            case "Add":
                
                website  = prompt("Website  : ")
                username = prompt("Username : ")
                email    = prompt("Email    : ")
                password = prompt("Password : ")
                notes    = prompt("Notes    : ")

                cursor.execute("""
                    INSERT INTO records VALUES (?, ?, ?, ?, ?, ?)
                """, (None, website, username, email, password, notes))

            case "Update":
                
                cursor.execute("""
                    SELECT DISTINCT website FROM records
                """)

                website_list = list(sorted(row[0] for row in cursor.fetchall()))
        
                website_completer = WordCompleter(
                    website_list, ignore_case=True
                )

                website = prompt(
                    "Select Website: ",
                    completer=website_completer,
                    complete_while_typing=True,
                    placeholder=website_list[0]
                )
                
                console.log(website)

                cursor.execute("""
                    SELECT record_id, website, username, email, password, notes 
                    FROM records WHERE website == ?
                """, (website,))

                records = cursor.fetchall()

                console.line()

                for index, record in enumerate(records, start=1):
                    _, website, username, email, password, notes = record
                    console.print(make_table(
                        index, website, username, email, password, notes
                    ))
                    console.line()

                record_index_list = [f"Record {index + 1}" for index in range(len(records))]

                record_index_completer = WordCompleter(
                    record_index_list, ignore_case=True
                )

                record_index = int(prompt(
                    "Select Record for Update: ",
                    completer=record_index_completer,
                    complete_while_typing=True,
                    placeholder=record_index_list[0]
                ).split()[1]) - 1

                console.clear()

                record = records[record_index]                
                
                console.log(record)

                console.print(make_table(record_index + 1, record[1], record[2], record[3], record[4], record[5]))
                console.line()

                field_list = ["Website", "Username", "Email", "Password", "Notes"]

                field_completer = WordCompleter(
                    field_list, ignore_case=True
                )

                field = prompt(
                    "Select Field to Update: ",
                    completer=field_completer,
                    complete_while_typing=True,
                    placeholder=field_list[0]
                ).lower()

                console.log(field)

                updated_field = prompt(f"Enter New {field.capitalize()}: ")

                match field:
                    case "website":
                        cursor.execute("""
                            UPDATE records
                            SET website = ?
                            WHERE record_id = ? 
                        """, (updated_field, record[0]))
                    case "username":
                        cursor.execute("""
                            UPDATE records
                            SET username = ?
                            WHERE record_id = ? 
                        """, (updated_field, record[0]))
                    case "email":
                        cursor.execute("""
                            UPDATE records
                            SET email = ?
                            WHERE record_id = ? 
                        """, (updated_field, record[0]))
                    case "password":
                        cursor.execute("""
                            UPDATE records
                            SET password = ?
                            WHERE record_id = ? 
                        """, (updated_field, record[0]))
                    case "notes":
                        cursor.execute("""
                            UPDATE records
                            SET notes = ?
                            WHERE record_id = ? 
                        """, (updated_field, record[0]))
                    case _:
                        print("Error: Invalid Field"); return

            case "Delete":
                
                cursor.execute("""
                    SELECT DISTINCT website FROM records
                """)

                website_list = list(sorted(row[0] for row in cursor.fetchall()))
        
                website_completer = WordCompleter(
                    website_list, ignore_case=True
                )
                website = prompt(
                    "Select Website: ",
                    completer=website_completer,
                    complete_while_typing=True,
                    placeholder=website_list[0]
                )
                
                console.log(website)

                cursor.execute("""
                    SELECT record_id, website, username, email, password, notes 
                    FROM records WHERE website == ?
                """, (website,))

                records = cursor.fetchall()

                console.line()

                for index, record in enumerate(records, start=1):
                    _, website, username, email, password, notes = record
                    console.print(make_table(
                        index, website, username, email, password, notes
                    ))
                    console.line()

                record_index_list = [f"Record {index + 1}" for index in range(len(records))]

                record_index_completer = WordCompleter(
                    record_index_list, ignore_case=True
                )

                record_index = int(prompt(
                    "Select Record to Delete: ",
                    completer=record_index_completer,
                    complete_while_typing=True,
                    placeholder=record_index_list[0]
                ).split()[1]) - 1

                console.clear()

                record = records[record_index]                
                
                console.log(record)

                cursor.execute("""
                    DELETE FROM records
                    WHERE record_id = ?
                """, (record[0],))

            case _:

                print("Error: Invalid Option"); return

if __name__ == "__main__":

    decrypt_database(
        Path(__file__).parent / "database.db.enc", 
        Path(__file__).parent / "database.db"
    )

    main(Path(__file__).parent / "database.db")

    encrypt_database(
        Path(__file__).parent / "database.db", 
        Path(__file__).parent / "database.db.enc"
    )



