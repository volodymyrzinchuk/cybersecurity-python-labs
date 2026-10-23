"""Завдання 3: хешування, CSV-база та JSON-логування (варіант 11)."""
import csv
import hashlib
import hmac
import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from shared.student import VARIANT_NUMBER

ALGORITHM = "blake2b"
MIN_LENGTH = 12
SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = Path(__file__).parent / "data"
USERS_CSV = DATA_DIR / "users.csv"
LOG_JSON = DATA_DIR / "log.json"

# Демонстраційні дані (не реальні паролі)
users_to_register = (
    ("alice", "Alice#Secure2024"),
    ("bob", "B0b!StrongPass99"),
    ("carol", "Carol$Cyber_123"),
    ("dave", "Dave&Network#77"),
    ("eve", "Eve_Analyst!2024"),
    ("frank", "Frank@Forensic12"),
    ("grace", "Grace#Crypto2024"),
    ("heidi", "Heidi!Defense_55"),
    ("ivan", "Ivan$Pentest#2024"),
    ("judy", "Judy@Threat_Intel9"),
)


class ValidationError(Exception):
    """Пароль не відповідає вимогам до довжини."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає hex-хеш від password + salt."""
    if not password or not salt:
        raise ValueError("Password and salt must not be empty")
    if len(password) < MIN_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_LENGTH} characters"
        )
    data = (password + salt).encode("utf-8")
    return hashlib.new(ALGORITHM, data).hexdigest()


def create_user(username, password):
    """Повертає (username, hash_value) з персональною сіллю."""
    return username, generate_hash(password, SALT)


def create_users(users_list):
    """Записує користувачів у users.csv (папка data створюється)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for username, password in users_list:
        try:
            rows.append(create_user(username, password))
        except (ValidationError, ValueError) as err:
            print(f"Skipped '{username}': {err}")
    with USERS_CSV.open("w", newline="", encoding="utf-8") as file:
        csv.writer(file).writerows(rows)


def load_users():
    """Зчитує users.csv у список users_db."""
    with USERS_CSV.open(newline="", encoding="utf-8") as file:
        return [tuple(row) for row in csv.reader(file)]


def write_log(username, success):
    """Дописує запис про спробу входу в log.json."""
    entry = {
        "event": "login",
        "user": username,
        "result": "success" if success else "failure",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "args": [],  # пароль навмисно не логуємо
        "kwargs": {},
    }
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            records = json.loads(LOG_JSON.read_text(encoding="utf-8"))
        except FileNotFoundError:
            records = []
        records.append(entry)
        LOG_JSON.write_text(
            json.dumps(records, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )
    except (PermissionError, IOError, ValueError) as err:
        print(f"Logging error: {err}")


def log_event(func):
    """Декоратор: логує кожну спробу входу."""
    @wraps(func)
    def wrapper(username, password):
        success = False
        try:
            success = func(username, password)
            return success
        finally:
            write_log(username, success)
    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін і пароль за users.csv."""
    if not username or not password:
        raise ValueError("Username and password must not be empty")
    for name, stored_hash in load_users():
        if name == username:
            candidate = generate_hash(password, SALT)
            return hmac.compare_digest(candidate, stored_hash)
    return False


def main():
    """Повний сценарій: реєстрація, читання, спроби входу."""
    try:
        create_users(users_to_register + (("temp_user", "short"),))
        users_db = load_users()
        print(f"{'Login':<10}Hash")
        for name, hash_value in users_db:
            print(f"{name:<10}{hash_value[:40]}...")

        attempts = [
            ("alice", "Alice#Secure2024"),
            ("alice", "WrongPassword123!"),
            ("nobody", "Some#Password12345"),
            ("bob", "short"),
            ("", ""),
        ]
        for username, password in attempts:
            try:
                ok = login(username, password)
                print(f"login({username!r}) -> {ok}")
            except (ValueError, ValidationError) as err:
                print(f"login({username!r}) error: {err}")
    except FileNotFoundError:
        print("Error: users.csv not found")
    except PermissionError:
        print("Error: no permission to access file")
    except IOError as err:
        print(f"I/O error: {err}")


if __name__ == "__main__":
    main()