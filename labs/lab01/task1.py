"""Завдання 1: аналізатор надійності паролів (варіант 11).

Категорії визначаються за кількістю виконаних груп символів
(цифра, велика літера, спеціальний символ):
    3 групи -> Сильний або Дуже сильний
    2 групи -> Середній
    0-1 група -> Слабкий
"""
import random

from shared.student import STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "APT@Detect10n", "simple", "Red@Team2023", "participant", "Blue@T3am",
    "common123", "Purple@T34m", "regular123", "Gr33n@Team", "normal123",
]
CRITERIA = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN = {
    "simple", "participant", "common123", "regular123", "normal123", "test",
}


def add_duplicates(passwords, count=3):
    """Додає в кінець копії паролів за випадковими індексами."""
    result = list(passwords)
    for index in random.sample(range(len(passwords)), count):
        result.append(passwords[index])
    return result


def analyze_password(password, all_passwords, criteria, forbidden):
    """Повертає категорію надійності пароля."""
    min_len = criteria["min_length"]
    if password.lower() in forbidden or len(password) < min_len:
        return "Заборонений"

    met = sum([
        any(ch.isdigit() for ch in password),
        any(ch.isupper() for ch in password),
        any(not ch.isalnum() for ch in password),
    ])
    if met == 3:
        long_enough = len(password) >= min_len + 4
        unique = all_passwords.count(password) == 1
        if long_enough and unique:
            return "Дуже сильний"
        return "Сильний"
    if met == 2:
        return "Середній"
    return "Слабкий"


def main():
    """Запуск аналізу та вивід таблиці."""
    print(f"{STUDENT_NAME}, варіант {VARIANT_NUMBER}")
    passwords = add_duplicates(PASSWORDS)
    print(f"{'№':<4}{'Пароль':<20}{'Довжина':<10}Категорія")
    print("-" * 50)
    for number, pwd in enumerate(passwords, start=1):
        category = analyze_password(pwd, passwords, CRITERIA, FORBIDDEN)
        print(f"{number:<4}{pwd:<20}{len(pwd):<10}{category}")


if __name__ == "__main__":
    main()