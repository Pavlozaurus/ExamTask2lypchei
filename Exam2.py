import re

class SQLInjectionFilter:

    # Список потенційно небезпечних шаблонів для SQL-ін'єкцій
    SQL_INJECTION_PATTERNS = [
        r"--",             # SQL коментарі
        r";",              # Завершення SQL-запиту
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC)\b",  # Ключові слова SQL
        r"['\"]",        # Одинарні або подвійні лапки
        r"\\",           # Символ зворотного слешу
        r"\*",            # Символ зірочки
        r"\bOR\b|\bAND\b",  # Логічні оператори
        r"\d=\d",        # Умови (наприклад, 1=1)
    ]

    @staticmethod
    def is_safe(input_data):
        found_patterns = []
        for pattern in SQLInjectionFilter.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                found_patterns.append(pattern)
        return (not bool(found_patterns), found_patterns)

if __name__ == "__main__":
    print("Програма для виявлення спроб SQL-ін'єкцій")

    user_input = input("Введіть текст для аналізу: ")

    # Перевірка безпеки введених даних
    is_safe, patterns = SQLInjectionFilter.is_safe(user_input)

    if is_safe:
        print("Вхідні дані безпечні.")
    else:
        print("Попередження: у вхідних даних знайдено потенційно небезпечні шаблони!")
        print("Знайдені шаблони:", patterns)