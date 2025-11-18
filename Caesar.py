import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import string
import requests
from collections import Counter
import re

class CaesarCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифр Цезаря - Криптоанализ")
        self.root.geometry("900x700")
        
        # Загрузка словаря английских слов
        self.english_words = self.load_dictionary()
        
        # Создание вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Вкладка 1: Шифрование/Расшифрование
        self.tab1 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text="Шифрование/Расшифрование")
        self.create_encrypt_decrypt_tab()
        
        # Вкладка 2: Атака по известному тексту
        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab2, text="Known-plaintext атака")
        self.create_known_plaintext_tab()
        
        # Вкладка 3: Атака по шифротексту
        self.tab3 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab3, text="Ciphertext-only атака")
        self.create_ciphertext_only_tab()
        
        # Вкладка 4: Автоматическая атака со словарем
        self.tab4 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab4, text="Авто-атака со словарем")
        self.create_auto_attack_tab()
    
    def load_dictionary(self):
        """Загрузка словаря английских слов"""
        try:
            # Попытка загрузить словарь из интернета
            response = requests.get(
                "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt",
                timeout=5
            )
            words = set(response.text.lower().split())
            print(f"Загружено {len(words)} слов из онлайн-словаря")
            return words
        except:
            # Если не удалось загрузить, используем базовый набор
            basic_words = set(['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 
                             'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 
                             'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they',
                             'we', 'say', 'her', 'she', 'or', 'an', 'will', 'my', 'one',
                             'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out',
                             'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when',
                             'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
                             'take', 'people', 'into', 'year', 'your', 'good', 'some',
                             'could', 'them', 'see', 'other', 'than', 'then', 'now',
                             'look', 'only', 'come', 'its', 'over', 'think', 'also',
                             'back', 'after', 'use', 'two', 'how', 'our', 'work'])
            print(f"Используется базовый словарь ({len(basic_words)} слов)")
            return basic_words
    
    @staticmethod
    def caesar_encrypt(text, key):
        """Шифрование текста шифром Цезаря"""
        result = []
        for char in text:
            if char.upper() in string.ascii_uppercase:
                # Определяем, заглавная ли буква
                is_upper = char.isupper()
                # Преобразуем в верхний регистр для обработки
                char = char.upper()
                # Шифруем
                encrypted_char = chr((ord(char) - ord('A') + key) % 26 + ord('A'))
                # Возвращаем исходный регистр
                result.append(encrypted_char if is_upper else encrypted_char.lower())
            else:
                # Не буква - оставляем как есть
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def caesar_decrypt(text, key):
        """Расшифрование текста шифром Цезаря"""
        return CaesarCipherApp.caesar_encrypt(text, -key)
    
    def find_key_known_plaintext(self, plaintext, ciphertext):
        """Поиск ключа по известному открытому тексту"""
        # Находим первую букву в обоих текстах
        plain_letter = None
        cipher_letter = None
        
        for p, c in zip(plaintext, ciphertext):
            if p.upper() in string.ascii_uppercase and c.upper() in string.ascii_uppercase:
                plain_letter = p.upper()
                cipher_letter = c.upper()
                break
        
        if plain_letter and cipher_letter:
            key = (ord(cipher_letter) - ord(plain_letter)) % 26
            return key
        return None
    
    def analyze_frequency(self, text):
        """Частотный анализ текста"""
        # Удаляем все небуквенные символы и приводим к верхнему регистру
        letters = [c.upper() for c in text if c.upper() in string.ascii_uppercase]
        
        if not letters:
            return None
        
        # Подсчет частот
        freq_counter = Counter(letters)
        total = sum(freq_counter.values())
        
        # Нормализация частот
        frequencies = {letter: count/total for letter, count in freq_counter.items()}
        
        # Английские частоты букв (приблизительные)
        english_freq = {
            'E': 0.127, 'T': 0.091, 'A': 0.082, 'O': 0.075, 'I': 0.070,
            'N': 0.067, 'S': 0.063, 'H': 0.061, 'R': 0.060, 'D': 0.043,
            'L': 0.040, 'C': 0.028, 'U': 0.028, 'M': 0.024, 'W': 0.024,
            'F': 0.022, 'G': 0.020, 'Y': 0.020, 'P': 0.019, 'B': 0.015,
            'V': 0.010, 'K': 0.008, 'J': 0.002, 'X': 0.002, 'Q': 0.001, 'Z': 0.001
        }
        
        # Находим наиболее частую букву в шифротексте
        most_common = max(frequencies, key=frequencies.get)
        
        # Предполагаем, что это 'E' (самая частая буква в английском)
        estimated_key = (ord(most_common) - ord('E')) % 26
        
        return estimated_key
    
    def score_text(self, text):
        """Оценка текста на основе словаря"""
        words = re.findall(r'[a-zA-Z]+', text.lower())
        if not words:
            return 0
        
        valid_words = sum(1 for word in words if word in self.english_words and len(word) > 2)
        return valid_words / len(words) if words else 0
    
    def auto_decrypt(self, ciphertext):
        """Автоматическая расшифровка с использованием словаря"""
        best_key = 0
        best_score = 0
        best_text = ""
        
        results = []
        
        for key in range(26):
            decrypted = self.caesar_decrypt(ciphertext, key)
            score = self.score_text(decrypted)
            results.append((key, decrypted, score))
            
            if score > best_score:
                best_score = score
                best_key = key
                best_text = decrypted
        
        return best_key, best_text, best_score, results
    
    def create_encrypt_decrypt_tab(self):
        """Создание вкладки шифрования/расшифрования"""
        # Ввод текста
        tk.Label(self.tab1, text="Введите текст:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.input_text1 = scrolledtext.ScrolledText(self.tab1, height=5, width=80)
        self.input_text1.grid(row=1, column=0, columnspan=3, padx=10, pady=5)
        
        # Ключ
        tk.Label(self.tab1, text="Ключ (0-25):").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.key_var = tk.IntVar(value=3)
        self.key_spinbox = tk.Spinbox(self.tab1, from_=0, to=25, textvariable=self.key_var, width=10)
        self.key_spinbox.grid(row=2, column=1, sticky='w', padx=10, pady=5)
        
        # Кнопки
        tk.Button(self.tab1, text="Зашифровать", command=self.encrypt_text).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(self.tab1, text="Расшифровать", command=self.decrypt_text).grid(row=3, column=1, padx=10, pady=10)
        
        # Результат
        tk.Label(self.tab1, text="Результат:").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        self.output_text1 = scrolledtext.ScrolledText(self.tab1, height=5, width=80)
        self.output_text1.grid(row=5, column=0, columnspan=3, padx=10, pady=5)
    
    def create_known_plaintext_tab(self):
        """Создание вкладки атаки по известному тексту"""
        # Открытый текст
        tk.Label(self.tab2, text="Открытый текст:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.plaintext_input = scrolledtext.ScrolledText(self.tab2, height=5, width=80)
        self.plaintext_input.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        
        # Зашифрованный текст
        tk.Label(self.tab2, text="Зашифрованный текст:").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.ciphertext_input = scrolledtext.ScrolledText(self.tab2, height=5, width=80)
        self.ciphertext_input.grid(row=3, column=0, columnspan=2, padx=10, pady=5)
        
        # Кнопка анализа
        tk.Button(self.tab2, text="Найти ключ", command=self.find_key_known).grid(row=4, column=0, padx=10, pady=10)
        
        # Результат
        self.result_label2 = tk.Label(self.tab2, text="", font=("Arial", 12, "bold"))
        self.result_label2.grid(row=5, column=0, columnspan=2, padx=10, pady=10)
    
    def create_ciphertext_only_tab(self):
        """Создание вкладки атаки по шифротексту"""
        # Зашифрованный текст
        tk.Label(self.tab3, text="Зашифрованный текст:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.ciphertext_only_input = scrolledtext.ScrolledText(self.tab3, height=5, width=80)
        self.ciphertext_only_input.grid(row=1, column=0, padx=10, pady=5)
        
        # Кнопка анализа
        tk.Button(self.tab3, text="Показать все варианты", command=self.bruteforce_attack).grid(row=2, column=0, padx=10, pady=10)
        
        # Результаты
        tk.Label(self.tab3, text="Варианты расшифровки:").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.results_text = scrolledtext.ScrolledText(self.tab3, height=15, width=80)
        self.results_text.grid(row=4, column=0, padx=10, pady=5)
    
    def create_auto_attack_tab(self):
        """Создание вкладки автоматической атаки"""
        # Зашифрованный текст
        tk.Label(self.tab4, text="Зашифрованный текст:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.auto_ciphertext_input = scrolledtext.ScrolledText(self.tab4, height=5, width=80)
        self.auto_ciphertext_input.grid(row=1, column=0, padx=10, pady=5)
        
        # Кнопка анализа
        tk.Button(self.tab4, text="Автоматическая расшифровка", command=self.auto_attack).grid(row=2, column=0, padx=10, pady=10)
        
        # Результаты
        tk.Label(self.tab4, text="Результат анализа:").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.auto_result_label = tk.Label(self.tab4, text="", font=("Arial", 11, "bold"))
        self.auto_result_label.grid(row=4, column=0, padx=10, pady=5)
        
        tk.Label(self.tab4, text="Расшифрованный текст:").grid(row=5, column=0, sticky='w', padx=10, pady=5)
        self.auto_results_text = scrolledtext.ScrolledText(self.tab4, height=5, width=80)
        self.auto_results_text.grid(row=6, column=0, padx=10, pady=5)
        
        tk.Label(self.tab4, text="Все варианты (отсортированы по вероятности):").grid(row=7, column=0, sticky='w', padx=10, pady=5)
        self.all_variants_text = scrolledtext.ScrolledText(self.tab4, height=8, width=80)
        self.all_variants_text.grid(row=8, column=0, padx=10, pady=5)
    
    def encrypt_text(self):
        """Обработчик шифрования"""
        text = self.input_text1.get(1.0, tk.END).strip()
        key = self.key_var.get()
        
        if not text:
            messagebox.showwarning("Предупреждение", "Введите текст для шифрования")
            return
        
        encrypted = self.caesar_encrypt(text, key)
        self.output_text1.delete(1.0, tk.END)
        self.output_text1.insert(1.0, encrypted)
    
    def decrypt_text(self):
        """Обработчик расшифрования"""
        text = self.input_text1.get(1.0, tk.END).strip()
        key = self.key_var.get()
        
        if not text:
            messagebox.showwarning("Предупреждение", "Введите текст для расшифрования")
            return
        
        decrypted = self.caesar_decrypt(text, key)
        self.output_text1.delete(1.0, tk.END)
        self.output_text1.insert(1.0, decrypted)
    
    def find_key_known(self):
        """Обработчик поиска ключа по известному тексту"""
        plaintext = self.plaintext_input.get(1.0, tk.END).strip()
        ciphertext = self.ciphertext_input.get(1.0, tk.END).strip()
        
        if not plaintext or not ciphertext:
            messagebox.showwarning("Предупреждение", "Введите оба текста")
            return
        
        key = self.find_key_known_plaintext(plaintext, ciphertext)
        
        if key is not None:
            # Проверка найденного ключа
            test_encrypted = self.caesar_encrypt(plaintext, key)
            if test_encrypted.upper() == ciphertext.upper():
                self.result_label2.config(
                    text=f"Найден ключ: {key}\n✓ Ключ подтвержден!",
                    fg="green"
                )
            else:
                self.result_label2.config(
                    text=f"Предполагаемый ключ: {key}\n⚠ Требуется проверка",
                    fg="orange"
                )
        else:
            self.result_label2.config(
                text="Не удалось определить ключ",
                fg="red"
            )
    
    def bruteforce_attack(self):
        """Обработчик атаки перебором"""
        ciphertext = self.ciphertext_only_input.get(1.0, tk.END).strip()
        
        if not ciphertext:
            messagebox.showwarning("Предупреждение", "Введите зашифрованный текст")
            return
        
        self.results_text.delete(1.0, tk.END)
        
        # Частотный анализ для предположения
        estimated_key = self.analyze_frequency(ciphertext)
        
        for key in range(26):
            decrypted = self.caesar_decrypt(ciphertext, key)
            if key == estimated_key:
                self.results_text.insert(tk.END, f"Ключ {key:2d}: {decrypted} ← ВЕРОЯТНЫЙ (частотный анализ)\n\n")
            else:
                self.results_text.insert(tk.END, f"Ключ {key:2d}: {decrypted}\n\n")
    
    def auto_attack(self):
        """Обработчик автоматической атаки со словарем"""
        ciphertext = self.auto_ciphertext_input.get(1.0, tk.END).strip()
        
        if not ciphertext:
            messagebox.showwarning("Предупреждение", "Введите зашифрованный текст")
            return
        
        best_key, best_text, best_score, all_results = self.auto_decrypt(ciphertext)
        
        # Показываем лучший результат
        self.auto_result_label.config(
            text=f"Наиболее вероятный ключ: {best_key} (точность: {best_score:.1%})",
            fg="green" if best_score > 0.5 else "orange"
        )
        
        self.auto_results_text.delete(1.0, tk.END)
        self.auto_results_text.insert(1.0, best_text)
        
        # Показываем все варианты, отсортированные по вероятности
        self.all_variants_text.delete(1.0, tk.END)
        sorted_results = sorted(all_results, key=lambda x: x[2], reverse=True)
        
        for key, text, score in sorted_results[:10]:  # Показываем топ-10
            preview = text[:100] + "..." if len(text) > 100 else text
            self.all_variants_text.insert(
                tk.END,
                f"Ключ {key:2d} (точность: {score:.1%}): {preview}\n\n"
            )

def main():
    root = tk.Tk()
    app = CaesarCipherApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()