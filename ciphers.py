import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import math

# Rail Fence Cipher functions
def rail_fence_encrypt(msg, key):
    if key <= 1:
        return msg

    rail = ['' for _ in range(key)]
    direction = None
    row = 0

    for char in msg:
        rail[row] += char
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        row += direction

    return ''.join(rail)

def rail_fence_decrypt(cipher, key):
    if key <= 1:
        return cipher

    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    direction = None
    row, col = 0, 0

    for i in range(len(cipher)):
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        rail[row][col] = '*'
        col += 1
        row += direction

    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1

    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        row += direction


    return ''.join(result)


def polyalphabetic_cipher(text, key, decrypt=False):
    result = []
    for i, char in enumerate(text):
        if char.isalpha():
            shift = int(key[i % len(key)])
            if decrypt:
                shift = -shift  
            if char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            elif char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


# # Rail Fence Cipher functions
# def rail_fence_encrypt(msg, key):
#     if key <= 1:
#         return msg

#     rail = ['' for _ in range(key)]
#     direction = None
#     row = 0

#     for char in msg:
#         rail[row] += char
#         if row == 0:
#             direction = 1
#         elif row == key - 1:
#             direction = -1
#         row += direction

#     return ''.join(rail)

# def rail_fence_decrypt(cipher, key):
#     if key <= 1:
#         return cipher

#     rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
#     direction = None
#     row, col = 0, 0

#     for i in range(len(cipher)):
#         if row == 0:
#             direction = 1
#         elif row == key - 1:
#             direction = -1
#         rail[row][col] = '*'
#         col += 1
#         row += direction

#     index = 0
#     for i in range(key):
#         for j in range(len(cipher)):
#             if rail[i][j] == '*' and index < len(cipher):
#                 rail[i][j] = cipher[index]
#                 index += 1

#     result = []
#     row, col = 0, 0
#     for i in range(len(cipher)):
#         if row == 0:
#             direction = 1
#         elif row == key - 1:
#             direction = -1
#         if rail[row][col] != '*':
#             result.append(rail[row][col])
#             col += 1
#         row += direction

#     return ''.join(result)


def generate_keyword_cipher(keyword):
    # Create a list of unique letters in the keyword
    keyword = keyword.upper()
    unique_letters = []
    for letter in keyword:
        if letter not in unique_letters and letter.isalpha():
            unique_letters.append(letter)
    
    # Create the remaining letters of the alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    remaining_letters = [letter for letter in alphabet if letter not in unique_letters]
    
    # Generate the keyword cipher
    keyword_cipher = unique_letters + remaining_letters
    return ''.join(keyword_cipher)

def monoalphabetic_cipher(plain_text, key):
    key_cipher = generate_keyword_cipher(key)
    plain_text = plain_text.upper()
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():
            index = ord(char) - ord('A')
            cipher_text += key_cipher[index]
        else:
            cipher_text += char
    return cipher_text

def monoalphabetic_decipher(cipher_text, key):
    key_cipher = generate_keyword_cipher(key)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cipher_text = cipher_text.upper()
    plain_text = ""
    for char in cipher_text:
        if char.isalpha():
            index = key_cipher.index(char)
            plain_text += alphabet[index]
        else:
            plain_text += char
    return plain_text

# Row Transposition Cipher Functions
def transpose_cipher(msg, key):
    # """
    # This function performs both encryption and decryption using a transposition cipher.

    # Args:
    #     msg: The message to be encrypted or decrypted.
    #     key: The key to be used for the transposition cipher (unique characters).

    # Returns:``
    #     None. Prints the encrypted and decrypted messages.
    # """

    def encrypt(msg, key):
        cipher = ""
        k_indx = 0

        msg_len = len(msg)
        msg_lst = list(msg)
        key_lst = sorted(list(key))

        col = len(key)
        row = int(math.ceil(msg_len / col))

        fill_null = int((row * col) - msg_len)
        msg_lst.extend('_' * fill_null)

        matrix = [msg_lst[i: i + col] for i in range(0, len(msg_lst), col)]

        for _ in range(col):
            curr_idx = key.index(key_lst[k_indx])
            cipher += ''.join([row[curr_idx] for row in matrix])
            k_indx += 1

        return cipher

    def decrypt(cipher, key):
        msg = ""
        k_indx = 0
        msg_indx = 0

        msg_len = len(cipher)
        msg_lst = list(cipher)

        col = len(key)
        row = int(math.ceil(msg_len / col))
        key_lst = sorted(list(key))

        decrypted_msg = []
        for _ in range(row):
            decrypted_msg.append([None] * col)

        for _ in range(col):
            curr_idx = key.index(key_lst[k_indx])
            for j in range(row):
                decrypted_msg[j][curr_idx] = msg_lst[msg_indx]
                msg_indx += 1
            k_indx += 1

        try:
            msg = ''.join(sum(decrypted_msg, []))
        except TypeError:
            raise ValueError("Message length is not compatible with the key.")

        null_count = msg.count('_')
        if null_count > 0:
            return msg[:-null_count]
        return msg

    # Perform encryption and decryption
    encrypted_msg = encrypt(msg, key)
    decrypted_msg = decrypt(encrypted_msg, key)

    return encrypted_msg, decrypted_msg

# Playfair Cipher Functions
def generateKeyTable(key):
    key_letters = []
    for i in key:
        if i not in key_letters and i != 'j':
            key_letters.append(i)
    
    for i in range(97, 123):
        if chr(i) not in key_letters and chr(i) != 'j':
            key_letters.append(chr(i))
    
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(key_letters[i:i+5])
    
    return matrix

def search(matrix, letter):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == letter:
                return i, j

def encrypt_RowRule(matrix, row, col1, col2):
    encrypted_char1 = matrix[row][(col1 + 1) % 5]
    encrypted_char2 = matrix[row][(col2 + 1) % 5]
    return encrypted_char1, encrypted_char2

def encrypt_ColumnRule(matrix, col, row1, row2):
    encrypted_char1 = matrix[(row1 + 1) % 5][col]
    encrypted_char2 = matrix[(row2 + 1) % 5][col]
    return encrypted_char1, encrypted_char2

def encrypt_RectangleRule(matrix, row1, col1, row2, col2):
    encrypted_char1 = matrix[row1][col2]
    encrypted_char2 = matrix[row2][col1]
    return encrypted_char1, encrypted_char2

def playfair_encrypt(key, plaintext):
    plaintext = plaintext.replace(" ", "").lower()
    plaintext = plaintext.replace("j", "i")
    
    key_matrix = generateKeyTable(key)
    
    plaintext_pairs = []
    i = 0
    while i < len(plaintext):
        if i == len(plaintext) - 1 or plaintext[i] == plaintext[i + 1]:
            plaintext_pairs.append(plaintext[i] + 'x')
            i += 1
        else:
            plaintext_pairs.append(plaintext[i] + plaintext[i + 1])
            i += 2
    
    ciphertext = ""
    for pair in plaintext_pairs:
        char1, char2 = pair[0], pair[1]
        row1, col1 = search(key_matrix, char1)
        row2, col2 = search(key_matrix, char2)
        
        if row1 == row2:  
            encrypted_char1, encrypted_char2 = encrypt_RowRule(key_matrix, row1, col1, col2)
        elif col1 == col2:  
            encrypted_char1, encrypted_char2 = encrypt_ColumnRule(key_matrix, col1, row1, row2)
        else:  
            encrypted_char1, encrypted_char2 = encrypt_RectangleRule(key_matrix, row1, col1, row2, col2)
        
        ciphertext += encrypted_char1 + encrypted_char2
    
    return ciphertext

def decrypt_RowRule(matrix, row, col1, col2):
    decrypted_char1 = matrix[row][(col1 - 1) % 5]
    decrypted_char2 = matrix[row][(col2 - 1) % 5]
    return decrypted_char1, decrypted_char2

def decrypt_ColumnRule(matrix, col, row1, row2):
    decrypted_char1 = matrix[(row1 - 1) % 5][col]
    decrypted_char2 = matrix[(row2 - 1) % 5][col]
    return decrypted_char1, decrypted_char2

def decrypt_RectangleRule(matrix, row1, col1, row2, col2):
    decrypted_char1 = matrix[row1][col2]
    decrypted_char2 = matrix[row2][col1]
    return decrypted_char1, decrypted_char2

def playfair_decrypt(key, ciphertext):
    ciphertext = ciphertext.replace(" ", "").lower()
    ciphertext = ciphertext.replace("j", "i")
    
    key_matrix = generateKeyTable(key)
    
    ciphertext_pairs = []
    i = 0
    while i < len(ciphertext):
        if i == len(ciphertext) - 1 or ciphertext[i] == ciphertext[i + 1]:
            ciphertext_pairs.append(ciphertext[i] + 'x')
            i += 1
        else:
            ciphertext_pairs.append(ciphertext[i] + ciphertext[i + 1])
            i += 2
    
    plaintext = ""
    for pair in ciphertext_pairs:
        char1, char2 = pair[0], pair[1]
        row1, col1 = search(key_matrix, char1)
        row2, col2 = search(key_matrix, char2)
        
        if row1 == row2:  
            decrypted_char1, decrypted_char2 = decrypt_RowRule(key_matrix, row1, col1, col2)
        elif col1 == col2:  
            decrypted_char1, decrypted_char2 = decrypt_ColumnRule(key_matrix, col1, row1, row2)
        else:  
            decrypted_char1, decrypted_char2 = decrypt_RectangleRule(key_matrix, row1, col1, row2, col2)
        
        plaintext += decrypted_char1 + decrypted_char2
    
    return plaintext

# Existing cipher functions (Caesar, Vigenère, DES, AES) here
def caesar_encrypt(plain_text, shift):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted_text += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            elif char.isupper():
                encrypted_text += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    return caesar_encrypt(encrypted_text, -shift)

def vigenere_encrypt(plain_text, key):
    encrypted_text = ""
    key_index = 0
    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index].lower()) - ord('a')
            if char.islower():
                encrypted_text += chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            elif char.isupper():
                encrypted_text += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_decrypt(encrypted_text, key):
    decrypted_text = ""
    key_index = 0
    for char in encrypted_text:
        if char.isalpha():
            shift = ord(key[key_index].lower()) - ord('a')
            if char.islower():
                decrypted_text += chr(((ord(char) - ord('a') - shift + 26) % 26) + ord('a'))
            elif char.isupper():
                decrypted_text += chr(((ord(char) - ord('A') - shift + 26) % 26) + ord('A'))
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_text += char
    return decrypted_text

def des_encrypt(plain_text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(plain_text.encode('utf-8'), DES.block_size))
    return encrypted_text.hex()

def des_decrypt(encrypted_text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(bytes.fromhex(encrypted_text)), DES.block_size)
    return decrypted_text.decode('utf-8')

def aes_encrypt(plain_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    return encrypted_text.hex()

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(bytes.fromhex(encrypted_text)), AES.block_size)
    return decrypted_text.decode('utf-8')

class CipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher GUI")
        self.geometry("400x400")
        
        self.cipher_type = tk.StringVar()
        self.operation = tk.StringVar()
        
        self.create_widgets()

    def create_widgets(self):
        # Cipher type dropdown
        ttk.Label(self, text="Select Cipher:").pack(pady=10)
        cipher_menu = ttk.Combobox(self, textvariable=self.cipher_type)
        cipher_menu['values'] = ('Caesar', 'Vigenère', 'Playfair', 'DES', 'AES' , 'Row Transposition' , 'monoalphabetic' , 'Polyalphabetic' , 'RailFence')
        cipher_menu.pack(pady=10)
        
        # Operation dropdown
        ttk.Label(self, text="Operation:").pack(pady=10)
        operation_menu = ttk.Combobox(self, textvariable=self.operation)
        operation_menu['values'] = ('Encrypt', 'Decrypt')
        operation_menu.pack(pady=10)
        
        # Input text
        ttk.Label(self, text="plaintext:").pack(pady=10)
        self.input_text = tk.Text(self, height=5)
        self.input_text.pack(pady=10)
        
        # Key entry
        ttk.Label(self, text="Key:").pack(pady=10)
        self.key_entry = ttk.Entry(self)
        self.key_entry.pack(pady=10)
        
        # Execute button
        self.execute_button = ttk.Button(self, text="Execute", command=self.execute)
        self.execute_button.pack(pady=10)
        
        # Output text
        self.output_text = tk.Text(self, height=5)
        self.output_text.pack(pady=10)

    def execute(self):
        cipher = self.cipher_type.get()
        operation = self.operation.get()
        input_text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        
        if cipher == 'Caesar':
            try:
                shift = int(key)
            except ValueError:
                messagebox.showerror("Error", "Key must be an integer for Caesar cipher.")
                return
            
            if operation == 'Encrypt':
                result = caesar_encrypt(input_text, shift)
            else:
                result = caesar_decrypt(input_text, shift)
        
        elif cipher == 'Vigenère':
            if operation == 'Encrypt':
                result = vigenere_encrypt(input_text, key)
            else:
                result = vigenere_decrypt(input_text, key)
        
        elif cipher == 'monoalphabetic':
            if operation == 'Encrypt':
                result = monoalphabetic_cipher(input_text, key)
            else:
                result = monoalphabetic_decipher(input_text, key)
        
        elif cipher == 'Playfair':
            if operation == 'Encrypt':
                result = playfair_encrypt(key, input_text)
            else:
                result = playfair_decrypt(key, input_text)
        
        elif cipher == 'DES':
            if len(key) != 8:
                messagebox.showerror("Error", "Key must be 8 characters long for DES.")
                return

            if operation == 'Encrypt':
                result = des_encrypt(input_text, key)
            else:
                result = des_decrypt(input_text, key)
        
        elif cipher == 'AES':
            if len(key) not in [16, 24, 32]:
                messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long for AES.")
                return

            if operation == 'Encrypt':
                result = aes_encrypt(input_text, key)
            else:
                result = aes_decrypt(input_text, key)

        elif cipher == 'Row Transposition':
            if operation == 'Encrypt':
                result = transpose_cipher(input_text, key)[0]  # Index 0 for encrypted message
            else:
                result = transpose_cipher(input_text, key)[1]  # Index 1 for decrypted message   

        elif cipher == 'Polyalphabetic':
             if operation == 'Encrypt':
               result = polyalphabetic_cipher(input_text, key)
             else:
               result = polyalphabetic_cipher(input_text, key, decrypt=True)

        elif cipher == 'RailFence':
            try:
                key = int(key)
            except ValueError:
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, "Error: Key must be an integer for Rail Fence cipher.")
                return
            
            if operation == 'Encrypt':
                result = rail_fence_encrypt(input_text, key)
            else:
                result = rail_fence_decrypt(input_text, key)       
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, result)

if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()