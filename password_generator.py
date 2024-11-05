import random
import string
import tkinter as tk
from tkinter import messagebox

# Function to generate password
def generate_password():
    try:
        length = int(length_entry.get())  # Get password length
        if length <= 0:
            raise ValueError("Password length must be greater than zero.")
    except ValueError as e:
        messagebox.showerror("Error", f"Invalid input: {e}")
        return

    use_letters = letters_var.get()
    use_numbers = numbers_var.get()
    use_symbols = symbols_var.get()

    # Build the character set based on user selection
    character_set = ""
    if use_letters:
        character_set += string.ascii_letters
    if use_numbers:
        character_set += string.digits
    if use_symbols:
        character_set += string.punctuation

    if not character_set:
        messagebox.showerror("Error", "Please select at least one character type.")
        return

    # Generate password
    password = ''.join(random.choice(character_set) for _ in range(length))

    # Display password in the entry box
    password_entry.delete(0, tk.END)  # Clear previous password
    password_entry.insert(0, password)  # Display the new password

# Function to copy password to clipboard
def copy_to_clipboard():
    password = password_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("No Password", "No password to copy!")

# Set up the main window
root = tk.Tk()
root.title("Random Password Generator")

# Label and Entry for password length
length_label = tk.Label(root, text="Password Length:")
length_label.grid(row=0, column=0, padx=10, pady=10)
length_entry = tk.Entry(root)
length_entry.grid(row=0, column=1, padx=10, pady=10)

# Checkboxes for character options (letters, numbers, symbols)
letters_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

letters_check = tk.Checkbutton(root, text="Include Letters", variable=letters_var)
letters_check.grid(row=1, column=0, padx=10, pady=10)

numbers_check = tk.Checkbutton(root, text="Include Numbers", variable=numbers_var)
numbers_check.grid(row=1, column=1, padx=10, pady=10)

symbols_check = tk.Checkbutton(root, text="Include Symbols", variable=symbols_var)
symbols_check.grid(row=2, column=0, padx=10, pady=10)

# Button to generate the password
generate_button = tk.Button(root, text="Generate Password", command=generate_password)
generate_button.grid(row=2, column=1, padx=10, pady=10)

# Entry field to display the generated password
password_entry = tk.Entry(root, width=40)
password_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Button to copy password to clipboard
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

# Run the application
root.mainloop()
