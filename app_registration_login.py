# tkinter application (your_tkinter_app.py)
import tkinter as tk
from tkinter import messagebox
import requests
from app_landing_page import LandingPage
import crypto_utils

class App:
    def __init__(self, master):
        self.master = master
        master.title("NickiesGoss")
        master.geometry("400x200")

        frame = tk.Frame(master)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Username").grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=0, column=1)

        tk.Label(frame, text="Password").grid(row=1, column=0, sticky="w")
        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1)

        tk.Button(frame, text="Register User", command=self.on_register).grid(row=2, column=0, columnspan=2, pady=10)
        tk.Button(frame, text="Login", command=self.on_login).grid(row=2, column=1, pady=10)

    def on_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        #print("Registering:", username, password)

        if not username or not password:
            messagebox.showerror("Validation Error", "Username and password cannot be empty")
            return

        public_key, private_key = crypto_utils.generate_keys_for_user()
        print("Public and private keys generated")

        encrypted_private_key = crypto_utils.encrypt_private_key(private_key, password) 
        encrypted_key_path = crypto_utils.save_encrypted_private_key(username, encrypted_private_key)
        messagebox.showinfo("Key Saved", f"Your private key has been securely saved at {encrypted_key_path}.")

        response = self.post_registration(username, password, public_key)
        if response and response.ok:
            messagebox.showinfo("Registration", "Registration successful!")
            self.open_landing_page(username)
        elif response:
            try:
                error_message = response.json().get('message', 'An error occurred. Please try again.')
            except ValueError:
                error_message = "Server response was not in JSON format"
            messagebox.showerror("Registration Failed", error_message)
        else:
            messagebox.showerror("Registration Failed", "Network or server error occurred")

        self.clear_entries()

    '''def post_registration(self, username, password, public_key):
        return requests.post('http://localhost:5000/register', json={
            'username': username, 'password': password, 'public_key': public_key
        }, timeout=5)'''

    def post_registration(self, username, password, public_key):
        try:
            response = requests.post('http://localhost:5000/register', json={
                'username': username, 'password': password, 'public_key': public_key
            }, timeout=5)
            response.raise_for_status()  # Raises HTTPError for bad responses
            return response
        except requests.exceptions.RequestException as e:
            # Here you could log the exception or handle it differently if needed
            print(f"Error during registration: {str(e)}")
            return None  # Return None or a suitable response-like object in case of error


    def on_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
    
        # Check if the username or password fields are empty
        if not username or not password:
            messagebox.showerror("Validation Error", "Username and password cannot be empty")
            return
    
        # Post request to the server for login
        try:
            response = requests.post('http://localhost:5000/login', json={
                'username': username,
                'password': password
            }, timeout=5)  # Added timeout for the request

            if response.status_code == 200:
                messagebox.showinfo("Login", "Login successful!")
                self.open_landing_page(username)    
            else:
                try:
                    # Attempt to parse the JSON response and get the 'message'
                    error_message = response.json().get('message', 'Invalid credentials')
                except ValueError:
                    # If there is no JSON response, default to a generic error
                    error_message = "An error occurred. Please try again."
                messagebox.showerror("Login Failed", error_message)

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Login Failed", f"Network error: {e}")
    
        # Clear the entry fields
        self.clear_entries()


    def open_landing_page(self, username):
        self.master.withdraw()
        landing_page_window = tk.Toplevel(self.master)
        LandingPage(landing_page_window, username)

    def clear_entries(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
