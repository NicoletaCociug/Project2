import base64
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, simpledialog
import requests
from crypto_utils import decrypt_message_with_symmetric_key, load_and_decrypt_private_key, encrypt_message_with_symmetric_key, decrypt_symmetric_key
from Crypto.PublicKey import RSA


class GroupChatPage:
    def __init__(self, master, group_name, username, is_member=True, landing_page=None):
        self.master = master
        self.group_name = group_name
        self.username = username
        self.is_member = is_member
        self.landing_page = landing_page
        self.symmetric_key = None

        master.title(f"Chat = {group_name}")
        self,master.geometry("1000x800")
        self.setup_widgets()
        if self.is_member:
            self.symmetric_key = self.get_and_decrypt_symmetric_key(self.username)
        self.fetch_and_display_messages()

    def setup_widgets(self):
        # User display setup
        self.user_display = tk.Label(self.master, text=f"User: {self.username}", font=("Arial", 10))
        self.user_display.pack(padx=20, pady=5, anchor='ne')

        # Chat display area setup
        self.chat_display = tk.Text(self.master, state='disabled', wrap='word')
        self.chat_display.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # Conditional setup based on group membership
        print(f"is the user a member of the group?: {self.is_member}")
        if self.is_member:
            # Enable message entry and send button only for group members
            self.message_entry = tk.Entry(self.master)
            self.message_entry.pack(padx=20, pady=5)
            self.message_entry.bind('<Return>', self.send_message)

            self.send_button = tk.Button(self.master, text="Send Message", command=self.send_message)
            self.send_button.pack(padx=20, pady=10)

            self.add_users_label = tk.Label(self.master, text="Add users to group:")
            self.add_users_label.pack(pady=(5,0))

            self.users_combobox = ttk.Combobox(self.master, values=self.get_non_group_members())
            self.users_combobox.pack()

            self.add_user_button = tk.Button(self.master, text="Add User", command=self.add_user_to_group)
            self.add_user_button.pack(pady=(5,20))

            self.show_add_user_dialog_button = tk.Button(self.master, text="Add user", command=self.show_add_user_dialog)
            self.show_add_user_dialog_button.pack(pady=(5,20))
        else:
            # For non-members, display a read-only message and disable message-related widgets
            self.read_only_label = tk.Label(self.master, text="You are viewing this group in read-only mode.")
            self.read_only_label.pack(pady=10)
            self.chat_display.insert(tk.END, "Messages are encrypted and cannot be read.\n")
            
    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            encrypted_message = encrypt_message_with_symmetric_key(message, self.symmetric_key)
            response = requests.post('http://localhost:5000/send_message', json={
                'group_name': self.group_name,
                'sender_username': self.username,
                'ciphertext': encrypted_message
            })
            if response.ok:
                self.display_message(f"You: {message}")
                self.message_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", f"Failed to send message: {response.text}")

    def show_add_user_dialog(self):
        non_members = self.get_non_group_members()
        if not non_members:
            messagebox.showinfo("Info", "No more users to add")
            return

        #create a new toplevel window
        self.add_user_dialog = tk.Toplevel(self.master)
        self.add_user_dialog.title("Add Users")
        
        #label
        tk.Label(self.add_user_dialog, text="Select users to add:").pack()

        #listbox for non-members
        self.non_members_listbox = tk.Listbox(self.add_user_dialog, selectmode='multiple')
        self.non_members_listbox.pack(pady=5)

        #insert non-member usernames into the listbox
        for user in non_members:
            self.non_members_listbox.insert(tk.END, user)

        #button to confirm addition
        tk.Button(self.add_user_dialog, text="Add", command=self.perform_add_user_to_group).pack()

    def update_non_member_list(self):
        # Call this method to update the combobox with non-member usernames
        non_members = self.get_non_group_members()
        self.users_combobox['values'] = non_members

    def perform_add_user_to_group(self):
        selected_indices = self.non_members_listbox.curselection()
        selected_users = [self.non_members_listbox.get(i) for i in selected_indices]

        for user in selected_users:
            self.add_user_to_group_post_creation(user)

        # Close the dialog
        self.add_user_dialog.destroy()
        # Update the non-member combobox
        self.update_non_member_list()

    def add_user_to_group_post_creation(self, selected_user):
        # Call the API to add the user to the group
        response = requests.post('http://localhost:5000/add_user_to_group', json={
            'group_name': self.group_name,
            'username': selected_user
        })
        if not response.ok:
            messagebox.showerror("Error", f"Failed to add {selected_user} to the group")

    def fetch_and_display_messages(self):
        messages_response = requests.get(f'http://localhost:5000/fetch_messages_by_name/{self.group_name}')
        if messages_response.ok:
            messages = messages_response.json().get('messages', [])
            for message in messages:
                if self.is_member:
                    try:
                        decrypted_message = decrypt_message_with_symmetric_key(message['ciphertext'], self.symmetric_key)
                        display_message = f"{message['sender_username']}: {decrypted_message}"
                    except Exception as e:  # Catch decryption errors
                        display_message = f"{message['sender_username']}: [Error decrypting message: {e}]"
                else:
                    # For non-members, display the encrypted message as is
                    encrypted_message = message['ciphertext']
                    display_message = f"{message['sender_username']}: {encrypted_message}"

                self.display_message(display_message)
        else:
            messagebox.showerror("Error", f"Failed to fetch messages: {messages_response.text}")

    def get_non_group_members(self):
        response = requests.get(f'http://localhost:5000/non_group_users/{self.group_name}')
        return response.json() if response.ok else []

    def add_user_to_group(self):
        selected_user = self.users_combobox.get()
        response = requests.post('http://localhost:5000/add_user_to_group', json={
            'group_name': self.group_name,
            'username': selected_user
        })
        if response.ok:
            messagebox.showinfo("Success", f"{selected_user} added to the group")
            self.users_combobox['values'] = self.get_non_group_members()
        else:
            messagebox.showerror("Error", f"Failed to add {selected_user} to the group")

    def get_and_decrypt_symmetric_key(self, username):
        key_response = requests.get(f'http://localhost:5000/get_encrypted_symmetric_key/{self.group_name}/{username}')
        if key_response.ok:
            encrypted_symmetric_key = key_response.json()['encrypted_symmetric_key']
            # The user must enter their password to decrypt the private key
            password = self.get_user_password()  # Implement this method
            private_key = load_and_decrypt_private_key(username, password)
            if private_key:
                # Now decrypt the symmetric key with the RSA private key
                symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, private_key.exportKey())
                return symmetric_key
            else:
                messagebox.showerror("Error", "Failed to decrypt private key.")
        else:
            messagebox.showerror("Error", "Unable to fetch or decrypt group key.")
        return None

    def get_user_password(self):
        return simpledialog.askstring("Password", "Enter your password to unlock your private key:", show='*')


    def display_message(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

