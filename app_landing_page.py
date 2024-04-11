import tkinter as tk
from tkinter import messagebox
from app_groupChat_page import GroupChatPage
import requests  # Import requests to make HTTP calls

class LandingPage:
    def __init__(self, master, username):
        self.master = master
        self.username = username
        master.title(f"Gossip Girl - Welcome {username}")

        # Create frames for different sections
        self.top_frame = tk.Frame(master)
        self.top_frame.pack(side=tk.TOP, fill=tk.X, padx=20, pady=20)

        self.groups_frame = tk.Frame(master)
        self.groups_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.bottom_frame = tk.Frame(master)
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=20)

        # Greeting label
        self.greeting_label = tk.Label(self.top_frame, text=f"Hi {username}", font=("Arial", 16))
        self.greeting_label.pack(side=tk.LEFT)

        # Groups label and listboxes
        self.groups_label = tk.Label(self.groups_frame, text="Groups Available", font=("Arial", 14))
        self.groups_label.pack()
        
        self.your_groups_label = tk.Label(self.groups_frame, text="Groups you're in:")
        self.your_groups_label.pack()

        self.your_groups_listbox = tk.Listbox(self.groups_frame, height=10)
        self.your_groups_listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.your_groups_listbox.bind('<<ListboxSelect>>', self.open_group_chat)

        self.not_in_groups_label = tk.Label(self.groups_frame, text="Groups you're not in:")
        self.not_in_groups_label.pack()

        self.not_in_groups_listbox = tk.Listbox(self.groups_frame, height=10)
        self.not_in_groups_listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.not_in_groups_listbox.bind('<<ListboxSelect>>', self.open_group_chat_non_member)

        # Invitation buttons
        self.invitations_received_button = tk.Button(self.bottom_frame, text="Invitations Received")
        self.invitations_received_button.pack(side=tk.LEFT)

        self.approve_invitations_button = tk.Button(self.bottom_frame, text="Approve Invitations")
        self.approve_invitations_button.pack(side=tk.LEFT)

        self.create_group_button = tk.Button(self.top_frame, text="Create Group", command=self.create_group)
        self.create_group_button.pack(side=tk.LEFT)

        # Display groups upon initialization
        self.display_groups(username)

    def create_group(self):
        self.new_group_window = tk.Toplevel(self.master)
        self.new_group_window.title("Create New Group")
        tk.Label(self.new_group_window, text="Group Name:").pack()
        self.group_name_entry = tk.Entry(self.new_group_window)
        self.group_name_entry.pack()
        tk.Label(self.new_group_window, text="Select users to add:").pack()
        self.users_listbox = tk.Listbox(self.new_group_window, selectmode='multiple')
        self.users_listbox.pack()
        self.populate_users_listbox()
        tk.Button(self.new_group_window, text="Create Group", command=self.confirm_create_group).pack()

    def populate_users_listbox(self):
        try:
            response = requests.get('http://localhost:5000/users')
            if response.ok:
                users = response.json()
                for user_dict in users:
                    username = user_dict['username']  # Extract the username from the dictionary
                    self.users_listbox.insert(tk.END, username)
            else:
                messagebox.showerror("Error", f"Failed to fetch user list: {response.text}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {e}")


    def confirm_create_group(self):
        group_name = self.group_name_entry.get()
        selected_indices = self.users_listbox.curselection()
        selected_users = [self.users_listbox.get(i) for i in selected_indices]

        if not group_name or not selected_users:
            messagebox.showerror("Error", "Please enter a group name and select at least one user.")
            return

        # Post the group creation to the server
        response = requests.post('http://localhost:5000/create_group', json={
            'group_name': group_name,
            'members': selected_users
        })

        if response.ok:
            messagebox.showinfo("Success", "Group created successfully!")
            self.display_groups(self.username)
            self.new_group_window.destroy()
        else:
            try:
                # Attempt to parse the JSON response and get the 'message'
                error_message = response.json().get('message', 'An error occurred during group creation.')
            except ValueError:
                # If there is no JSON response, default to a generic error
                error_message = "An error occurred. Please try again."
            messagebox.showerror("Group Creation Failed", error_message)


    def open_group_chat(self, event):
        selection = self.your_groups_listbox.curselection()
        if selection:
            index = selection[0]
            group_name = self.your_groups_listbox.get(index)
            self.open_messaging_page(group_name, True) #tru indicating that the user is a member

    def open_group_chat_non_member(self, event):
        selection = self.not_in_groups_listbox.curselection()
        if selection:
            index = selection[0]
            group_name = self.not_in_groups_listbox.get(index)
            self.open_messaging_page(group_name, False)

    def open_messaging_page(self, group_name, is_member):
        self.master.withdraw()
        chat_window = tk.Toplevel(self.master)
        chat_window.geometry("400x500")
        GroupChatPage(chat_window, group_name, self.username, is_member, self)

    def display_groups(self, username):
        # Fetch all groups
        all_groups_response = requests.get('http://localhost:5000/groups')
        if all_groups_response.ok:
            all_groups = all_groups_response.json()
            print("All groups:", all_groups)  # Log to console for debugging
        else:
            print("Error fetching all groups:", all_groups_response.text)
            all_groups = []

        # Fetch groups that the user is part of
        user_groups_response = requests.get(f'http://localhost:5000/user_groups/{username}')
        if user_groups_response.ok:
            user_groups = user_groups_response.json()['your_groups']
            print("User's groups:", user_groups)  # Log to console for debugging
        else:
            print("Error fetching user's groups:", user_groups_response.text)
            user_groups = []

        # Clear existing entries in the listboxes
        self.your_groups_listbox.delete(0, tk.END)
        self.not_in_groups_listbox.delete(0, tk.END)

        # Populate the listboxes
        for group in all_groups:
            if group in user_groups:
                self.your_groups_listbox.insert(tk.END, group)
            else:
                self.not_in_groups_listbox.insert(tk.END, group)

# This is the function to be called to display the landing page
def show_landing_page(username):
    root = tk.Toplevel()  # Create a new window on top of the main window
    root.geometry("800x600")
    LandingPage(root, username)

