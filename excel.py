import tkinter as tk
from tkinter import messagebox, filedialog
import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font

class SpreadsheetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Spreadsheet")
        self.root.geometry("800x600")

        # Variables to hold the spreadsheet data
        self.data = pd.DataFrame()
        
        # Menu bar
        self.create_menu()

        # Table (Canvas to simulate spreadsheet)
        self.create_table()

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.load_spreadsheet)
        file_menu.add_command(label="Save", command=self.save_spreadsheet)
        file_menu.add_command(label="Exit", command=self.root.quit)

        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Bold", command=self.make_bold)
        edit_menu.add_command(label="Sum", command=self.calculate_sum)

    def create_table(self):
        self.table_frame = tk.Frame(self.root)
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        # Create an empty DataFrame with 10 rows and 10 columns
        self.data = pd.DataFrame([[None] * 10 for _ in range(10)])

        self.cells = []
        for i in range(10):
            row_cells = []
            for j in range(10):
                cell = tk.Entry(self.table_frame, width=10, font=('Arial', 10))
                cell.grid(row=i, column=j, padx=5, pady=5)
                row_cells.append(cell)
            self.cells.append(row_cells)

    def load_spreadsheet(self):
        file_path = filedialog.askopenfilename(defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")])
        if file_path:
            self.data = pd.read_excel(file_path)
            self.update_table()

    def save_spreadsheet(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")])
        if file_path:
            self.data.to_excel(file_path, index=False)

    def update_table(self):
        # Update the table with data from the DataFrame
        for i in range(len(self.data)):
            for j in range(len(self.data.columns)):
                self.cells[i][j].delete(0, tk.END)
                self.cells[i][j].insert(tk.END, str(self.data.iloc[i, j]))

    def make_bold(self):
        # Mark the selected cell as bold
        for i in range(10):
            for j in range(10):
                if self.cells[i][j].focus_get():
                    self.cells[i][j].config(font=('Arial', 10, 'bold'))
                    self.data.iloc[i, j] = self.cells[i][j].get()

    def calculate_sum(self):
        # Sum values in the column
        for j in range(10):
            try:
                col_sum = self.data.iloc[:, j].apply(pd.to_numeric, errors='coerce').sum()
                self.cells[9][j].delete(0, tk.END)
                self.cells[9][j].insert(tk.END, str(col_sum))
            except Exception as e:
                messagebox.showerror("Error", "Error in calculating sum: " + str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = SpreadsheetApp(root)
    root.mainloop()
