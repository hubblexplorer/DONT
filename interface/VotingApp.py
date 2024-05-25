import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import font

class VotingApp:
    def __init__(self, master,candidates,ele_name):
        self.master = master
        master.title(ele_name)

        # Ativar tela cheia
        self.master.attributes('-fullscreen', True)

        self.custom_font = font.Font(family="Helvetica", size=14)

        self.setup_window()

        self.partidos = [{"nome_completo": candidate} for candidate in candidates]


        self.check_vars = {partido["nome_completo"]: tk.BooleanVar() for partido in self.partidos}

        for index, partido in enumerate(self.partidos):
            self.add_party(party_frame=self.scrollable_frame, partido=partido, index=index)

        # Botão de submissão do voto, inicialmente oculto
        self.submit_button = tk.Button(self.scrollable_frame, text="Submeter Voto", bg="#FFD700", command=self.submit_vote, font=self.custom_font)
        self.submit_button.grid(row=len(self.partidos) * 2, column=0, columnspan=3, pady=20, sticky="ew")
        self.submit_button.grid_remove() #talvez remova isto

    def setup_window(self):
        self.canvas = tk.Canvas(self.master, bg="white")
        self.scrollbar = tk.Scrollbar(self.master, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="white")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        # Inicialmente posiciona a janela no meio do canvas
        self.window = self.canvas.create_window((self.master.winfo_width() // 2, 0),
                                                window=self.scrollable_frame, anchor="n")

        # Atualizar a posição da janela quando o canvas for redimensionado
        self.canvas.bind("<Configure>", self.reposition_frame)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        max_height = 900
        self.master.geometry(f"560x{max_height}")
        self.master.resizable(True, True)

    def reposition_frame(self, event):
        # Recalcula a posição central para a janela dentro do canvas
        self.canvas.coords(self.window, (event.width // 3, 0))

    def add_party(self, party_frame, partido, index):
        frame = tk.Frame(party_frame, bg="#FFFFFF", pady=7)  # espaço entre linhas
        frame.grid(row=index * 2, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)

        label_nome = tk.Label(frame, text=partido["nome_completo"], bg="#FFFFFF", font=self.custom_font)
        label_nome.grid(row=0, column=0, sticky="w")

        check_button = tk.Checkbutton(frame, variable=self.check_vars[partido["nome_completo"]], bg="#FFFFFF", command=lambda p=partido["nome_completo"]: self.on_check(p))
        check_button.grid(row=0, column=1, sticky="e")

        if index < len(self.partidos) - 1:
            separator = ttk.Separator(party_frame, orient='horizontal')
            separator.grid(row=index * 2 + 1, column=0, sticky="ew", columnspan=3)

    def on_check(self, selected):
        any_selected = any(var.get() for var in self.check_vars.values())
        if any_selected:
            self.submit_button.grid()  # Assegurar que o botão é mostrado se algum item está selecionado
        else:
            self.submit_button.grid_remove()  # Esconder o botão se nada está selecionado
        for key, var in self.check_vars.items():
            if key != selected:
                var.set(False)

    def submit_vote(self):
        self.selected_partido = next((k for k, v in self.check_vars.items() if v.get()), None)
        if not self.selected_partido:
            messagebox.showerror("Erro", "Por favor, selecione um partido antes de votar.")
        else:
            messagebox.showinfo("Voto", f"Voto registrado para: {self.selected_partido}")
            self.master.destroy()  # Fechar a janela após a votação

    def get_boletim(self):
        return self.partidos
        
    def get_vote(self):
        return self.selected_partido

def start_app():
    root = tk.Tk()
    app = VotingApp(root)
    root.mainloop()
    vot = app.get_vote()
    return vot

if __name__ == "__main__":
    start_app()
