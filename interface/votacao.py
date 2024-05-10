import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import font

class VotingApp:
    def __init__(self, master):
        self.master = master
        master.title("Votação Eleitoral")

        # Ativar tela cheia
        self.master.attributes('-fullscreen', True)
        #self.master.state('zoomed')

        self.custom_font = font.Font(family="Helvetica", size=14)

        self.setup_window()

        self.partidos = [
            {"nome_completo": "Partido Nacional Republicano", "diminutivo": "PNR"},
            {"nome_completo": "Partido Comunista dos Trabalhadores Portugueses", "diminutivo": "PCTP"},
            {"nome_completo": "Partido Social Democrata", "diminutivo": "PSD"},
            {"nome_completo": "Partido Socialista", "diminutivo": "PS"},
            {"nome_completo": "Centro Democrático Social - Partido Popular", "diminutivo": "CDS-PP"},
            {"nome_completo": "Bloco de Esquerda", "diminutivo": "BE"},
            {"nome_completo": "Partido Comunista Português", "diminutivo": "PCP"},
            {"nome_completo": "Partido Ecologista Os Verdes", "diminutivo": "PEV"},
            {"nome_completo": "Pessoas-Animais-Natureza", "diminutivo": "PAN"},
            {"nome_completo": "Iniciativa Liberal", "diminutivo": "IL"},
            {"nome_completo": "Chega", "diminutivo": "CH"},
            {"nome_completo": "LIVRE", "diminutivo": "L"},
            {"nome_completo": "Aliança", "diminutivo": "A"},
            {"nome_completo": "Partido da Terra", "diminutivo": "MPT"},
            {"nome_completo": "Nós, Cidadãos!", "diminutivo": "NC"},
            {"nome_completo": "R.I.R. - Reagir, Incluir, Reciclar", "diminutivo": "RIR"},
            {"nome_completo": "Partido Renovador Democrático", "diminutivo": "PRD"},
            {"nome_completo": "Partido dos Pintassilgos", "diminutivo": "PDB"},
            {"nome_completo": "Voto em Branco", "diminutivo": " "}
            # Adicione mais partidos conforme necessário
        ]


        self.check_vars = {partido["diminutivo"]: tk.BooleanVar() for partido in self.partidos}

        for index, partido in enumerate(self.partidos):
            self.add_party(party_frame=self.scrollable_frame, partido=partido, index=index)

        # Botão de submissão do voto, inicialmente oculto
        self.submit_button = tk.Button(self.scrollable_frame, text="Submeter Voto", bg="#FFD700" ,command=self.submit_vote, font=self.custom_font)
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
        frame = tk.Frame(party_frame, bg="#FFFFFF",pady = 7) #espaço entre linhas
        frame.grid(row=index * 2, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)

        label_nome = tk.Label(frame, text=partido["nome_completo"], bg="#FFFFFF", font=self.custom_font)
        label_nome.grid(row=0, column=0, sticky="w")
        label_dim = tk.Label(frame, text=f"({partido['diminutivo']})", bg="#FFFFFF", font=self.custom_font)
        label_dim.grid(row=0, column=1, sticky="e")

        check_button = tk.Checkbutton(frame, variable=self.check_vars[partido["diminutivo"]], bg="#FFFFFF", command=lambda p=partido["diminutivo"]: self.on_check(p))
        check_button.grid(row=0, column=2, sticky="e")

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
        selected_partido = next((k for k, v in self.check_vars.items() if v.get()), None)
        if not selected_partido:
            messagebox.showerror("Erro", "Por favor, selecione um partido antes de votar.")
        else:
            messagebox.showinfo("Voto", f"Voto registrado para: {selected_partido}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VotingApp(root)
    root.mainloop()