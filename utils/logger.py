class Logger:
    R="[91m"; G="[92m"; Y="[93m"; B="[94m"; X="[0m"
    def __init__(self, verbose=False): self.verbose = verbose
    def info(self, m):    print(f"{self.B}[*]{self.X} {m}")
    def success(self, m): print(f"{self.G}[+]{self.X} {m}")
    def warning(self, m): print(f"{self.Y}[!]{self.X} {m}")
    def error(self, m):   print(f"{self.R}[-]{self.X} {m}")
    def debug(self, m):
        if self.verbose: print(f"[DBG] {m}")
