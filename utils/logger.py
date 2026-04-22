class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose
    def info(self, m):    print(f"\033[94m[*]\033[0m {m}")
    def success(self, m): print(f"\033[92m[+]\033[0m {m}")
    def warning(self, m): print(f"\033[93m[!]\033[0m {m}")
    def error(self, m):   print(f"\033[91m[-]\033[0m {m}")
    def debug(self, m):
        if self.verbose: print(f"[D] {m}")
