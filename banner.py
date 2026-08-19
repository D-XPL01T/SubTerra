VERSION = "v0.0.6"

# ANSI color codes
RED = "\033[31m"
RESET = "\033[0m"


def print_version() -> None:
    """Prints the version message."""
    print(f"Current SubTerra version {VERSION}")


def print_banner() -> None:
    """Prints the SubTerra ASCII art banner."""
    # Using a raw string (r"...") to safely include backslashes and backticks
    banner = r"""      
   ______           _________    
  / ____|     | |   |__   __|                   
 | (___  _   _| |__    | | ___ _ __ _ __ __ _   
  \___ \| | | | '_ \   | |/ _ \ '__| '__/ _` |    
  ____) | |_| | |_) |  | |  __/ |  | | | (_| |    
 |_____/ \__,_|_.__/   |_|\___|_|  |_|  \__,_|   """

    version_str = f"Current SubTerra version {VERSION}"
    print(banner)
    # Red tagline directly below the ASCII art
    print(f"{RED}Made with jealousy by XPL01T{RESET}")
    # Right-align the version string to 48 characters to match the banner's visual width
    print(f"{version_str:>48}\n")