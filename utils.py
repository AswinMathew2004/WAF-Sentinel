#!/usr/bin/env python3
"""CLI display utilities for WAF Sentinel."""

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()


def print_banner(version="2.0.0"):
    banner = rf"""
{Fore.CYAN}
 ██╗    ██╗ █████╗ ███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██║    ██║██╔══██╗██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ██║ █╗ ██║███████║█████╗      ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ██║███╗██║██╔══██║██╔══╝      ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ╚███╔███╔╝██║  ██║██║         ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝         ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  Advanced Web Application Firewall Fingerprinting Tool{Style.RESET_ALL}
{Fore.LIGHTBLACK_EX}  Version {version} | For authorized testing only{Style.RESET_ALL}
{Fore.LIGHTBLACK_EX}  ─────────────────────────────────────────────────────{Style.RESET_ALL}
"""
    print(banner)


def print_status(msg):
    print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def print_success(msg):
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_info(msg):
    print(f"  {Fore.CYAN}[i]{Style.RESET_ALL} {msg}")

def print_section(title):
    width = 55
    line = "─" * width
    print(f"\n  {Fore.CYAN}{line}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  {title}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{line}{Style.RESET_ALL}\n")

def format_table(headers, rows, col_widths=None):
    """Simple text table formatter."""
    if not col_widths:
        col_widths = [max(len(str(row[i])) for row in [headers] + rows) + 2 for i in range(len(headers))]
    
    header_line = "".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
    sep_line = "".join("─" * w for w in col_widths)
    
    lines = [f"  {Fore.WHITE}{header_line}{Style.RESET_ALL}", f"  {sep_line}"]
    for row in rows:
        line = "".join(str(c).ljust(w) for c, w in zip(row, col_widths))
        lines.append(f"  {line}")
    
    return "\n".join(lines)
