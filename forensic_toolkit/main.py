#!/usr/bin/env python3

"""
AI Cyber Forensic Toolkit
Version : 1.0
Author  : CSRL Workshop

Main Menu
"""

import os
import sys
import subprocess
from forensic_toolkit.system_info import system_information
from forensic_toolkit.ollama_info import ollama_information, get_ollama_path
from forensic_toolkit.artifacts import collect_artifacts
from forensic_toolkit.hashing import hash_menu
from forensic_toolkit.process_info import process_information
from forensic_toolkit.timeline import create_timeline
from forensic_toolkit.report import generate_report


def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def banner():
    clear()

    print("=" * 60)
    print("      AI CYBER FORENSIC TOOLKIT v1.0")
    print("=" * 60)

    print("1. System Information")
    print("2. Ollama Information")
    print("3. Installed Models")
    print("4. Running Processes")
    print("5. Collect AI Artifacts")
    print("6. Generate SHA256 Hashes")
    print("7. Timeline Generator")
    print("8. Investigation Report (AI-Assisted)")
    print("9. Exit")

    print("=" * 60)


def show_installed_models():
    print("\n========== INSTALLED OLLAMA MODELS ==========\n")
    ollama_cmd = get_ollama_path()
    try:
        result = subprocess.run(
            f"{ollama_cmd} list",
            shell=True,
            capture_output=True,
            text=True
        )
        print(result.stdout.strip())
    except Exception as e:
        print(f"Error listing models: {e}")
    
    input("\nPress Enter to continue...")


while True:
    banner()

    choice = input("Enter Choice : ")

    if choice == "1":
        system_information()
    elif choice == "2":
        ollama_information()
    elif choice == "3":
        show_installed_models()
    elif choice == "4":
        process_information()        
    elif choice == "5":
        collect_artifacts()
    elif choice == "6":
        hash_menu()
    elif choice == "7":
        create_timeline()
    elif choice == "8":
        generate_report()
    elif choice == "9":
        print("\nGood Bye.\n")
        break
    else:
        print("\nInvalid choice. Please select 1-9.")
        input("Press Enter to continue...")