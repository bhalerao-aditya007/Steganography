"""One-click launcher for the TESSERA v2 Mirage Interactive Research Demo."""
import os
import sys
import subprocess

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(root_dir, ".venv", "Scripts", "python.exe")
    app_path = os.path.join(root_dir, "tessera", "ui", "app.py")
    
    if not os.path.exists(venv_python):
        print(f"Error: Virtual environment python not found at {venv_python}")
        sys.exit(1)
        
    print("=" * 65)
    print("STARTING TESSERA v2: MIRAGE RESEARCH DEMONSTRATION")
    print("=" * 65)
    print(f"Launching Streamlit application at: {app_path}")
    print("Open http://localhost:8501 in your browser once started.\n")
    
    env = os.environ.copy()
    env["PYTHONPATH"] = root_dir
    
    cmd = [
        venv_python,
        "-m",
        "streamlit",
        "run",
        app_path,
        "--server.port=8501",
        "--server.headless=false",
        "--browser.gatherUsageStats=false"
    ]
    subprocess.run(cmd, env=env)

if __name__ == "__main__":
    main()
