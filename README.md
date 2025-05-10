# Network Vulnerability Scanner Lite 🕵️

A simple web-based network vulnerability scanner built with Python, Streamlit, and Nmap. This tool allows you to perform various Nmap scans on a target host and view the results in a user-friendly interface.

**Disclaimer:** This tool is for educational and authorized testing purposes only. Always obtain explicit permission before scanning any network or host that you do not own or have explicit consent to test. Unauthorized scanning can be illegal.

## Features

*   User-friendly web interface powered by Streamlit.
*   Input target IP address or hostname.
*   Select from common Nmap scan types:
    *   Quick Scan (`-T4 -F`)
    *   Standard Service Scan (`-sV`)
    *   Aggressive Scan (`-A`)
    *   TCP SYN Scan (`-sS`) (may require root/admin privileges)
    *   UDP Scan (`-sU`)
    *   Comprehensive Scan (`-sV -sC -O -T4`)
*   Option to provide custom Nmap arguments.
*   Displays:
    *   Host status (up/down).
    *   Resolved hostname.
    *   Detected OS (if applicable scan type is used, e.g., `-A`, `-O`).
    *   Open ports, protocols, states, services, product names, and versions.
    *   Output from Nmap Scripting Engine (NSE) scripts (e.g., from `-sC` or `--script vuln`).
*   Results are presented in a clear, readable format, including a table for port information.

## Screenshot

**(Optional: Add a screenshot of your application here if you like. You can take a screenshot, upload it to your GitHub repo, and then link it like this: `![App Screenshot](path/to/your/screenshot.png)`)**

## Prerequisites

1.  **Nmap:** The Nmap command-line tool must be installed on your system and accessible in your system's PATH.
    *   **Linux (Debian/Ubuntu):** `sudo apt-get install nmap`
    *   **Linux (Fedora/CentOS):** `sudo yum install nmap` or `sudo dnf install nmap`
    *   **macOS (using Homebrew):** `brew install nmap`
    *   **Windows:** Download the installer from [nmap.org](https://nmap.org/download.html) and ensure you add its directory to your system's PATH environment variable.

2.  **Python:** Python 3.7 or higher is recommended.

## Installation & Setup

1.  **Clone the repository (or download the `app.py` file):**
    ```bash
    git clone https://github.com/iamsjeevan/network-vulnerability-scanner.git # Replace with your actual repo URL
    cd network-vulnerability-scanner
    ```

2.  **(Recommended) Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install the required Python libraries:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Alternatively, if you don't have a `requirements.txt` yet, you can install them directly):*
    ```bash
    pip install streamlit python-nmap pandas
    ```

    *(If you create a `requirements.txt` file, it should contain:*
    ```
    streamlit
    python-nmap
    pandas
    ```
    *)*

## Usage

1.  Ensure Nmap is installed and your virtual environment (if used) is activated.
2.  Navigate to the project directory in your terminal.
3.  Run the Streamlit application:
    ```bash
    streamlit run app.py
    ```
4.  Open your web browser and go to the local URL provided by Streamlit (usually `http://localhost:8501`).
5.  Enter the target IP address or hostname.
6.  Select your desired scan options from the sidebar.
7.  Click the "Scan Target" button.
8.  View the scan results displayed on the page.

## How it Works

The application uses the `python-nmap` library to interact with the Nmap command-line tool.
1.  The Streamlit interface collects the target and scan parameters from the user.
2.  When the "Scan Target" button is clicked, the `run_nmap_scan` function is called.
3.  This function constructs and executes an Nmap command via `python-nmap`.
4.  The raw XML output from Nmap is parsed by `python-nmap` into a Python dictionary.
5.  The application then processes this dictionary to extract relevant information (host status, open ports, services, OS details, script outputs) and displays it using Streamlit components. Pandas is used to format port details into a table.

## Contributing

Contributions are welcome! If you have suggestions for improvements or find any bugs, please feel free to:
1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature` or `bugfix/YourBugfix`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/YourFeature`).
6.  Open a Pull Request.

## License

This project is open-source and available under the [MIT License](LICENSE.txt). (Optional: If you add a LICENSE.txt file). If not, you can just remove this line or state "No license provided" or similar.

## Author

*   **Jeevan S.**
*   GitHub: [@iamsjeevan](https://github.com/iamsjeevan)
*   LinkedIn: [Jeevan S.](https://www.linkedin.com/in/jeevan-s-655393331) (Replace with your LinkedIn profile URL if different)

---

**Note:** This is a basic scanner. For comprehensive and professional penetration testing or vulnerability assessment, dedicated security tools and expertise are required.
