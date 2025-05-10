import streamlit as st
import nmap
import socket # For basic IP validation/hostname resolution
import pandas as pd

# --- Nmap Scanning Function ---
def run_nmap_scan(target_host, arguments):
    """
    Runs an Nmap scan on the target host with specified arguments.
    Returns the Nmap scan results.
    """
    nm = nmap.PortScanner()
    try:
        st.write(f"Initiating Nmap scan on {target_host} with arguments: {arguments}...")
        # The scan method can raise PortScannerError if nmap is not found
        # or other issues occur during the scan process itself.
        nm.scan(hosts=target_host, arguments=arguments)
        return nm
    except nmap.PortScannerError as e:
        st.error(f"Nmap execution error: {e}. Ensure Nmap is installed and in your system PATH.")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred during the scan: {e}")
        return None

# --- Streamlit App ---
st.set_page_config(page_title="Network Vulnerability Scanner", layout="wide")
st.title("🕵️ Network Vulnerability Scanner Lite")
st.markdown("""
    This tool performs a network scan on the specified target to identify open ports,
    services, and potentially gather version information.
    **Disclaimer:** Only scan hosts you have explicit permission to scan.
    Unauthorized scanning can be illegal.
""")

# --- User Input ---
target_input = st.text_input("Enter Target IP Address or Hostname:", "scanme.nmap.org")

# Nmap scan options
st.sidebar.header("Scan Options")
scan_type = st.sidebar.selectbox(
    "Select Scan Type:",
    ("Quick Scan (-T4 -F)", # Fast scan, fewer ports
     "Standard Service Scan (-sV)", # Service version detection
     "Aggressive Scan (-A)", # OS detection, version detection, script scanning, and traceroute
     "TCP SYN Scan (-sS)", # Stealthy SYN scan (requires root/admin)
     "UDP Scan (-sU)", # Scan UDP ports (can be slow)
     "Comprehensive Scan (-sV -sC -O -T4)", # Version, default scripts, OS, faster
     "Custom Arguments")
)

custom_args_input = ""
if scan_type == "Custom Arguments":
    custom_args_input = st.sidebar.text_input("Enter Nmap Arguments:", "-sV -T4")
    nmap_arguments = custom_args_input
else:
    nmap_arguments = scan_type.split('(')[1][:-1] # Extract args from selection

# --- Perform Scan ---
if st.button("🚀 Scan Target"):
    if not target_input:
        st.warning("Please enter a target IP or hostname.")
    else:
        # Basic validation or resolution attempt
        try:
            # Attempt to resolve hostname to ensure it's valid before passing to nmap
            # This doesn't guarantee nmap will succeed but is a basic check.
            socket.gethostbyname(target_input)
        except socket.gaierror:
            st.error(f"Could not resolve hostname: {target_input}. Please enter a valid IP or hostname.")
        else:
            with st.spinner(f"Scanning {target_input}... This might take a while."):
                scan_results = run_nmap_scan(target_input, nmap_arguments)

            if scan_results:
                st.success(f"Scan completed for {target_input}!")

                if not scan_results.all_hosts():
                    st.warning(f"No hosts found or host {target_input} is down.")
                else:
                    for host in scan_results.all_hosts():
                        st.header(f"Host: {host} ({scan_results[host].hostname()})")
                        st.subheader(f"State: {scan_results[host].state()}")

                        # OS Detection (if available from -A or -O)
                        if 'osmatch' in scan_results[host] and scan_results[host]['osmatch']:
                            st.subheader("OS Detection:")
                            for os_match in scan_results[host]['osmatch']:
                                os_info = f"- {os_match['name']} (Accuracy: {os_match['accuracy']}%)"
                                if os_match.get('osclass'):
                                    os_classes = [oc.get('vendor', '') + " " + oc.get('osfamily', '') + " " + oc.get('osgen', '')
                                                  for oc in os_match['osclass']]
                                    os_info += f" | Classes: {', '.join(filter(None, os_classes))}"
                                st.write(os_info)

                        # Port Information
                        st.subheader("Open Ports & Services:")
                        port_data = []
                        for proto in scan_results[host].all_protocols():
                            ports = scan_results[host][proto].keys()
                            for port in sorted(ports):
                                port_info = scan_results[host][proto][port]
                                port_data.append({
                                    "Protocol": proto.upper(),
                                    "Port": port,
                                    "State": port_info.get('state', 'N/A'),
                                    "Service": port_info.get('name', 'N/A'),
                                    "Product": port_info.get('product', 'N/A'),
                                    "Version": port_info.get('version', 'N/A'),
                                    "Extra Info": port_info.get('extrainfo', 'N/A'),
                                    "CPE": port_info.get('cpe', 'N/A')
                                })

                        if port_data:
                            df_ports = pd.DataFrame(port_data)
                            # Displaying specific columns for better readability
                            st.dataframe(df_ports[["Port", "Protocol", "State", "Service", "Product", "Version", "Extra Info"]], use_container_width=True)

                            # Vulnerability information from NSE scripts (if any script like 'vuln' was run)
                            for port_entry in port_data:
                                port = port_entry["Port"]
                                proto = port_entry["Protocol"].lower()
                                if 'script' in scan_results[host][proto][port]:
                                    st.markdown(f"**Scripts output for Port {port}/{proto.upper()}:**")
                                    for script_id, script_output in scan_results[host][proto][port]['script'].items():
                                        with st.expander(f"Script: {script_id}"):
                                            st.text(script_output)
                        else:
                            st.info("No open ports found or information available for the selected scan type.")
            else:
                # Error messages are handled within run_nmap_scan or by the calling block
                pass # st.error was already called

st.sidebar.markdown("---")
st.sidebar.info("Developed by Jeevan S. (using Streamlit & python-nmap)")