import subprocess
import re

def run_nmap(ip_address):
    # Specify the path to the Nmap directory
    nmap_directory = r'C:\Program Files (x86)\Nmap'

    # Specify the Nmap command and its arguments
    nmap_command = [fr'{nmap_directory}\nmap', '-v', '-A', ip_address]

    try:
        # Run the command in the Nmap directory
        result = subprocess.run(nmap_command, check=True, capture_output=True, text=True)

        # Extract OS details using a regular expression
        os_details_match = re.search(r'OS details: (.+?)\n', result.stdout)
        os_details = os_details_match.group(1) if os_details_match else "OS details not found"

        # Return the extracted OS details
        return os_details

    except subprocess.CalledProcessError as e:
        # Handle any errors
        return f"Error: {e}\nCommand output: {e.output}"


def run_main_app(ip_address):
    # Run the Main app and capture the output
    # Replace the following line with the actual command to run your Main app
    main_app_command = f"py C:\\Users\\admin\\PycharmProjects\\OSfingerprint\\main.py {ip_address}"
    main_app_result = subprocess.check_output(main_app_command, shell=True, text=True)
    return main_app_result


def compare_answers(ip_address):
    # Run Nmap
    nmap_result = run_nmap(ip_address)

    # Run the Main app
    main_app_result = run_main_app(ip_address)

    # Compare the answers
    return nmap_result == main_app_result


# Example usage:
ip_address_to_scan = "127.0.0.1"
result = compare_answers(ip_address_to_scan)

print("Are the answers equal?", result)
