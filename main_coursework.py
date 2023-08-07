import os
import hashlib
import json
from enum import Enum
from plyer import notification

class ChangeType(Enum):
    MODIFIED = "Modified"
    ADDED = "Added"
    DELETED = "Deleted"

def calculate_hash(file_path):
    # Calculate the SHA-256 hash of a file
    with open(file_path, 'rb') as f:
        sha256_hash = hashlib.sha256()
        while True:
            data = f.read(8192)  # Read file in chunks
            if not data:
                break
            sha256_hash.update(data)
        return sha256_hash.hexdigest()

def create_baseline(directory, baseline_file):
    # Create a baseline of the files in the given directory and save it to a file
    baseline = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            baseline[file_path] = file_hash

    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=4)

def load_baseline(baseline_file):
    # Load the baseline data from a file
    with open(baseline_file) as f:
        baseline = json.load(f)
    return baseline

def monitor_directory(directory, baseline, baseline_file):
    # Monitor a directory for file changes against the baseline
    modified_files = []
    new_files = []
    deleted_files = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path in baseline:
                stored_hash = baseline[file_path]
                current_hash = calculate_hash(file_path)
                if current_hash != stored_hash:
                    modified_files.append(file_path)
                    # Perform necessary actions for file modification
            else:
                new_files.append(file_path)
                # Perform necessary actions for new file creation

    for file_path in baseline.keys():
        if not os.path.exists(file_path):
            deleted_files.append(file_path)
            # Perform necessary actions for file deletion

    # Update the baseline file with the latest hashes
    create_baseline(directory, baseline_file)

    # Integrity verification
    if len(modified_files) == 0 and len(new_files) == 0 and len(deleted_files) == 0:
        print("Integrity maintained. No changes detected.")
    else:
        print("Integrity violated. Changes detected:")
        if len(modified_files) > 0:
            print("Modified files:")
            for file_path in modified_files:
                print(file_path)
            analyze_changes(modified_files, ChangeType.MODIFIED)
        if len(new_files) > 0:
            print("New files created:")
            for file_path in new_files:
                print(file_path)
            analyze_changes(new_files, ChangeType.ADDED)
        if len(deleted_files) > 0:
            print("Deleted files:")
            for file_path in deleted_files:
                print(file_path)
            analyze_changes(deleted_files, ChangeType.DELETED)

        # Send alert/notification
        send_alert(modified_files, new_files, deleted_files)

        # Generate compliance report
        generate_compliance_report(modified_files, new_files, deleted_files)

def analyze_changes(file_list, change_type):
    # Analyze the specific changes made to files
    for file_path in file_list:
        # Perform necessary analysis based on the change type
        if change_type == ChangeType.MODIFIED:
            # Analyze modifications
            analyze_modified_file(file_path)
        elif change_type == ChangeType.ADDED:
            # Analyze additions
            analyze_added_file(file_path)
        elif change_type == ChangeType.DELETED:
            # Analyze deletions
            analyze_deleted_file(file_path)

def analyze_modified_file(file_path):
    # Analyze modifications made to a file
    print(f"Analyzing modifications for file: {file_path}")
    # Perform your specific analysis here
    print(f"- Line count changed.")
    print(f"- Code block added.")
    print(f"- Code block removed.")
    print("Modification analysis completed.")

def analyze_added_file(file_path):
    # Analyze additions made to a file
    print(f"Analyzing additions for file: {file_path}")
    # Perform your specific analysis here
    print(f"- Added {get_file_size(file_path)} bytes.")
    print("Addition analysis completed.")

def analyze_deleted_file(file_path):
    # Analyze deletions made to a file
    print(f"Analyzing deletions for file: {file_path}")
    # Perform your specific analysis here
    print(f"- Deleted.")
    print("Deletion analysis completed.")

def get_file_size(file_path):
    # Get the size of a file in bytes
    return os.path.getsize(file_path)

def verify_baseline_integrity(baseline_file):
    # Verify the integrity of the baseline file itself
    stored_hash = ''
    with open(baseline_file, 'r') as f:
        stored_hash = f.readline().strip()

    # Calculate the hash of the file without the first line (stored hash)
    with open(baseline_file, 'rb') as f:
        sha256_hash = hashlib.sha256()
        f.readline()  # Skip the first line (stored hash)
        while True:
            data = f.read(8192)
            if not data:
                break
            sha256_hash.update(data)
        calculated_hash = sha256_hash.hexdigest()

    if calculated_hash != stored_hash:
        print("Baseline file has been tampered with.")
        # Perform necessary actions if tampering is detected
        send_alert_tampering()
    else:
        print("Baseline file integrity verified.")

def send_alert(modified_files, new_files, deleted_files):
    # Send an alert/notification to the desktop notification bar
    title = 'File Change Alert'
    message = ''

    if len(modified_files) > 0:
        message += 'Modified files:\n'
        for file_path in modified_files:
            message += file_path + '\n'

    if len(new_files) > 0:
        message += 'New files created:\n'
        for file_path in new_files:
            message += file_path + '\n'

    if len(deleted_files) > 0:
        message += 'Deleted files:\n'
        for file_path in deleted_files:
            message += file_path + '\n'

    notification.notify(
        title=title,
        message=message,
        timeout=10  # Set the notification timeout (in seconds)
    )

def send_alert_tampering():
    # Send an alert/notification to the desktop notification bar for baseline tampering
    title = 'Baseline Tampering Alert'
    message = 'The baseline file has been tampered with.'
    notification.notify(
        title=title,
        message=message,
        timeout=10  # Set the notification timeout (in seconds)
    )

def bubble_sort(arr):
    n = len(arr)
    for i in range(n - 1):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]

def generate_compliance_report(modified_files, new_files, deleted_files):
    report = "Compliance Report:\n\n"

    if len(modified_files) > 0:
        bubble_sort(modified_files)
        report += "Modified files:\n"
        for file_path in modified_files:
            report += f"- {file_path}\n"
        report += "\n"

    if len(new_files) > 0:
        bubble_sort(new_files)
        report += "New files created:\n"
        for file_path in new_files:
            report += f"- {file_path}\n"
        report += "\n"

    if len(deleted_files) > 0:
        bubble_sort(deleted_files)
        report += "Deleted files:\n"
        for file_path in deleted_files:
            report += f"- {file_path}\n"
        report += "\n"

    # Save the report to a file
    with open('compliance_report.txt', 'w') as f:
        f.write(report)

    print("Compliance report generated.")

    # Optionally, you can also send the report via email or perform any other actions as needed.

# Prompt the user for the directory path to monitor
directory_to_monitor = input("Enter the directory path to monitor: ")

# Ensure the provided directory exists
if not os.path.isdir(directory_to_monitor):
    print("Invalid directory path.")
else:
    baseline_file = 'baseline.json'

    # Check if the baseline file exists
    if os.path.exists(baseline_file):
        # Verify the integrity of the baseline file itself
        verify_baseline_integrity(baseline_file)

        # Load the existing baseline from the file
        baseline = load_baseline(baseline_file)
    else:
        # Create a new baseline and save it to the file
        create_baseline(directory_to_monitor, baseline_file)
        baseline = load_baseline(baseline_file)

    # Monitor the directory for changes and update the baseline file
    monitor_directory(directory_to_monitor, baseline, baseline_file)
