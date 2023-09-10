# GUI Port Scanner Application

## Introduction
This is a Python GUI application for performing port scanning on a target host. It allows users to specify various scanning parameters, including the type of scan (Quick, Normal, or Advanced), target IP address or hostname, port range, number of threads to use, and the option to rate limit the scan. The application uses a graphical interface built with the tkinter library.

## Prerequisites
Before running the application, make sure you have the following libraries installed:
- `customtkinter`: This appears to be a custom tkinter library, so ensure you have it available in your Python environment.
- `tkinter`: The standard tkinter library is required for building the graphical user interface.
- `threading`: This library is used for managing threads.
- `socket`: It's used for socket operations to perform port scanning.
- `queue`: This library is used for managing a queue of ports to scan.

## Application Features
1. **User Interface**: The application provides a graphical user interface for ease of use.
2. **Scan Modes**:
   - **Quick Scan**: Scans a predefined list of common ports.
   - **Normal Scan**: Allows users to specify a range of ports.
   - **Advanced Scan**: Allows users to specify a range of ports and the number of threads.
3. **Rate Limiting**: Users can enable or disable rate limiting to control the scan speed.
4. **Result Display**: The application displays the results of the port scan in a text box within the GUI.
5. **Result Download**: Users can save the scan results to a text file.
6. **Clear All**: Clears the input fields, results, and resets the GUI.

## Usage Instructions

### 1. Launching the Application
Run the Python script provided to launch the application.

```bash
python multi-threaded-port-scanner.py
```

## 2. GUI Layout

Upon launching, you'll see the GUI window with the following components:

- **Enter hostname or IP address**: Enter the target hostname or IP address.

- **Scan Type**:
  - Quick Scan: Scans common ports.
  - Normal Scan: Allows you to specify a range of ports.
  - Advanced Scan: Allows you to specify ports, threads, and rate limiting.

- **Generate Results**: Starts the port scan.

- **Stop**: Stops the ongoing scan.

- **Clear All**: Clears all input fields and results.

## 3. Quick Scan

- Select "Quick Scan" radio button.
- Enter the target hostname or IP address.
- Click "Generate Results" to start the scan.

## 4. Normal Scan

- Select "Normal Scan" radio button.
- Enter the target hostname or IP address.
- Enter the starting and ending ports.
- Click "Generate Results" to start the scan.

## 5. Advanced Scan

- Select "Advanced Scan" radio button.
- Enter the target hostname or IP address.
- Enter the starting and ending ports.
- Enter the number of threads to use (optional).
- Enable or disable rate limiting (optional).
- Click "Generate Results" to start the scan.

## 6. During Scanning

- While scanning is in progress, the "Generate Results" button will display a progress animation.
- You can stop the scan using the "Stop" button.

## 7. Viewing Results

- The scan results will be displayed in a text box within the GUI.
- You can download the results as a text file using the "Download as text file" button.

## 8. Clearing Results

- Click "Clear All" to clear input fields and results.

## 9. Exiting the Application

- Close the application window to exit.

## Notes

- The application uses a custom tkinter library (`customtkinter`), so ensure it's available in your environment.

- Rate limiting allows you to control the speed of the scan. By default, it's set to 50 scans per second.

- The application uses threading to improve scan performance. The number of threads can be customized in "Advanced Scan."

- The application provides informative messages about the scan progress and results.

- The "Quick Scan" uses a predefined list of common ports. You can customize this list in the `common_ports` variable.

- Ensure you have appropriate permissions to perform port scanning on the target host.

- The application can handle both IPv4 and IPv6 addresses.
