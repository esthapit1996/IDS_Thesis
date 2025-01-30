# Intrusion Detection System (IDS)

This project is an Intrusion Detection System (IDS) built using Python. It was developed and tested on **Ubuntu 24.04.1 LTS**, with **Python 3.12.3**.

## Why It Doesn't Work on Windows or macOS

- **Windows**: The system relies on `syslog` for logging, which is not available on Windows. Additionally, capturing network traffic in **promiscuous mode** typically requires low-level network access that is not easily available or supported on Windows without third-party tools. As such, running the system on Windows would require substantial modifications to both the logging and packet capture logic.

- **macOS**: While it's possible to run the system on macOS, **promiscuous mode** is more restrictive. macOS does not easily allow network interfaces to be switched to promiscuous mode due to system security restrictions. As a result, network packet capturing is difficult to achieve unless specific configurations are set, making it less practical for running this IDS out-of-the-box on macOS.

For these reasons, the system is optimized and tested specifically for Ubuntu and Linux-based environments.

## Introduction

This IDS is designed to detect and alert on potential security threats within a network or computer system. It is built using Python scripts and was developed in an Ubuntu environment. The system monitors real-time network traffic in promiscuous mode, identifies anomalies based on a whitelist of IP addresses and ports, and sends alerts to the user about potential attacks.

The IDS uses anomaly detection techniques where traffic not matching the whitelisted IP addresses and ports is flagged as suspicious. The alert system sends messages to the user via `mail-CLI`, but the alert mechanism can be easily modified by adjusting the script to integrate with different alert systems.

Additionally, the system creates a file containing detected anomalies, which can later be reviewed and used to either add the offending IP addresses and ports to a whitelist or blacklist, helping improve the accuracy of detection over time.

All the important events are also logged using the `syslog` Module.

## Folder Structure

Here is the directory structure for the IDS system, showing where each file should be placed:

/IDS  
│  
├── Scripts/                    
│   ├── .env                   
│   ├── capture_packets.pcap    
│   ├── requirements.txt       
│   ├── packet_handler.py       
│   ├── trigger.py    
│   ├── alert_system.py       
│   ├── whitelist_manager.py  
│   ├── dist (stand alone apps here)  
|  └── build

├── filtered_files/             
│   ├── blacklist.txt           
│   ├── whitelist.txt  
│   ├── unsorted.txt  
│

└── tests/            
|   ├── test_whitelist_manager.py  
|  └── test_trigger.py

## Features

- **Real-time Network Traffic Monitoring**: Monitors network traffic in promiscuous mode to capture all packets passing through the network interface.
- **Anomaly Detection**: Detects deviations from normal network traffic patterns by comparing incoming traffic against a whitelist of allowed IP addresses and ports.
- **Alert System**: Sends messages about detected attacks via mail-CLI to the user. This can be customized by modifying the alert script to integrate with other alert mechanisms.
- **Whitelist-Based Detection**: Uses a whitelist consisting of trusted IP addresses and port information to identify potentially malicious traffic.
- **Anomaly Log File**: Creates a file to log detected anomalies, which can later be used to review and manage suspicious IPs and ports, adding them to a whitelist or blacklist for improved future detection.
- **Event Logging with syslog**: Important events, such as detected anomalies, alerts, and system status updates, are logged using **syslog**. This provides a centralized logging mechanism for easier tracking and debugging of system activities.
- **Built on Python**: The system is implemented using Python scripts, making it easy to extend and modify.
- **Developed for Ubuntu**: The IDS was developed on an Ubuntu machine, ensuring compatibility with Linux-based environments.

This system is an open-source solution aimed at enhancing network security by providing real-time detection, alerts, and the ability to refine detection mechanisms over time through manual management of whitelists and blacklists.

## How to Use

To use the IDS, follow these steps:

### 1. Set Up the Environment

Before running the IDS, you'll need to create a `.env` file to configure the necessary parameters. Create a file named `.env` in the project directory `Scripts` with the following content:

- **INTERFACE**: Specify the network interface you want to monitor. For example, `eth0` (for wired network) or `wlan0` (for wireless network).
- **CAPTURE_FILE**: Set the file name where the captured network packets will be stored. For example, `captured_packets.pcap` (this file will store all captured network traffic).
- **OUTPUT_FOLDER**: Define the directory where filtered and processed files will be saved. For example, `../filtered_files` (relative path to the folder where the output will go).
- **WHITELIST**: Specify the path to your whitelist file, which contains trusted IP addresses and ports. For example, `whitelist.txt` (this file will contain trusted IPs and ports that are considered safe).
- **BLACKLIST**: Specify the path to your blacklist file, where suspicious or malicious IP addresses and ports will be saved. For example, `blacklist.txt` (this file will contain detected malicious IPs and ports).
- **UNSORTED_FILE**: Define the file that will contain detected anomalies for further review. For example, `unsorted.txt` (this file will store the detected anomalies that haven't been classified yet).
- **RECIPIENT**: Enter the email address of the recipient who will receive alerts. For example, `admin@example.com` (this is where the alert notifications will be sent).

### 2. Install Dependencies

Before running the IDS, you'll need to install the necessary Python modules. These modules are listed in the `requirements.txt` file located in the `/Scripts` folder.

To install the required modules, run the following command:

```bash
pip install -r Scripts/requirements.txt
```

### 3. Navigate to the Scripts Directory
Once you've set up the .env file and installed the necessary dependencies, navigate to the Scripts directory where the main Python scripts are located.
In this directory, you will find four main Python scripts:

    packet_handler.py
    trigger.py
    alert_system.py
    whitelist_manager.py

Make sure all these scripts are executable.
```bash
sudo chmod +x <script.py>
```

#### 4. Using packet_handler.py

The packet_handler.py script is responsible for capturing network packets in promiscuous mode and saving them to a .pcap file. This script requires sudo privileges to change the network device into promiscuous mode, allowing it to capture all packets, even those not addressed to the local machine.
You can specify a timeout for packet capture. For example, to capture packets for 24 hours, you can modify the script to set the capture duration. 
```bash
sudo ./packet_handler.py --timeout 86400
```

### 5. Using `whitelist_manager.py` in Creation Mode

The `whitelist_manager.py` script is used to manage and sort IP addresses and ports for the whitelist. It has two main modes of operation: **Creation Mode** and **Sorting Mode**.

#### Creation Mode

In **Creation Mode**, the script generates a new whitelist file by capturing network traffic and identifying trusted IP addresses and ports. This mode helps you create an initial whitelist that contains all known safe IPs and ports from the traffic you are monitoring.

##### Running in Creation Mode

To run the `whitelist_manager.py` in **Creation Mode**, use the following command:

```bash
sudo ./whitelist_manager.py 1
```

After the whitelist has been generated, the script will prompt you to delete the captured .pcap file. This is recommended because .pcap files can grow large and consume significant disk space.

### 6. Using `trigger.py`

The `trigger.py` script is the heart of the IDS system. It continuously monitors network traffic and triggers alerts when anomalies are detected. It also saves all the detected anomalies into an unsorted file, which can later be reviewed and categorized using the **Sorting Mode** of `whitelist_manager.py`.

#### How `trigger.py` Works

The `trigger.py` script operates by:

- **Monitoring Network Traffic**: It continuously monitors network traffic using the network interface specified in the `.env` file.
- **Detecting Anomalies**: It compares incoming packets against the entries in the whitelist (defined in `whitelist.txt`). If a packet does not match any trusted IP or port, it is flagged as an anomaly.
- **Sending Alerts**: When an anomaly is detected, the script sends an alert using the `alert_system.py` script, notifying the configured recipient (as defined in the `.env` file).
- **Saving Anomalies**: All detected anomalies are saved into an unsorted file (`unsorted.txt`), which can later be reviewed and classified using **Sorting Mode** in `whitelist_manager.py`.

#### Running `trigger.py`

To start the IDS system and begin monitoring traffic, run the `trigger.py` script with the following command:

```bash
sudo ./trigger.py
```

### 8. Sorting Mode with `whitelist_manager.py`

Once anomalies have been detected by the IDS system and saved to the `UNSORTED_FILE` (by default, `unsorted.txt`), you can use **Sorting Mode** in `whitelist_manager.py` to review and categorize them. This step is crucial for refining your whitelist and blacklist, ensuring that only trusted traffic is allowed, while suspicious traffic is flagged as malicious.

#### Running Sorting Mode

To run **Sorting Mode**, use the following command:

```bash
sudo ./whitelist_manager.py 2
```

**Note:** The permissions for the `whitelist.txt` and `blacklist.txt` files should be/ are set to `600` to ensure that only the owner has read and write access.

###### 6. Running Unit Tests

To run the unit tests for the system, navigate to the `tests` folder and execute the relevant test script.

### Running a Specific Test

Navigate into the `tests` folder and run a specific test script using the following command:
```bash
./test_trigger.py
```
To get more detailed output (including individual test results), you can run the test scripts with the -v flag:
```bash
./test_trigger.py -v
```

Make sure these are executable was well.

### Standalone App

The trigger.py script has been compiled into `trigger` using `pyinstaller` in a `venv`, a standalone executable. It includes all required dependencies and can be run directly inside the `Scripts` folder using:

sudo ./dist/trigger

This allows the script to function without requiring Python or additional installations.
It still required `sudo` and does not work just by clicking yet.
