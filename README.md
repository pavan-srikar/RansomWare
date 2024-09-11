# Ransomware Encryption Tool

## Introduction

This project is a Python-based ransomware encryption tool designed to encrypt files and folders using AES encryption. It provides a graphical user interface (GUI) for notifying users about the encryption status and includes options to open a local HTML file and a README text file. The tool supports Linux, macOS, and Windows operating systems.

## Features

- Encrypts files and folders recursively.
- Adds a README text file in each directory with instructions.
- Displays a GUI notification with options to open an HTML file or close the notification.
- Compatible with Linux, macOS, and Windows.

## Installation

### Prerequisites

Ensure you have Python 3.6+ installed. You will also need `pip` for installing the required packages.

### Install Dependencies

#### Linux

To install the required Python packages on Linux, use the following command:

```bash
pip install -r requirements.txt
```

#### Windows

To install the required Python packages on Windows, use the following command:

```bash
pip install -r requirements.txt
```

#### macOS

To install the required Python packages on macOS, use the following command:

```bash
pip install -r requirements.txt
```

### Creating a Standalone Executable

To create a standalone executable for distribution, you can use `pyinstaller`. First, install `pyinstaller`:

#### Linux, Windows, and macOS

```bash
pip install pyinstaller
```

Then, navigate to the directory containing your script and run:

```bash
pyinstaller --onefile --noconsole your_script_name.py
```

Replace `your_script_name.py` with the name of your Python script. This will generate a standalone executable in the `dist` directory.

## Implementation

1. **Encryption**: Uses AES encryption in CFB mode with a password-derived key.
2. **File Operations**: Encrypts files and directories recursively and deletes original files after encryption.
3. **GUI**: Provides a notification using `tkinter`, with buttons to open an HTML file or close the window.
4. **Cross-Platform**: Designed to work on Linux, macOS, and Windows.

## Usage

1. Set the `PASSWORD` and `ENCRYPTION_PATH` variables in the script to your desired password and target directory.
2. Run the script to encrypt the files and folders in the specified directory.
3. After encryption, a popup will notify you, and you can choose to open an HTML file or close the window.

