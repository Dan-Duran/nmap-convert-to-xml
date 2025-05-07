# nmap-convert-to-xml

## Overview

This tool processes Nmap scan output files in plain text format (.log or .txt) and converts them to structured XML format that can be imported into different cybersecurity tools for vulnerability management. It extracts information like host details, port information, service details, and OS detection results from the log files and structures them according to Nmap's XML schema.

## Links

- **👉 Checkout some more awesome tools at [GetCyber](https://getcyber.me/tools)**
- **👉 Subscribe to my YouTube Channel [GetCyber - YouTube](https://youtube.com/getCyber)**
- **👉 Discord Server [GetCyber - Discord](https://discord.gg/YUf3VpDeNH)**

## Features

- Converts multiple Nmap log files (.log and .txt) to XML format in a single run
- Extracts host information, port details, and service information
- Preserves hostname and OS detection information when available
- Creates properly formatted Nmap XML files compatible with DefectDojo
- Provides detailed logging for troubleshooting
- Optional ZIP file creation for easy import into DefectDojo
- Customizable input/output directories

## Project Structure

```
nmap-convert-to-xml/
├── convert.py       # Main script for conversion
├── convert.log      # Log file with detailed operation information
├── README.md        # This documentation file
├── input/           # Directory containing Nmap log/txt files to be converted
│   ├── *.log        # Nmap log files
│   └── *.txt        # Nmap output in text format
└── output/          # Directory containing converted XML files
    └── *.xml        # Output XML files ready for DefectDojo import
```

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Installation

No installation is required. Simply clone or download this repository to your local machine.

```bash
git clone https://github.com/Dan-Duran/nmap-convert-to-xml.git
cd nmap-convert-to-xml
```

After cloning the repository, create the `input` and `output` directories if they don't exist:

```bash
mkdir -p input output
```

## Usage

Basic usage:

```bash
python3 convert.py
```

This will process all `.log` and `.txt` files from the `input` directory and save the resulting XML files to the `output` directory.

### Command Line Options

- `-i, --input-dir`: Directory containing Nmap .log or .txt files (default: input)
- `-o, --output-dir`: Directory to save XML output files (default: output)
- `--debug`: Enable debug output for more detailed logging
- `-z, --zip`: Create a zip file of the output XML files
- `--zip-filename`: Name of the zip file to create (default: nmap_output.zip)

### Examples

Process files from a custom input directory:

```bash
python3 convert.py --input-dir /path/to/nmap/logs
```

Save output to a custom directory:

```bash
python3 convert.py --output-dir /path/to/output
```

Enable debug mode for verbose output:

```bash
python3 convert.py --debug
```

Create a ZIP file of the output XMLs:

```bash
python3 convert.py --zip
```

Customize the ZIP filename:

```bash
python3 convert.py --zip --zip-filename nmap-scan-results.zip
```

## File Format

The tool expects Nmap output files in .log or .txt format generated from normal Nmap scans. The files should contain standard Nmap output including:

- Host information (IP addresses and hostnames)
- Port details (number, protocol, state)
- Service information
- OS detection results (if available)

Example commands to generate compatible log files:

```bash
nmap -sS -sV -p- 192.168.1.0/24 -oN scan_results.txt
nmap -sU -sV --top-ports 100 10.0.0.0/24 -oN udp_scan.log
```

## Output

The output XML files follow the standard Nmap XML format with elements including:

- `<nmaprun>`: Root element containing scan information
- `<host>`: Information about each host
- `<ports>`: Details about open/filtered/closed ports
- `<service>`: Service information for each port
- `<os>`: Operating system detection results (if available)

## Troubleshooting

If you encounter issues with the conversion:

1. Run the script with the `--debug` flag for more detailed output:
   ```bash
   python3 convert.py --debug
   ```

2. Check the `convert.log` file for error messages
3. Ensure your Nmap log files contain the expected output format
4. Verify that the input and output directories exist and are accessible
5. If parsing fails for specific log files, check for non-standard formatting or encoding issues

## Repository

This project is available on GitHub: [https://github.com/Dan-Duran/nmap-convert-to-xml](https://github.com/Dan-Duran/nmap-convert-to-xml)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
