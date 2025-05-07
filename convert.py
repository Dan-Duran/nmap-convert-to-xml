#!/usr/bin/env python3
"""
Nmap Log to XML Converter

This script converts Nmap .log or .txt files to XML format.
It reads all .log/.txt files from the input directory and outputs XML files to the output directory.
"""

import os
import re
import sys
import logging
import argparse
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
import zipfile

# Define default directories
DEFAULT_INPUT_DIR = "input"
DEFAULT_OUTPUT_DIR = "output"

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("convert.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("nmap-converter")

class NmapLogParser:
    """Parser for Nmap log files that converts them to XML format"""
    
    def __init__(self, debug: bool = False):
        """
        Initialize the parser
        
        Args:
            debug: Enable debug output
        """
        if debug:
            logger.setLevel(logging.DEBUG)
        
        self.debug = debug
        # Compiled regex patterns for better performance
        self.ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        self.port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+([^\n]+)")
        self.host_info_pattern = re.compile(r"Nmap scan report for (?:([^\(]+) )?\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?")
        self.scan_date_pattern = re.compile(r"Starting Nmap.*at\s+(.+)$")
        self.os_pattern = re.compile(r"OS details:\s*(.+)$")

    def parse_log(self, log_path: str) -> Optional[ET.Element]:
        """
        Parse an Nmap log file and return XML structure
        
        Args:
            log_path: Path to the Nmap log file
            
        Returns:
            XML Element representing the Nmap scan, or None if parsing fails
        """
        logger.info(f"Parsing log file: {log_path}")
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as file:
                content = file.read()
            
            # Extract scan date if available
            scan_date_match = self.scan_date_pattern.search(content)
            scan_date = None
            if scan_date_match:
                date_str = scan_date_match.group(1)
                logger.debug(f"Found scan date: {date_str}")
                try:
                    scan_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M %Z")
                except ValueError:
                    try:
                        # Try without timezone
                        scan_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                    except ValueError:
                        logger.warning(f"Could not parse scan date: {date_str}")
            
            if not scan_date:
                scan_date = datetime.now()
            
            scan_timestamp = int(scan_date.timestamp())
            
            # Create root XML element
            root = ET.Element("nmaprun")
            root.set("scanner", "nmap")
            root.set("start", str(scan_timestamp))
            root.set("startstr", scan_date.strftime("%Y-%m-%d %H:%M:%S"))
            root.set("version", "7.94")  # Assumed based on logs
            root.set("xmloutputversion", "1.04")
            
            # Extract filename and try to get target from it
            filename = os.path.basename(log_path)
            target_ip = None
            
            # Try to extract IP from filename
            ip_match = self.ip_pattern.search(filename)
            if ip_match:
                target_ip = ip_match.group(1)
                logger.debug(f"Extracted target IP from filename: {target_ip}")
                args = f"nmap {target_ip}"
                root.set("args", args)
            else:
                logger.warning(f"Could not extract target IP from filename: {filename}")
                root.set("args", f"nmap -oA output")
            
            # Process the log content to find hosts
            hosts_processed = set()
            for host_match in self.host_info_pattern.finditer(content):
                hostname, ip = host_match.groups()
                
                # Skip if we've already processed this host
                if ip in hosts_processed:
                    continue
                
                hosts_processed.add(ip)
                logger.debug(f"Found host: {ip} ({hostname if hostname else 'no hostname'})")
                
                # Find the section for this host
                host_section_start = host_match.start()
                next_host_match = self.host_info_pattern.search(content, host_section_start + 1)
                host_section_end = next_host_match.start() if next_host_match else len(content)
                host_section = content[host_section_start:host_section_end]
                
                # Create host element
                host_elem = self.create_host_element(ip, hostname, host_section)
                root.append(host_elem)
            
            # If we didn't find any hosts but have a target IP, create a host for it
            if not hosts_processed and target_ip:
                logger.debug(f"No hosts found in log, creating one for: {target_ip}")
                host_elem = self.create_host_element(target_ip, None, content)
                root.append(host_elem)
                
            # Add runstats
            runstats = ET.SubElement(root, "runstats")
            finished = ET.SubElement(runstats, "finished")
            finished.set("time", str(int(datetime.now().timestamp())))
            finished.set("timestr", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            hosts = ET.SubElement(runstats, "hosts")
            hosts.set("up", str(len(hosts_processed) or 1))  # At least 1
            hosts.set("down", "0")
            hosts.set("total", str(len(hosts_processed) or 1))
            
            return root
            
        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {str(e)}", exc_info=True)
            return None
    
    def create_host_element(self, ip: str, hostname: Optional[str], host_section: str) -> ET.Element:
        """
        Create an XML host element from parsed data
        
        Args:
            ip: IP address of the host
            hostname: Hostname if available
            host_section: Section of the log containing information about this host
            
        Returns:
            XML Element representing the host
        """
        host = ET.Element("host")
        
        # Add status
        status = ET.SubElement(host, "status")
        status.set("state", "up")  # Assuming host is up if it's in the scan
        status.set("reason", "syn-ack")
        
        # Add address
        addr = ET.SubElement(host, "address")
        addr.set("addr", ip)
        addr.set("addrtype", "ipv4")
        
        # Add hostname if available
        if hostname and hostname.strip():
            hostnames = ET.SubElement(host, "hostnames")
            h_name = ET.SubElement(hostnames, "hostname")
            h_name.set("name", hostname.strip())
            h_name.set("type", "PTR")
        else:
            # Empty hostnames element
            ET.SubElement(host, "hostnames")
        
        # Find OS information
        os_match = self.os_pattern.search(host_section)
        if os_match:
            os_info = os_match.group(1)
            logger.debug(f"Found OS info for {ip}: {os_info}")
            
            os_elem = ET.SubElement(host, "os")
            os_match_elem = ET.SubElement(os_elem, "osmatch")
            os_match_elem.set("name", os_info)
            os_match_elem.set("accuracy", "100")
        
        # Find ports
        ports_elem = ET.SubElement(host, "ports")
        port_count = 0
        
        for port_match in self.port_pattern.finditer(host_section):
            port_num, proto, state, service_info = port_match.groups()
            
            port_elem = ET.SubElement(ports_elem, "port")
            port_elem.set("protocol", proto)
            port_elem.set("portid", port_num)
            
            state_elem = ET.SubElement(port_elem, "state")
            state_elem.set("state", state)
            state_elem.set("reason", "syn-ack")
            
            service_elem = ET.SubElement(port_elem, "service")
            service_name = service_info.strip().split()[0]  # Get first word as service name
            service_elem.set("name", service_name)
            service_elem.set("product", service_info.strip())
            
            port_count += 1
        
        logger.debug(f"Found {port_count} ports for host {ip}")
        
        # Add times
        times = ET.SubElement(host, "times")
        times.set("srtt", "30000")  # Default values
        times.set("rttvar", "20000")
        times.set("to", "100000")
        
        return host
    
    def xml_to_string(self, root: ET.Element) -> str:
        """
        Convert XML element to a properly formatted string
        
        Args:
            root: XML Element to convert
            
        Returns:
            Formatted XML string
        """
        rough_string = ET.tostring(root, 'utf-8')
        try:
            reparsed = minidom.parseString(rough_string)
            return reparsed.toprettyxml(indent="  ")
        except Exception as e:
            logger.error(f"Error formatting XML: {str(e)}")
            # Fallback to basic string conversion
            return rough_string.decode('utf-8')

def zip_output_folder(output_dir: str, zip_filename: str = "nmap_output.zip") -> bool:
    """
    Create a zip file containing all XML files in the output directory
    
    Args:
        output_dir: Directory containing XML files to zip
        zip_filename: Name of the zip file to create
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Creating zip file from {output_dir}")
        
        # Check if output directory exists
        if not os.path.exists(output_dir):
            logger.error(f"Output directory does not exist: {output_dir}")
            return False
        
        # Get list of XML files
        xml_files = [f for f in os.listdir(output_dir) if f.endswith('.xml')]
        
        if not xml_files:
            logger.warning(f"No XML files found in {output_dir}")
            return False
        
        logger.info(f"Found {len(xml_files)} XML files to zip")
        
        # Create the zip file
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for xml_file in xml_files:
                file_path = os.path.join(output_dir, xml_file)
                logger.debug(f"Adding {xml_file} to zip")
                zipf.write(file_path, arcname=xml_file)
        
        logger.info(f"Successfully created {zip_filename} with {len(xml_files)} files")
        return True
    
    except Exception as e:
        logger.error(f"Error creating zip file: {str(e)}", exc_info=True)
        return False

def process_files(input_dir: str, output_dir: str, debug: bool = False) -> Tuple[int, int]:
    """
    Process all log/txt files in the input directory and save XML output to the output directory
    
    Args:
        input_dir: Directory containing Nmap log/txt files
        output_dir: Directory to save XML output files
        debug: Enable debug output
        
    Returns:
        Tuple of (success_count, failure_count)
    """
    parser = NmapLogParser(debug)
    
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        except Exception as e:
            logger.error(f"Failed to create output directory {output_dir}: {str(e)}")
            return 0, 0
    
    success_count = 0
    failure_count = 0
    
    # Process each log/txt file
    try:
        # Look for both .log and .txt files
        files = [f for f in os.listdir(input_dir) if f.endswith(('.log', '.txt'))]
        logger.info(f"Found {len(files)} scan files (.log and .txt) in {input_dir}")
        
        for filename in files:
            input_path = os.path.join(input_dir, filename)
            base_name = os.path.splitext(filename)[0]
            output_path = os.path.join(output_dir, f"{base_name}.xml")
            
            logger.info(f"Processing {input_path} -> {output_path}")
            
            try:
                root = parser.parse_log(input_path)
                if root is not None:
                    xml_content = parser.xml_to_string(root)
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(xml_content)
                    
                    logger.info(f"Successfully converted {input_path} to {output_path}")
                    success_count += 1
                else:
                    logger.error(f"Failed to parse {input_path}")
                    failure_count += 1
            except Exception as e:
                logger.error(f"Error processing {input_path}: {str(e)}", exc_info=True)
                failure_count += 1
    except Exception as e:
        logger.error(f"Error listing files in {input_dir}: {str(e)}", exc_info=True)
    
    return success_count, failure_count

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(
        description='Convert Nmap log/txt files to XML format for DefectDojo import'
    )
    parser.add_argument(
        '-i', '--input-dir', 
        default=DEFAULT_INPUT_DIR, 
        help=f'Directory containing Nmap .log or .txt files (default: {DEFAULT_INPUT_DIR})'
    )
    parser.add_argument(
        '-o', '--output-dir', 
        default=DEFAULT_OUTPUT_DIR, 
        help=f'Directory to save XML output files (default: {DEFAULT_OUTPUT_DIR})'
    )
    parser.add_argument(
        '--debug', 
        action='store_true', 
        help='Enable debug output'
    )
    parser.add_argument(
        '-z', '--zip',
        action='store_true',
        help='Create a zip file of the XML output files'
    )
    parser.add_argument(
        '--zip-filename',
        default='nmap_output.zip',
        help='Name of the zip file to create (default: nmap_output.zip)'
    )
    
    args = parser.parse_args()
    
    logger.info("Starting Nmap log/txt to XML conversion")
    logger.info(f"Input directory: {args.input_dir}")
    logger.info(f"Output directory: {args.output_dir}")
    logger.info(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    if args.zip:
        logger.info(f"Zip mode enabled, output will be zipped to: {args.zip_filename}")
    
    # Validate input directory
    if not os.path.exists(args.input_dir):
        logger.error(f"Input directory does not exist: {args.input_dir}")
        return 1
    
    # Process files
    success, failures = process_files(args.input_dir, args.output_dir, args.debug)
    
    logger.info(f"Conversion complete. {success} file(s) processed successfully, {failures} failed.")
    
    # Create zip file if requested
    if args.zip and success > 0:
        if zip_output_folder(args.output_dir, args.zip_filename):
            logger.info(f"ZIP file created successfully: {args.zip_filename}")
        else:
            logger.error(f"Failed to create ZIP file")
            return 1
    
    if failures > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
