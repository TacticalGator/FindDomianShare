#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Description:
#   Enhanced script to find all shares across a domain by querying the domain controller
#   for all computers and then attempting to list shares on each one.
#   Features parallel processing, modular design, and multiple output formats.
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import sys
import argparse
import logging
import re
import os
import tempfile
import random
import string
import json
import csv
import concurrent.futures
import shutil
import time
from datetime import datetime
from tqdm import tqdm

from impacket import version
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, wkst, srvs
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from getpass import getpass


# Create a custom logger class to filter messages based on debug flag
class DebugOnlyFilter(logging.Filter):
    """Filter to only allow messages when debug is enabled."""
    
    def filter(self, record):
        # If record level is ERROR or higher, always show
        if record.levelno >= logging.ERROR:
            return True
            
        # Only show INFO messages when debug is True
        return getattr(self, 'debug_enabled', False)


class ProgressManager:
    """Class to manage progress bar and console output."""
    
    def __init__(self, total, desc="Progress", debug=False):
        self.total = total
        self.desc = desc
        self.debug = debug
        self.progress_bar = None
        self.terminal_width = shutil.get_terminal_size().columns
        
    def __enter__(self):
        # Only show progress bar if not in debug mode
#        if not self.debug:
        if self.debug:
            self.progress_bar = tqdm(
                total=self.total,
                desc=self.desc,
                position=0,
                leave=True,
                ncols=self.terminal_width,
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
            )
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.progress_bar is not None:
            self.progress_bar.close()
            
    def update(self, n=1):
        if self.progress_bar is not None:
            self.progress_bar.update(n)
            
    def set_description(self, desc):
        if self.progress_bar is not None:
            self.progress_bar.set_description(desc)
            
    def write(self, message):
        if self.progress_bar is not None:
            self.progress_bar.write(message)
        elif self.debug:
            print(message)


class LDAPConnector:
    """Class to handle LDAP connections and queries."""

    def __init__(self, username, password, domain, options):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = options.aesKey
        self.doKerberos = options.k
        self.kdcIP = options.dc_ip
        self.kdcHost = options.dc_host
        self.target = None
        self.progress_mgr = None

        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(":")

        # Create the baseDN from the domain
        domainParts = self.domain.split(".")
        self.baseDN = ""
        for i in domainParts:
            self.baseDN += "dc=%s," % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        # Use user-provided baseDN if specified
        if options.base_dn is not None:
            self.baseDN = options.base_dn

    def set_progress_manager(self, progress_mgr):
        """Set progress manager for output"""
        self.progress_mgr = progress_mgr

    def getMachineName(self, target):
        """Get machine name via SMB connection."""
        try:
            s = SMBConnection(target, target)
            s.login("", "")
        except OSError as e:
            if str(e).find("timed out") > 0:
                raise Exception(
                    "The connection timed out. Probably 445/TCP port is closed. Try to specify "
                    "corresponding NetBIOS name or FQDN as the value of the -dc-host option"
                )
            else:
                raise
        except Exception:
            if s.getServerName() == "":
                raise Exception("Error while anonymous logging into %s" % target)
        else:
            s.logoff()
        return s.getServerName()

    def connect(self):
        """Connect to LDAP server with fallback between LDAPS and LDAP."""
        if self.kdcHost is not None:
            self.target = self.kdcHost
        else:
            if self.kdcIP is not None:
                self.target = self.kdcIP
            else:
                self.target = self.domain

            if self.doKerberos:
                logging.debug("Getting machine hostname")
                self.target = self.getMachineName(self.target)

        logging.info(f"Connecting to LDAP at {self.target}")

        # Try LDAPS first (636), then fall back to LDAP (389)
        for protocol in ["ldaps", "ldap"]:
            try:
                logging.debug(f"Attempting {protocol.upper()} connection")
                ldapConnection = ldap.LDAPConnection(
                    f"{protocol}://{self.target}", self.baseDN, self.kdcIP
                )
                
                if not self.doKerberos:
                    ldapConnection.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
                else:
                    ldapConnection.kerberosLogin(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        self.aesKey,
                        kdcHost=self.kdcIP,
                    )
                    
                logging.info(f"{protocol.upper()} connection successful")
                return ldapConnection
            except ldap.LDAPSessionError as e:
                if protocol == "ldap" and str(e).find("strongerAuthRequired") >= 0:
                    logging.info("Server requires SSL/TLS, retrying LDAPS connection with detailed error handling")
                    # We already tried LDAPS, so this is a real error
                    raise
                else:
                    logging.debug(f"{protocol.upper()} connection failed: {str(e)}")
                    
                    if str(e).find("NTLMAuthNegotiate") >= 0:
                        logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try Kerberos authentication.")
                        raise
                        
                    if protocol == "ldaps":
                        # Continue to try LDAP
                        continue
                    else:
                        # Both LDAPS and LDAP failed
                        raise
            except Exception as e:
                logging.debug(f"{protocol.upper()} connection failed: {str(e)}")
                if protocol == "ldaps":
                    # Continue to try LDAP
                    continue
                else:
                    # Both LDAPS and LDAP failed
                    raise

        raise Exception("Could not establish LDAP connection using any method.")

    def get_domain_computers(self, computer_filter=None):
        """Get all computers in the domain using LDAP with optional filtering."""
        ldapConnection = self.connect()
        computers = []

        # Building the search filter
        searchFilter = "(&(objectCategory=computer)(objectClass=computer))"

        try:
            logging.debug(f"Search Filter={searchFilter}")
            sc = ldap.SimplePagedResultsControl(size=100)

            ldapConnection.search(
                searchFilter=searchFilter,
                attributes=["sAMAccountName", "dNSHostName", "operatingSystem"],
                sizeLimit=0,
                searchControls=[sc],
                perRecordCallback=lambda item: self._process_and_append(item, computers),
            )

        except ldap.LDAPSearchError as e:
            logging.error(f"LDAP search error: {str(e)}")
        finally:
            ldapConnection.close()

        # Apply filter if specified
        if computer_filter:
            pattern = re.compile(computer_filter, re.IGNORECASE)
            filtered_computers = []
            for computer in computers:
                # Match against DNS hostname or SAM account name
                hostname = computer.get('dNSHostName', '').lower()
                samname = computer.get('sAMAccountName', '').lower()
                if pattern.search(hostname) or pattern.search(samname):
                    filtered_computers.append(computer)
            logging.info(f"Filtered to {len(filtered_computers)} computers based on pattern '{computer_filter}'")
            return filtered_computers
            
        return computers

    def _process_and_append(self, item, computers):
        """Process LDAP computer record and append to list."""
        computer = self._process_computer_record(item)
        if computer:
            computers.append(computer)

    def _process_computer_record(self, item):
        """Process LDAP computer record."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return None

        computer = {}
        try:
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "sAMAccountName":
                    computer["sAMAccountName"] = (
                        attribute["vals"][0].asOctets().decode("utf-8")
                    )
                elif str(attribute["type"]) == "dNSHostName":
                    computer["dNSHostName"] = (
                        attribute["vals"][0].asOctets().decode("utf-8")
                    )
                elif str(attribute["type"]) == "operatingSystem":
                    computer["operatingSystem"] = (
                        attribute["vals"][0].asOctets().decode("utf-8")
                    )

            return computer
        except Exception as e:
            logging.debug("Exception processing computer", exc_info=True)
            logging.error(f"Skipping item, cannot process due to error {str(e)}")
            return None


class SMBConnector:
    """Class to handle SMB connections and operations."""

    def __init__(self, username, password, domain, lmhash="", nthash="", 
                 aesKey=None, doKerberos=False, kdcIP=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcIP = kdcIP
        self.connection_timeout = 5  # Timeout in seconds
        self.progress_mgr = None

    def set_progress_manager(self, progress_mgr):
        """Set progress manager for output"""
        self.progress_mgr = progress_mgr

    def connect(self, target_host):
        """Establish SMB connection to target host."""
        try:
            smbClient = SMBConnection(target_host, target_host, timeout=self.connection_timeout)

            # Handle authentication
            if self.doKerberos:
                smbClient.kerberosLogin(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                    self.aesKey,
                    self.kdcIP,
                )
            else:
                smbClient.login(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                )

            return smbClient
        except Exception as e:
            logging.debug(f"SMB connection to {target_host} failed: {str(e)}")
            raise

    def check_admin_access(self, target_host):
        """Check if current user has admin access to the target host."""
        try:
            logging.debug(f"Checking admin access on {target_host}")
            smbClient = self.connect(target_host)

            # Try to connect to admin shares
            admin_shares = ["C$", "ADMIN$"]
            for share in admin_shares:
                try:
                    smbClient.listPath(share, "*")
                    return True
                except Exception as e:
                    logging.debug(f"Failed to access {share} on {target_host}: {str(e)}")

            return False

        except Exception as e:
            logging.debug(f"Error checking admin access on {target_host}: {str(e)}")
            return False

    def check_share_access(self, smbClient, share_name, skip_write_test=False):
        """Check if we have read and write access to a share."""
        access_info = {"read": False, "write": False}

        # Check read access
        try:
            smbClient.listPath(share_name, "*")
            access_info["read"] = True

            # If read succeeded and write test is not skipped, try write access
            if access_info["read"] and not skip_write_test:
                try:
                    # Generate a random filename
                    temp_filename = (
                        "".join(random.choice(string.ascii_letters) for i in range(8))
                        + ".txt"
                    )
                    temp_file_content = b"DeleteMe"

                    # Create temp file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(temp_file_content)
                        temp_file_path = temp_file.name

                    # Upload test file
                    with open(temp_file_path, "rb") as file_obj:
                        smbClient.putFile(share_name, temp_filename, file_obj.read)

                    # If we made it here, we have write access
                    access_info["write"] = True

                    # Clean up by deleting the file
                    smbClient.deleteFile(share_name, temp_filename)

                except Exception as e:
                    logging.debug(f"Write access check failed: {str(e)}")
                finally:
                    # Clean up local temp file
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)

        except Exception as e:
            logging.debug(f"Read access check failed: {str(e)}")

        return access_info

    def get_shares(self, target_host, check_access=False, check_admin=False, skip_default_shares=False):
        """Get shares from a computer using SMB."""
        try:
            if not target_host:
                return []

            logging.debug(f"Attempting to find shares on {target_host}")

            # Check admin access if requested
            is_admin = False
            if check_admin:
                is_admin = self.check_admin_access(target_host)
                if is_admin:
                    logging.info(f"Admin access confirmed on {target_host}")
                else:
                    logging.debug(f"No admin access on {target_host}")

            # Prepare SMB connection
            smbClient = self.connect(target_host)

            # Get shares using SRVSVC named pipe
            shares = []
            rpctransport = transport.SMBTransport(
                smbClient.getRemoteHost(),
                smbClient.getRemoteHost(),
                filename=r"\srvsvc",
                smb_connection=smbClient,
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrShareEnum(dce, 1)

            for share in resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]:
                share_name = share["shi1_netname"][:-1]  # Remove null terminator
                
                # Skip default shares if requested
                if skip_default_shares and share_name in ["ADMIN$", "C$", "IPC$", "PRINT$"]:
                    continue
                    
                share_info = {
                    "ComputerName": target_host,
                    "Name": share_name,
                    "Remark": share["shi1_remark"][:-1] if share["shi1_remark"] else "",
                    "Type": share["shi1_type"],
                    "IsAdmin": is_admin,
                    "TypeName": self._get_share_type_name(share["shi1_type"]),
                }

                # Check if we can access the share
                if check_access:
                    # Skip write test for IPC$ share
                    skip_write = share_name == "IPC$"
                    access_info = self.check_share_access(smbClient, share_name, skip_write)
                    share_info["ReadAccess"] = access_info["read"]
                    share_info["WriteAccess"] = access_info["write"]

                shares.append(share_info)

            return shares

        except Exception as e:
            logging.debug(f"Error getting shares from {target_host}: {str(e)}")
            return []

    def _get_share_type_name(self, share_type):
        """Convert numeric share type to descriptive name."""
        base_type = share_type & 0x0000FFFF
        type_name = ""
        
        if base_type & 0x1:
            type_name = "Disk"
        elif base_type & 0x2:
            type_name = "Print"
        elif base_type & 0x3:
            type_name = "Device"
        elif base_type & 0x4:
            type_name = "IPC"
        else:
            type_name = "Unknown"

        if share_type & 0x80000000:
            type_name += " (Hidden)"
            
        return type_name


class ShareFinder:
    """Main class to coordinate finding shares across a domain."""

    def __init__(self, username, password, domain, options):
        self.options = options
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        
        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(":")
            
        self.ldap_connector = LDAPConnector(username, password, domain, options)
        self.smb_connector = SMBConnector(
            username, 
            password, 
            domain, 
            self.lmhash, 
            self.nthash, 
            options.aesKey, 
            options.k, 
            options.dc_ip
        )
        
        self.max_workers = options.threads
        self.check_access = options.check_access
        self.check_admin = options.check_admin
        self.skip_default_shares = options.skip_default
        self.retries = options.retries
        self.retry_delay = options.retry_delay
        self.debug = options.debug
        self.progress_mgr = None
        
    def set_progress_manager(self, progress_mgr):
        """Set progress manager for output"""
        self.progress_mgr = progress_mgr
        self.ldap_connector.set_progress_manager(progress_mgr)
        self.smb_connector.set_progress_manager(progress_mgr)
        
    def process_computer(self, computer):
        """Process a single computer to find shares."""
        hostname = computer.get('dNSHostName', computer.get('sAMAccountName', '')).rstrip('$')
        os_info = computer.get('operatingSystem', 'Unknown')
        
        if not hostname:
            logging.warning("Skipping computer with no hostname")
            return []
            
        for attempt in range(self.retries + 1):
            try:
                shares = self.smb_connector.get_shares(
                    hostname, 
                    self.check_access, 
                    self.check_admin,
                    self.skip_default_shares
                )
                
                if shares:
                    logging.info(f"Found {len(shares)} shares on {hostname}")
                    # Add OS info to each share
                    for share in shares:
                        share['OperatingSystem'] = os_info
                    return shares
                else:
                    logging.info(f"No accessible shares found on {hostname}")
                    return []
                    
            except Exception as e:
                if attempt < self.retries:
                    logging.warning(f"Error accessing {hostname} (attempt {attempt+1}/{self.retries+1}): {str(e)}")
                    time.sleep(self.retry_delay)
                else:
                    logging.error(f"Failed to access {hostname} after {self.retries+1} attempts: {str(e)}")
                    return []
        
        return []  # Should never reach here, but just in case
    
    def find_domain_shares(self):
        """Find shares across all domain computers with parallel processing."""
        all_shares = []
        
        # Get domain computers
        computers = self.ldap_connector.get_domain_computers(self.options.computer_name)
        if self.progress_mgr:
            self.progress_mgr.write(f"Found {len(computers)} computers in the domain")
        else:
            logging.info(f"Found {len(computers)} computers in the domain")
        
        if not computers:
            logging.warning("No computers found to scan")
            return []
            
        # Create a progress manager if not already set
        if not self.progress_mgr:
            with ProgressManager(len(computers), "Processing computers", self.debug) as progress:
                self.set_progress_manager(progress)
                return self._process_computers_parallel(computers, progress)
        else:
            return self._process_computers_parallel(computers, self.progress_mgr)
            
    def _process_computers_parallel(self, computers, progress):
        """Process computers in parallel with progress tracking."""
        all_shares = []
        
        # Use multithreading to process computers in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all computer processing tasks
            future_to_computer = {
                executor.submit(self.process_computer, computer): computer 
                for computer in computers
            }
            
            completed = 0
            total = len(computers)
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_computer):
                computer = future_to_computer[future]
                hostname = computer.get('dNSHostName', computer.get('sAMAccountName', '')).rstrip('$')
                
                try:
                    shares = future.result()
                    if shares:
                        all_shares.extend(shares)
                except Exception as e:
                    logging.error(f"Error processing {hostname}: {str(e)}")
                
                completed += 1
                progress.update(1)
                
                # Update progress description periodically
                if completed % 10 == 0 or completed == total:
                    progress.set_description(f"Processing computers [{completed}/{total}]")
        
        return all_shares


class OutputFormatter:
    """Class to handle different output formats."""
    
    @staticmethod
    def print_console(shares, check_access=False, check_admin=False):
        """Print shares in a formatted way to console with dynamic column widths."""
        if not shares:
            print("No shares found.")
            return

        # Get terminal width
        terminal_width = shutil.get_terminal_size().columns
        
        # Calculate dynamic column widths based on data and terminal size
        computer_max = max(len(share['ComputerName']) for share in shares) if shares else 15
        computer_max = min(computer_max, 30)  # Cap at 30 chars
        
        share_max = max(len(share['Name']) for share in shares) if shares else 10
        share_max = min(share_max, 15)  # Cap at 15 chars
        
        # Increased TypeName cap to 20 to accommodate longer entries
        typename_max = max(len(share['TypeName']) for share in shares) if shares else 10
        typename_max = min(typename_max, 20)  # Cap at 20 chars
        
        # Calculate OS max based on full string length and cap at 20
        os_max = max(len(str(share.get('OperatingSystem', 'Unknown'))) for share in shares) if shares else 15
        os_max = min(os_max, 20)  # Cap at 20 chars
        
        # Calculate how much space is left for remarks
        used_width = computer_max + share_max + typename_max + os_max + 9  # 9 for spacing
        if check_admin:
            used_width += 8
        if check_access:
            used_width += 12
        
        remark_max = terminal_width - used_width - 5
        remark_max = max(10, min(remark_max, 40))  # Between 10 and 40 chars
        
        print(f"\nFound {len(shares)} shares:")
        print("-" * min(terminal_width, 100))

        # Prepare header
        header = f"{'Computer':<{computer_max}} {'Share':<{share_max}} {'Type':<{typename_max}}"

        if check_admin:
            header += f" {'Admin':<6}"

        if check_access:
            header += f" {'Read':<5} {'Write':<5}"

        header += f" {'OS':<{os_max}} {'Remark':<{remark_max}}"

        print(header)
        print("-" * min(terminal_width, 100))

        for share in shares:
            # Truncate values if needed based on new column widths
            comp_name = share['ComputerName'][:computer_max]
            share_name = share['Name'][:share_max]
            type_name = share['TypeName'][:typename_max]
            os_info = str(share.get('OperatingSystem', 'Unknown'))[:os_max]  # Truncate to os_max if necessary
            remark = share['Remark'][:remark_max]
            
            line = f"{comp_name:<{computer_max}} {share_name:<{share_max}} {type_name:<{typename_max}}"

            if check_admin:
                admin_status = "Yes" if share.get("IsAdmin", False) else "No"
                line += f" {admin_status:<6}"

            if check_access:
                read_status = "Yes" if share.get("ReadAccess", False) else "No"
                write_status = "Yes" if share.get("WriteAccess", False) else "No"
                line += f" {read_status:<5} {write_status:<5}"

            line += f" {os_info:<{os_max}} {remark:<{remark_max}}"

            print(line)
    
    @staticmethod
    def export_json(shares, filename):
        """Export shares to JSON file."""
        with open(filename, 'w') as f:
            json.dump(shares, f, indent=4)
        print(f"Results exported to JSON file: {filename}")
    
    @staticmethod
    def export_csv(shares, filename, check_access=False, check_admin=False):
        """Export shares to CSV file."""
        fieldnames = ['ComputerName', 'Name', 'TypeName', 'Remark', 'OperatingSystem']
        
        if check_admin:
            fieldnames.append('IsAdmin')
            
        if check_access:
            fieldnames.extend(['ReadAccess', 'WriteAccess'])
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write only the fields we defined
            for share in shares:
                row = {field: share.get(field, '') for field in fieldnames}
                writer.writerow(row)
                
        print(f"Results exported to CSV file: {filename}")

# Main function to tie everything together
def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True, description="Find shares across a domain using Impacket"
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "-computer-name", action="store", help="Regex to filter computer names"
    )
    parser.add_argument(
        "-check-access",
        action="store_true",
        help="Check if we have read and write access to the shares",
    )
    parser.add_argument(
        "-check-admin",
        action="store_true",
        help="Check if current user is a local admin on the remote host",
    )
    parser.add_argument(
        "-skip-default",
        action="store_true",
        help="Skip default shares (ADMIN$, C$, IPC$, PRINT$)",
    )
    parser.add_argument(
        "-threads",
        type=int,
        default=10,
        help="Number of threads for parallel processing (default: 10)",
    )
    parser.add_argument(
        "-retries",
        type=int,
        default=1,
        help="Number of connection retries (default: 1)",
    )
    parser.add_argument(
        "-retry-delay",
        type=int,
        default=2,
        help="Delay between retries in seconds (default: 2)",
    )
    parser.add_argument(
        "-output",
        choices=["console", "json", "csv", "all"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "-output-file",
        action="store",
        help="Base output filename (without extension)",
    )
    parser.add_argument(
        "-ts", action="store_true", help="Adds timestamp to every logging output"
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument(
        "-base-dn",
        action="store",
        help="Base DN for LDAP search (e.g., DC=example,DC=com)",
    )

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="(RECOMMENDED) Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the "
        "ones specified in the command line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication " "(128 or 256 bits)",
    )

    group = parser.add_argument_group("connection")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )
    group.add_argument(
        "-dc-host",
        action="store",
        metavar="hostname",
        help="Hostname of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if domain == "":
        logging.critical("Domain should be specified!")
        sys.exit(1)

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is False
        and options.aesKey is None
    ):
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    # Fix potential missing import
    if options.retry_delay > 0:
        import time

    # Setup output filename if not provided
    if options.output != "console" and options.output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        options.output_file = f"domain_shares_{timestamp}"

    try:
        # Create share finder and find shares
        finder = ShareFinder(username, password, domain, options)
        start_time = datetime.now()
        logging.info(f"Starting domain share enumeration at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        shares = finder.find_domain_shares()
        
        end_time = datetime.now()
        duration = end_time - start_time
        logging.info(f"Enumeration completed in {duration}. Found {len(shares)} shares.")
        
        # Output results
        if options.output in ["console", "all"]:
            OutputFormatter.print_console(shares, options.check_access, options.check_admin)
            
        if options.output in ["json", "all"]:
            OutputFormatter.export_json(shares, f"{options.output_file}.json")
            
        if options.output in ["csv", "all"]:
            OutputFormatter.export_csv(shares, f"{options.output_file}.csv", 
                                       options.check_access, options.check_admin)
            
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
