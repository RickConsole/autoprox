#!/usr/bin/env python3

import cmd
import subprocess
import os
import time
import re
import threading
import sys
import select
import termios
import tty

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Proxmark3Shell(cmd.Cmd):
    intro = f"{Colors.OKGREEN}Welcome to AutoProx! Type help or ? to list commands.{Colors.ENDC}\n"
    prompt = f"{Colors.OKBLUE}(pm3){Colors.ENDC} "

    def __init__(self):
        super().__init__()
        self.pm3_client = "/usr/local/bin/proxmark3"
        self.pm3_reader_dev_file = "/dev/ttyACM0"

    def do_exit(self, arg):
        "Exit the shell."
        print(f"{Colors.OKGREEN}Exiting. Goodbye!{Colors.ENDC}")
        return True

    def do_EOF(self, line):
        "Exit the shell."
        print(f"{Colors.OKGREEN}\nExiting. Goodbye!{Colors.ENDC}")
        return True

    def do_hf(self, arg):
        "Enter the High Frequency (HF) Commands submenu."
        hf_menu = HFCommands(self.pm3_client, self.pm3_reader_dev_file)
        hf_menu.cmdloop()
        print(f"{Colors.OKGREEN}Returning to main menu.{Colors.ENDC}")

    def do_lf(self, arg):
        "Enter the Low Frequency (LF) Commands submenu."
        lf_menu = LFCommands(self.pm3_client, self.pm3_reader_dev_file)
        lf_menu.cmdloop()
        print(f"{Colors.OKGREEN}Returning to main menu.{Colors.ENDC}")

    def do_util(self, arg):
        "Enter the Utility Commands submenu."
        util_menu = UtilityCommands(self.pm3_client, self.pm3_reader_dev_file)
        util_menu.cmdloop()
        print(f"{Colors.OKGREEN}Returning to main menu.{Colors.ENDC}")

    def do_help(self, arg):
        "List available commands."
        print(f"{Colors.BOLD}Available commands:{Colors.ENDC}\n")
        print(f"  {Colors.OKCYAN}hf{Colors.ENDC}       Enter High Frequency (HF) Commands submenu")
        print(f"  {Colors.OKCYAN}lf{Colors.ENDC}       Enter Low Frequency (LF) Commands submenu")
        print(f"  {Colors.OKCYAN}util{Colors.ENDC}     Enter Utility Commands submenu")
        print(f"  {Colors.OKCYAN}exit{Colors.ENDC}     Exit the shell\n")
        print("Type help or ? within a submenu to list its commands.")

class HFCommands(cmd.Cmd):
    intro = f"{Colors.OKGREEN}High Frequency (HF) Commands. Type help or ? to list commands.{Colors.ENDC}\n"
    prompt = f"{Colors.OKBLUE}(pm3 hf){Colors.ENDC} "

    def __init__(self, pm3_client, pm3_reader_dev_file):
        super().__init__()
        self.pm3_client = pm3_client
        self.pm3_reader_dev_file = pm3_reader_dev_file

    def do_scan(self, arg):
        "Start continuous scanning for HF cards. Press Ctrl+C or 'q' to stop scanning."
        print(f"{Colors.OKGREEN}Starting HF continuous scanning. Press Ctrl+C or 'q' to stop scanning.{Colors.ENDC}")

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            pm3_cmd = "hf 14a reader"
            while True:
                dr, dw, de = select.select([sys.stdin], [], [], 0)
                if dr:
                    c = sys.stdin.read(1)
                    if c == 'q':
                        print(f"{Colors.OKGREEN}Scanning stopped.{Colors.ENDC}")
                        break

                pm3_proc = subprocess.Popen(
                    [self.pm3_client, self.pm3_reader_dev_file, "-c", pm3_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                output, errors = pm3_proc.communicate()
                output = output.decode('ascii', errors='ignore')
                errors = errors.decode('ascii', errors='ignore')

                output = output.strip()

                if not output or "No known/supported" in output or "No tags found" in output or "" in output:
                    print(f"{Colors.WARNING}No card detected.{Colors.ENDC}")
                else:
                    uid, sak, atqa = self.parse_card_info(output)
                    if uid:
                        print(f"{Colors.OKGREEN}Connected to card:{Colors.ENDC}")
                        print(f"  UID: {uid}")
                        print(f"  ATQA: {atqa}")
                        print(f"  SAK: {sak}")
                        self.write_to_file(
                            "scan_log.txt",
                            time.strftime("%Y-%m-%d %H:%M:%S") +
                            f" - HF Card UID: {uid}, SAK: {sak}, ATQA: {atqa}\n"
                        )
                    else:
                        print(f"{Colors.WARNING}Card detected but unable to parse information.{Colors.ENDC}")
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"\n{Colors.OKGREEN}Scanning stopped.{Colors.ENDC}")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    
    def do_clone(self, arg):
        "Clone a card based on saved information."
        saved_cards = self.read_scan_log()
        if not saved_cards:
            print(f"{Colors.WARNING}No saved card information found in scan_log.txt{Colors.ENDC}")
            return

        unique_cards = []
        seen = set()
        for card in saved_cards:
            card_tuple = (card['uid'], card['sak'], card['atqa'])
            if card_tuple not in seen:
                unique_cards.append(card)
                seen.add(card_tuple)

        while True:
            print(f"{Colors.OKGREEN}Unique saved card information:{Colors.ENDC}")
            for i, card in enumerate(unique_cards, 1):
                print(f"{i}. UID: {card['uid']}, SAK: {card['sak']}, ATQA: {card['atqa']}")

            selection = input(f"{Colors.OKCYAN}Enter the number of the card you want to clone (or '0' to cancel): {Colors.ENDC}")
            if selection == '0':
                print(f"{Colors.OKGREEN}Clone operation cancelled.{Colors.ENDC}")
                return

            try:
                selected_card = unique_cards[int(selection) - 1]
                break
            except (ValueError, IndexError):
                print(f"{Colors.FAIL}Invalid selection. Please try again.{Colors.ENDC}")

        while True:
            print(f"{Colors.OKGREEN}Select the target card type:{Colors.ENDC}")
            print("1. Standard (use csetuid)")
            print("2. Magic Gen2 (write directly to block 0)")
            print("0. Go Back")
            card_type = input(f"{Colors.OKCYAN}Enter the number of the card type (or '0' to cancel): {Colors.ENDC}")

            if card_type == '0':
                print(f"{Colors.OKGREEN}Clone operation cancelled.{Colors.ENDC}")
                return
            elif card_type in ['1', '2']:
                break
            else:
                print(f"{Colors.FAIL}Invalid card type selection. Please try again.{Colors.ENDC}")

        confirm = input(f"{Colors.WARNING}Are you sure you want to clone this card? (y/n/cancel): {Colors.ENDC}")
        if confirm.lower() != 'y':
            print(f"{Colors.OKGREEN}Clone operation cancelled.{Colors.ENDC}")
            return

        # Format UID, SAK, and ATQA correctly for the command
        uid = ' '.join([selected_card['uid'][i:i+2] for i in range(0, len(selected_card['uid']), 2)])
        sak = selected_card['sak']
        atqa = ' '.join([selected_card['atqa'][i:i+2] for i in range(0, len(selected_card['atqa']), 2)])

        if card_type == '1':
            # Standard card - use csetuid
            command = f"hf mf csetuid -w -u {uid} --atqa {atqa} --sak {sak}"
        else:
        
        # Magic Gen2 card - write directly to block 0
            try:
                uid_bytes = bytes.fromhex(selected_card['uid'])

                if len(uid_bytes) != 4:
                    print(f"{Colors.FAIL}Error: UID must be 4 bytes (8 hex characters).{Colors.ENDC}")
                    return

                # Calculate BCC
                bcc = uid_bytes[0] ^ uid_bytes[1] ^ uid_bytes[2] ^ uid_bytes[3]
                bcc_byte = bcc.to_bytes(1, 'big')

                sak_byte = bytes.fromhex(selected_card['sak'])
                atqa_bytes = bytes.fromhex(selected_card['atqa'])

                if len(sak_byte) != 1:
                    print(f"{Colors.FAIL}Error: SAK must be 1 byte (2 hex characters).{Colors.ENDC}")
                    return
                if len(atqa_bytes) != 2:
                    print(f"{Colors.FAIL}Error: ATQA must be 2 bytes (4 hex characters).{Colors.ENDC}")
                    return

                # Manufacturer Data (Bytes 8-15)
                manufacturer_data = bytes([0x00] * 8)

                # Construct the block 0 data
                block_0_bytes = uid_bytes + bcc_byte + sak_byte + atqa_bytes + manufacturer_data

                if len(block_0_bytes) != 16:
                    print(f"{Colors.FAIL}Error: Block 0 data must be 16 bytes.{Colors.ENDC}")
                    return

                # Convert to hex string without spaces
                block_0_data = block_0_bytes.hex()

                command = f"hf mf wrbl --blk 0 -d {block_0_data} --force"

            except ValueError as e:
                print(f"{Colors.FAIL}Error parsing card data: {e}{Colors.ENDC}")
                return

        print(f"{Colors.OKGREEN}Executing command: {command}{Colors.ENDC}")
        result = self.run_pm3_command(command)
        print(f"{Colors.OKGREEN}Clone result:{Colors.ENDC}")
        print(result)

    def do_read(self, arg):
        "Read HF card information."
        result = self.run_pm3_command("hf 14a reader")
        print(f"{Colors.OKGREEN}{result}{Colors.ENDC}")

    def do_back(self, arg):
        "Return to the main menu."
        return True

    def do_exit(self, arg):
        "Exit the shell."
        self.do_back(arg)
        return True

    def do_help(self, arg):
        "List available HF commands."
        print(f"{Colors.BOLD}HF Commands:{Colors.ENDC}\n")
        print(f"  {Colors.OKCYAN}scan{Colors.ENDC}     Start continuous scanning for HF cards")
        print(f"  {Colors.OKCYAN}read{Colors.ENDC}     Read HF card information")
        print(f"  {Colors.OKCYAN}clone{Colors.ENDC}    Clone a card based on saved information")
        print(f"  {Colors.OKCYAN}back{Colors.ENDC}     Return to the main menu")
        print(f"  {Colors.OKCYAN}exit{Colors.ENDC}     Exit the shell\n")
        print("Press Ctrl+C or 'q' to stop scanning when it is running.")

    def read_scan_log(self):
        try:
            with open("scan_log.txt", "r") as f:
                lines = f.readlines()
            
            cards = []
            for line in lines:
                match = re.search(r"HF Card UID: ([\w\s]+), SAK: ([\w\s]+)(?:\s+\[\d+\])?, ATQA: ([\w\s]+)", line)
                if match:
                    uid = match.group(1).replace(" ", "")
                    sak = match.group(2).split()[0]  
                    atqa = match.group(3).replace(" ", "")
                    cards.append({
                        'uid': uid,
                        'sak': sak,
                        'atqa': atqa
                    })
            return cards
        except FileNotFoundError:
            return []

    def run_pm3_command(self, command):
        """Function to run a Proxmark3 command."""
        try:
            pm3_proc = subprocess.Popen(
                [self.pm3_client, self.pm3_reader_dev_file, "-c", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, errors = pm3_proc.communicate()
            output = output.decode('ascii', errors='ignore')
            errors = errors.decode('ascii', errors='ignore')
            if pm3_proc.returncode != 0:
                return f"{Colors.FAIL}Error: {errors}{Colors.ENDC}"
            return output
        except Exception as e:
            return f"{Colors.FAIL}Error running command: {str(e)}{Colors.ENDC}"

    def parse_card_info(self, output):
        """Function to parse card information from Proxmark3 output."""
        uid = ''
        sak = ''
        atqa = ''
        lines = output.splitlines()
        for line in lines:
            uid_match = re.search(r"UID\s*:\s*(.*)", line)
            if uid_match:
                uid = uid_match.group(1).strip()
                continue
            sak_match = re.search(r"SAK\s*:\s*(.*)", line)
            if sak_match:
                sak = sak_match.group(1).strip()
                continue
            atqa_match = re.search(r"ATQA\s*:\s*(.*)", line)
            if atqa_match:
                atqa = atqa_match.group(1).strip()
                continue
        return uid, sak, atqa

    def write_to_file(self, filename, data):
        """Function to write data to a file."""
        with open(filename, 'a') as f:
            f.write(data)
        print(f"{Colors.OKGREEN}Data written to {filename}{Colors.ENDC}")

class LFCommands(cmd.Cmd):
    intro = f"{Colors.OKGREEN}Low Frequency (LF) Commands. Type help or ? to list commands.{Colors.ENDC}\n"
    prompt = f"{Colors.OKBLUE}(pm3 lf){Colors.ENDC} "

    def __init__(self, pm3_client, pm3_reader_dev_file):
        super().__init__()
        self.pm3_client = pm3_client
        self.pm3_reader_dev_file = pm3_reader_dev_file

    def do_scan(self, arg):
        "Scan for LF cards and save their information."
        print(f"{Colors.OKGREEN}Starting LF continuous scanning. Press Ctrl+C to stop scanning.{Colors.ENDC}")

        try:
            while True:
                lf_search_result = self.run_pm3_command("lf search")
                print(lf_search_result)

                if "No known 125/134 kHz tags found!" in lf_search_result or "No tags found!" in lf_search_result:
                    print(f"{Colors.WARNING}No LF card detected.{Colors.ENDC}")
                else:
                    if "Valid HID Prox ID found!" in lf_search_result:
                        print(f"{Colors.OKGREEN}HID Prox card detected.{Colors.ENDC}")
                        hid_reader_result = self.run_pm3_command("lf hid reader")
                        print(hid_reader_result)
                        lf_card_info = self.parse_hid_card_info(hid_reader_result)
                        if lf_card_info:
                            self.save_lf_card_info(lf_card_info)
                        else:
                            print(f"{Colors.WARNING}Unable to parse HID Prox card information.{Colors.ENDC}")
                    else:
                        if "Chipset detection: T55xx" in lf_search_result or "T55xx" in lf_search_result:
                            print(f"{Colors.OKGREEN}T55xx card detected.{Colors.ENDC}")
                            t55_detect_result = self.run_pm3_command("lf t55xx detect")
                            print(t55_detect_result)
                            lf_card_info = self.parse_lf_card_info(t55_detect_result)
                            if lf_card_info:
                                self.save_lf_card_info(lf_card_info)
                            else:
                                print(f"{Colors.WARNING}Unable to parse T55xx card information.{Colors.ENDC}")
                        else:
                            print(f"{Colors.WARNING}Unknown LF card type detected.{Colors.ENDC}")
                time.sleep(1)  
        except KeyboardInterrupt:
            print(f"{Colors.OKGREEN}\nScanning stopped.{Colors.ENDC}")


    def do_clone(self, arg):
        "Clone an LF card based on saved information."
        saved_cards = self.read_scan_log_lf()
        if not saved_cards:
            print(f"{Colors.WARNING}No saved LF card information found in scan_log.txt{Colors.ENDC}")
            return

        while True:
            print(f"{Colors.OKGREEN}Saved LF card information:{Colors.ENDC}")
            for i, card in enumerate(saved_cards, 1):
                if 'tag_id' in card:
                    # HID Prox card
                    print(f"{i}. HID Prox Card - TAG ID: {card.get('tag_id', 'Unknown')}, FAC: {card.get('facility_code', 'Unknown')}, CN: {card.get('card_number', 'Unknown')}")
                else:
                    # T55xx card
                    card_summary = ', '.join([f"{key}: {value}" for key, value in card.items()])
                    print(f"{i}. {card_summary}")
            selection = input(f"{Colors.OKCYAN}Enter the number of the card you want to clone (or '0' to cancel): {Colors.ENDC}")
            if selection == '0':
                print(f"{Colors.OKGREEN}Clone operation cancelled.{Colors.ENDC}")
                return

            try:
                selected_card = saved_cards[int(selection) - 1]
                break
            except (ValueError, IndexError):
                print(f"{Colors.FAIL}Invalid selection. Please try again.{Colors.ENDC}")

        confirm = input(f"{Colors.WARNING}Are you sure you want to clone this card? (y/n/cancel): {Colors.ENDC}")
        if confirm.lower() != 'y':
            print(f"{Colors.OKGREEN}Clone operation cancelled.{Colors.ENDC}")
            return

        # Detect T5577 card before cloning
        print(f"{Colors.OKGREEN}Place the T5577 card on the reader.{Colors.ENDC}")
        input(f"{Colors.OKCYAN}Press Enter when ready...{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Detecting T5577 card...{Colors.ENDC}")
        detect_result = self.run_pm3_command("lf t55xx detect")
        print(detect_result)

        command = self.build_lf_clone_command(selected_card)
        if command is None:
            return

        print(f"{Colors.OKGREEN}Executing command: {command}{Colors.ENDC}")
        result = self.run_pm3_command(command)
        print(f"{Colors.OKGREEN}Clone result:{Colors.ENDC}")
        print(result)



    def do_back(self, arg):
        "Return to the main menu."
        return True

    def do_exit(self, arg):
        "Exit the shell."
        self.do_back(arg)
        return True

    def do_help(self, arg):
        "List available LF commands."
        print(f"{Colors.BOLD}LF Commands:{Colors.ENDC}\n")
        print(f"  {Colors.OKCYAN}scan{Colors.ENDC}     Scan for LF cards and save their information")
        print(f"  {Colors.OKCYAN}clone{Colors.ENDC}    Clone an LF card based on saved information")
        print(f"  {Colors.OKCYAN}back{Colors.ENDC}     Return to the main menu")
        print(f"  {Colors.OKCYAN}exit{Colors.ENDC}     Exit the shell\n")


    def parse_lf_card_info(self, detect_output):
        """
        Parse the output of 'lf t55xx detect' to extract card parameters.
        Returns a dictionary with the parameters.
        """
        card_info = {}
        lines = detect_output.splitlines()
        for line in lines:
            line = re.sub(r'^\[.*?\]\s*', '', line)
            if not line.strip():
                continue
            match = re.match(r'(\S.*?)[\.\s]+(.*)', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                key_lower = key.lower()
                if 'chip type' in key_lower:
                    card_info['chip_type'] = value
                elif 'modulation' in key_lower:
                    card_info['modulation'] = value
                elif 'bit rate' in key_lower:
                    card_info['bit_rate'] = value
                elif 'inverted' in key_lower:
                    card_info['inverted'] = value
                elif 'psk' in key_lower:
                    card_info['psk'] = value
                elif 'raw' in key_lower or 'data' in key_lower:
                    card_info['raw_data'] = value.replace(' ', '')
                elif 'block0' in key_lower:
                    card_info['block0'] = value
                elif 'password set' in key_lower:
                    card_info['password_set'] = value
                elif 'downlink mode' in key_lower:
                    card_info['downlink_mode'] = value
                elif 'seq. terminator' in key_lower:
                    card_info['seq_terminator'] = value
            else:
                print(f"{Colors.WARNING}Unable to parse line: {line}{Colors.ENDC}")
        if card_info:
            return card_info
        else:
            return None

    def parse_hid_card_info(self, hid_reader_output):
        """
        Parse the output of 'lf hid reader' to extract HID Prox card parameters.
        Returns a dictionary with the parameters.
        """
        card_info = {}
        lines = hid_reader_output.splitlines()
        for line in lines:
            line = line.strip()
            # Example: [+] [C1k35s  ] HID Corporate 1000 35-bit std    FC: 365  CN: 288652  parity ( ok )
            if re.search(r'HID.*FC:\s*\d+\s*CN:\s*\d+', line):
                # Extract Facility Code and Card Number
                match = re.search(r'FC:\s*(\d+)\s*CN:\s*(\d+)', line)
                if match:
                    card_info['facility_code'] = match.group(1)
                    card_info['card_number'] = match.group(2)
            elif re.search(r'raw:\s*([A-Fa-f0-9]+)', line, re.IGNORECASE):
                raw_match = re.search(r'raw:\s*([A-Fa-f0-9]+)', line, re.IGNORECASE)
                if raw_match:
                    card_info['raw'] = raw_match.group(1)
            elif 'DemodBuffer:' in line:
                index = lines.index(line)
                if index + 1 < len(lines):
                    demod_line = lines[index + 1].strip()
                    # Extract Demodulated Data
                    card_info['demodulated_data'] = demod_line
        if card_info:
            return card_info
        else:
            return None



    def build_lf_clone_command(self, card_info):
        """
        Build the command to clone an LF card onto a T5577 card.
        """
        if 'tag_id' in card_info:
            # It's a HID Prox card
            raw = card_info.get('raw', '')
            if raw:
                command = f"lf hid clone --raw {raw}"
            else:
                print(f"{Colors.FAIL}Error: No raw data available for HID Prox cloning.{Colors.ENDC}")
                return None
        elif 'chip_type' in card_info and 'T55' in card_info['chip_type']:
            # It's a T55xx card
            command = self.build_t55xx_clone_command(card_info)
        else:
            print(f"{Colors.FAIL}Unsupported LF card type for cloning.{Colors.ENDC}")
            return None
        return command


        def read_scan_log_lf(self):
            """
            Read saved LF card information from the scan log.
            """
            try:
                with open('scan_log.txt', 'r') as f:
                    lines = f.readlines()
            except FileNotFoundError:
                return []

            saved_cards = []
            for line in lines:
                if 'LF Card' in line:
                    parts = line.strip().split(' - LF Card ')
                    if len(parts) == 2:
                        card_data = parts[1]
                        card_info = {}
                        items = card_data.split(', ')
                        for item in items:
                            key_value = item.split(': ', 1)
                            if len(key_value) == 2:
                                key = key_value[0].strip()
                                value = key_value[1].strip()
                                card_info[key] = value
                        if card_info:
                            saved_cards.append(card_info)
            return saved_cards


    def build_t55xx_clone_command(self, card_info):
        """
        Build the command to clone a T55xx card onto a T5577 card.
        """
        modulation = card_info.get('modulation', '').lower()
        bit_rate = card_info.get('bit_rate', '').lower()
        inverted = card_info.get('inverted', '').lower()
        psk = card_info.get('psk', '').lower()
        raw_data = card_info.get('raw_data', '')
        offset = card_info.get('offset', '')
        seq_terminator = card_info.get('seq_terminator', '').lower()

        options = ""
        if 'ask' in modulation:
            options += " -m ask"
        elif 'fs' in modulation:
            options += " -m fsync"
        elif 'psk' in modulation:
            options += " -m psk1"

        if 'yes' in inverted:
            options += " -i"
        if 'yes' in psk:
            options += " -p"

        if 'rf/32' in bit_rate.lower() or '32' in bit_rate:
            options += " -b 32"
        elif 'rf/64' in bit_rate.lower() or '64' in bit_rate:
            options += " -b 64"

        if offset:
            options += f" -o {offset}"

        if 'yes' in seq_terminator:
            options += " -t"

        if raw_data:
            options += f" -d {raw_data}"

        command = f"lf t55xx write {options} --wipe"

        return command


    
    def save_lf_card_info(self, card_info):
        """
        Save the LF card information to the scan log in a single-line format.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        card_data = ', '.join([f"{key}: {value}" for key, value in card_info.items()])
        log_entry = f"{timestamp} - LF Card {card_data}\n"

        with open('scan_log.txt', 'a') as f:
            f.write(log_entry)

        print(f"{Colors.OKGREEN}LF card information saved to scan_log.txt{Colors.ENDC}")



    def run_pm3_command(self, command):
        """Function to run a Proxmark3 command."""
        try:
            pm3_proc = subprocess.Popen(
                [self.pm3_client, self.pm3_reader_dev_file, "-c", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, errors = pm3_proc.communicate()
            output = output.decode('ascii', errors='ignore')
            errors = errors.decode('ascii', errors='ignore')
            if pm3_proc.returncode != 0:
                return f"{Colors.FAIL}Error: {errors}{Colors.ENDC}"
            return output
        except Exception as e:
            return f"{Colors.FAIL}Error running command: {str(e)}{Colors.ENDC}"

class UtilityCommands(cmd.Cmd):
    intro = f"{Colors.OKGREEN}Utility Commands. Type help or ? to list commands.{Colors.ENDC}\n"
    prompt = f"{Colors.OKBLUE}(pm3 util){Colors.ENDC} "

    def __init__(self, pm3_client, pm3_reader_dev_file):
        super().__init__()
        self.pm3_client = pm3_client
        self.pm3_reader_dev_file = pm3_reader_dev_file

    def do_run(self, arg):
        "Run a Proxmark3 command. Usage: run <command>"
        if not arg.strip():
            print(f"{Colors.WARNING}Usage: run <command>{Colors.ENDC}")
            return
        result = self.run_pm3_command(arg)
        print(f"{Colors.OKGREEN}{result}{Colors.ENDC}")
        self.write_to_file(
            "command_log.txt",
            time.strftime("%Y-%m-%d %H:%M:%S") +
            f" - Command: {arg}, Result: {result}\n"
        )

    def do_back(self, arg):
        "Return to the main menu."
        return True

    def do_exit(self, arg):
        "Exit the shell."
        self.do_back(arg)
        return True

    def do_help(self, arg):
        "List available Utility commands."
        print(f"{Colors.BOLD}Utility Commands:{Colors.ENDC}\n")
        print(f"  {Colors.OKCYAN}run{Colors.ENDC}      Run a Proxmark3 command. Usage: run <command>")
        print(f"  {Colors.OKCYAN}back{Colors.ENDC}     Return to the main menu")
        print(f"  {Colors.OKCYAN}exit{Colors.ENDC}     Exit the shell\n")

    def run_pm3_command(self, command):
        """Function to run a Proxmark3 command."""
        try:
            pm3_proc = subprocess.Popen(
                [self.pm3_client, self.pm3_reader_dev_file, "-c", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, errors = pm3_proc.communicate()
            output = output.decode('ascii', errors='ignore')
            errors = errors.decode('ascii', errors='ignore')
            if pm3_proc.returncode != 0:
                return f"{Colors.FAIL}Error: {errors}{Colors.ENDC}"
            return output
        except Exception as e:
            return f"{Colors.FAIL}Error running command: {str(e)}{Colors.ENDC}"

    def write_to_file(self, filename, data):
        """Function to write data to a file."""
        with open(filename, 'a') as f:
            f.write(data)
        print(f"{Colors.OKGREEN}Data written to {filename}{Colors.ENDC}")

if __name__ == '__main__':
    banner = rf"""{Colors.OKBLUE}
    ___         __        ____                 
   /   | __  __/ /_____  / __ \_________  _  __
  / /| |/ / / / __/ __ \/ /_/ / ___/ __ \| |/_/
 / ___ / /_/ / /_/ /_/ / ____/ /  / /_/ />  <  
/_/  |_\__,_/\__/\____/_/   /_/   \____/_/|_|  
                                               
    {Colors.ENDC}"""
    print(banner)
    Proxmark3Shell().cmdloop()
