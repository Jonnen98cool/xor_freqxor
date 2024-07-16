import sys
import os
import string
import json

import src.utils as utils


# Initializing global vars to None just so the IDE recognizes them for autocomplete
# Also setting type to help prevent errors (I can look here to see what type the variable is)

PRINT_BLUE: str = None
PRINT_GREEN: str = None
PRINT_UINPUT: str = None
END_COLOR: str = None

QUIET: bool = None
PRINT_NULL = None   #fp
CIPHERTEXT: [str] = None
KEY_LENGTH: int = None
UNKNOWN: str = None
INTERNAL_UNKNOWN: str = None
KNOWN_PLAINTEXT: [str] = None
#INTERNAL_KNOWN_PLAINTEXT = None
OUTPUT_FILE: str = None

KEY: [str] = None
#PRINTABLE_KEY = None
UNKNOWN_KEY_CHARS: int = None
KEY_KNOWN_LIST: [bool] = None

CPU_CORES: int = None
KEYSPACE: [str] = None
#KEYSPACE_LENGTH = None
INCLUDE_KEY: bool = None

CLEARTEXT_ALPHABET: [str] = None
EXPECTED_FREQUENCIES: dict = None


def init_globals_handle_errors(args):
    """Takes input arguments and populates globals. Also handles argument-related errors."""

    # Printing colors
    global PRINT_BLUE; PRINT_BLUE = "\033[94m"
    global PRINT_GREEN; PRINT_GREEN = "\033[92m"
    global PRINT_UINPUT; PRINT_UINPUT = '\033[95m'  # pink? "HEADER"
    global END_COLOR; END_COLOR = "\033[0m"

    # Various independent globals not requiring knowledge of other arguments
    global QUIET; QUIET = bool(args.quiet)  # sys.stderr will still print, and some necessary print statements have file=sys.__stdout__ so they also always print.
    global PRINT_NULL; PRINT_NULL = open(os.devnull, 'w'); sys.stdout = PRINT_NULL if QUIET else sys.__stdout__
    global INTERNAL_UNKNOWN; INTERNAL_UNKNOWN = chr(256)  # Used internally as a character not in KEYSPACE.
    global OUTPUT_FILE; OUTPUT_FILE = args.output_file
    # global CPU_CORES; CPU_CORES = int(args.processes)  # Currently unused
    global KEYSPACE; KEYSPACE = [chr(i) for i in range(256)]  # ascii 0-255
    global INCLUDE_KEY; INCLUDE_KEY = bool(args.include_key)  # Used to specify whether the key for a brute-forced cleartext should be stored alongside the cleartext. Setting to false saves disk space and writing time.
    global UNKNOWN; UNKNOWN = args.unknown  # Only used for user input and printing to the user
    if (len(UNKNOWN) != 1):
        print("ERROR: String specifying the unknown character from -u does NOT have a length of 1. Provide a single character, for example: -u '%'", file=sys.stderr)
        exit(1)
    if(ord(UNKNOWN) > 255):
        print(f"ERROR: String specifying the unknown character from -u has numerical value of {ord(UNKNOWN)}, only values in range 0-255, are allowed.", file=sys.stderr)
        exit(1)

    # Specify which letter frequencies to use
    try:
        f_freqs = open(args.expected_frequencies, "r")
    except(OSError):
        print(f"ERROR: could not open \"{args.expected_frequencies}\" for reading.", file=sys.stderr)
        exit(1)
    else:
        global EXPECTED_FREQUENCIES; EXPECTED_FREQUENCIES = json.load(f_freqs)
        # Some error handling here would be nice
        f_freqs.close()
        # print(f"DEBUG: EXPECTED_FREQUENCIES: {EXPECTED_FREQUENCIES}")

    # Which cleartext alphabet to use
    global CLEARTEXT_ALPHABET
    if (args.cleartext_alphabet == "printable"):
        CLEARTEXT_ALPHABET = list(string.printable)
    # elif (args.cleartext_alphabet == "human-readable"):  #Deprecated
    #     CLEARTEXT_ALPHABET = list(string.digits + string.ascii_letters + string.punctuation + ' ')
    elif (args.cleartext_alphabet == "alphanumeric"):
        CLEARTEXT_ALPHABET = list(string.digits + string.ascii_lowercase + string.ascii_uppercase)
    elif (args.cleartext_alphabet == "ctf"):
        CLEARTEXT_ALPHABET = list(string.digits + string.ascii_lowercase + string.ascii_uppercase + "_-?!{}")  # What other chars should be here?
    elif (args.cleartext_alphabet == "uppercase"):
        CLEARTEXT_ALPHABET = list(string.ascii_uppercase)
    elif (args.cleartext_alphabet == "lowercase"):
        CLEARTEXT_ALPHABET = list(string.ascii_lowercase)
    elif (args.cleartext_alphabet == "printable_extended"):
        CLEARTEXT_ALPHABET = list(string.printable)  # WARNING: this includes 5 chars which isprintable() considers False.
        for i in range(128, 256):
            if chr(i).isprintable(): CLEARTEXT_ALPHABET.append(chr(i))
    elif (args.cleartext_alphabet == "unprintable"):
        CLEARTEXT_ALPHABET = [chr(c) for c in range(256)]
    else:
        CLEARTEXT_ALPHABET = list(args.cleartext_alphabet)  # Custom alphabet

    # If running with the --add option, append added characters to CLEARTEXT_ALPHABET
    if (args.add != None):
        for i in range(len(args.add)):
            CLEARTEXT_ALPHABET.append(args.add[i])

    # These two error checks handle both arguments -a and --add
    for c in CLEARTEXT_ALPHABET:
        if(ord(c) > 255):
            print(f"ERROR: A character in the cleartext alphabet was outside of ascii 0-255. The program can't handle this.", file=sys.stderr)
            exit(1)
    if(len(CLEARTEXT_ALPHABET) > len(set(CLEARTEXT_ALPHABET))):
        print(f"WARNING: Plaintext alphabet characters used in either -a or --add options resulted in duplicates. Purging them.", file=sys.__stdout__)
        CLEARTEXT_ALPHABET = set(CLEARTEXT_ALPHABET)


    # Fill CIPHERTEXT, which contains the ascii represented ciphertext (i.e. not in hex)
    global CIPHERTEXT; read_ciphertext = None
    if (args.ciphertext_hex == None and args.ciphertext_hex_file == None):
        print(f"ERROR: A ciphertext from option -c or -C was not supplied. You can't decrypt a ciphertext if you don't have one!", file=sys.stderr)
        exit(1)
    elif(args.ciphertext_hex != None and args.ciphertext_hex_file != None):
        print(f"ERROR: You have used both options -c and -C. Use only one!", file=sys.stderr)
        exit(1)
    elif (args.ciphertext_hex != None):  # Read from string
        read_ciphertext = args.ciphertext_hex
    else:  # Read from file
        try:
            f = open(args.ciphertext_hex_file, "r")
        except(OSError):
            print(f"ERROR: could not open \"{args.ciphertext_hex_file}\" for reading.", file=sys.stderr)
            exit(1)
        else:
            read_ciphertext = f.read()
            read_ciphertext = read_ciphertext.replace("\n", "")  # Common occurrence, especially at EOF. Merely saving the file in some editors adds this char. This removes it.
            read_ciphertext = read_ciphertext.replace("\r", "")  # Common occurrence, especially at EOF. Merely saving the file in some editors adds this char. This removes it.
            f.close()

    # Error checks for CIPHERTEXT
    valid_chars = "0123456789ABCDEFabcdef"  # You can mix & match upper and lowercase without any problems
    for i in range(len(read_ciphertext)):  # Check if user input contains non-hexadecimal characters
        if (read_ciphertext[i] not in valid_chars):
            print(f"ERROR: Non hex character (not in {valid_chars}) with value '{read_ciphertext[i]}' was detected in ciphertext at index {i}. Only values 00 - ff are supported. Omit prefixes such as \\0x.", file=sys.stderr)
            exit(1)
    if(len(read_ciphertext) % 2 != 0):  # check if ciphertext is an even length
        print(f"ERROR: Provided ciphertext was not even in length. Ciphertext must be in hexadecimal format, where 2 hex chars are used to encode 1 ascii char.", file=sys.stderr)
        exit(1)
    # If error checks are passed, convert hex string to ascii and fill CIPHERTEXT.
    CIPHERTEXT = [chr(int(read_ciphertext[i:i + 2], 16)) for i in range(0, len(read_ciphertext), 2)]
    #CIPHERTEXT = "".join([chr(int(read_ciphertext[i:i + 2], 16)) for i in range(0, len(read_ciphertext), 2)])  # Deprecated, from when CIPHERTEXT was str

    # Populate KEY_LENGTH, requires CIPHERTEXT to be processed
    global KEY_LENGTH; KEY_LENGTH = args.key_length
    if(KEY_LENGTH < 0):
        print(f"ERROR: Key length from -l can not have value less than 0. Set to 0 for unknown length or a positive integer for known length.", file=sys.stderr)
        exit(1)
    if(KEY_LENGTH > len(CIPHERTEXT)):
        print(f"WARNING: Key length is {KEY_LENGTH-len(CIPHERTEXT)} chars longer than ciphertext, setting key length to length of ciphertext: {len(CIPHERTEXT)}.", file=sys.__stdout__)
        KEY_LENGTH = len(CIPHERTEXT)

    # Populate KNOWN_PLAINTEXT
    global KNOWN_PLAINTEXT
    if(args.known_plaintext == None and args.known_plaintext_file == None):  # No known plaintext
        #KNOWN_PLAINTEXT = "".join([UNKNOWN] * int((len(CIPHERTEXT) / 2)))  # Just full UNKNOWN (e.g. *) if nothing was provided  #Deprecated
        KNOWN_PLAINTEXT = None
    elif(args.known_plaintext != None and args.known_plaintext_file != None):
        print(f"ERROR: You have used both options -k and -K. Use only one!", file=sys.stderr)
        exit(1)
    else:
        if (args.known_plaintext != None):  # -k option
            KNOWN_PLAINTEXT = list(args.known_plaintext)
        else:                               # -K option
            try:
                f = open(args.known_plaintext_file, "rb")  # rb necessary here, since known plaintext can be anything in 0-255
            except(OSError):
                print(f"ERROR: could not open \"{args.known_plaintext_file}\" for reading.", file=sys.stderr)
                exit(1)
            else:
                #Read each character one at a time into a list
                KNOWN_PLAINTEXT = []
                while True:
                    c = f.read(1)
                    if c: KNOWN_PLAINTEXT.append(chr(ord(c)))
                    else: break

                f.close()
                #print(f"DEBUG: KNOWN_PLAINTEXT after opening as rb: {KNOWN_PLAINTEXT}")

                if(KNOWN_PLAINTEXT[-1] == '\n' or KNOWN_PLAINTEXT[-1] == '\r'):
                    print(f"WARNING: Final char of {args.known_plaintext_file} was either \\n or \\r. This was probably unintentional, removing it.", file=sys.__stdout__)
                    KNOWN_PLAINTEXT = KNOWN_PLAINTEXT[:-1]  # Remove final char
                    if(KNOWN_PLAINTEXT[-1] == '\n' or KNOWN_PLAINTEXT[-1] == '\r'): # If final char AND 2nd final char are both \n or \r, remove both
                        print(f"WARNING: 2nd final char of {args.known_plaintext_file} was also either \\n or \\r. This was probably unintentional, removing it.", file=sys.__stdout__)
                        KNOWN_PLAINTEXT = KNOWN_PLAINTEXT[:-1]  # Remove final char (again)
                    #TODO: This assumes the ciphertext is at least 5 chars long
                    print(f"WARNING: After cleanup, this is what the final 5 chars in the known plaintext are interpreted as: hex: {utils.to_hex_string(KNOWN_PLAINTEXT[-5::])}, ascii: {KNOWN_PLAINTEXT[-5::]}. If known plaintext is supposed to end with \\n or \\r, add 2 additional \\n to the end of {args.known_plaintext_file} to bypass the char removal.", file=sys.__stdout__)

        # Error checks on KNOWN_PLAINTEXT after it is populated
        for c in KNOWN_PLAINTEXT:   # Check if invalid chars are present
            if (ord(c) > 255):
                print(f"ERROR: A character in the known plaintext was outside of ascii 0-255. The program can't handle this.", file=sys.stderr)
                exit(1)
        if (len(KNOWN_PLAINTEXT) != len(CIPHERTEXT)):  # Check if user made length error
            print(f"ERROR: Length of the known plaintext from -k or -K must be equal to the length of ciphertext (in ascii representation) from -c or -C, but provided values were of length {len(KNOWN_PLAINTEXT)} and {len(CIPHERTEXT)} respectively.", file=sys.stderr)
            exit(1)
        known_copy = [c for c in KNOWN_PLAINTEXT if c != UNKNOWN]  # Copy of KNOWN_PLAINTEXT, with all UNKNOWN's removed
        for i in range(len(known_copy)):
            if(known_copy[i] not in CLEARTEXT_ALPHABET):  # Check if the supposedly known characters even exist in the supplied plaintext alphabet
                print(f"ERROR: Character '{known_copy[i]}' in known plaintext is NOT in the plaintext alphabet you supplied. Time to reconsider your input.", file=sys.stderr)
                exit(1)

    # Requires: KEY_LENGTH, UNKNOWN, INTERNAL_UNKNOWN, KNOWN_PLAINTEXT, CIPHERTEXT
    global KEY; KEY = utils.calculated_key(KEY_LENGTH)  # Initial part of the key which can be calculated using ciphertext and known chars.
    global UNKNOWN_KEY_CHARS; UNKNOWN_KEY_CHARS = KEY.count(INTERNAL_UNKNOWN) if args.key_length > 0 else -1
    global KEY_KNOWN_LIST; KEY_KNOWN_LIST = utils.get_known_list(KEY, INTERNAL_UNKNOWN) if args.key_length > 0 else None




