import sys
import argparse
from argparse import RawTextHelpFormatter
#import multiprocessing

import src.utils as utils
import src.globals as g
from src.known_plaintext import known_plaintext_attack
from src.bruteforce import perform_bruteforce
from src.determine_key_length import determine_key_length
from src.freq_analysis import freq_analysis
from src.freq_analysis import brute_n_best_keys
from src.freq_analysis import get_n_best_key_values



# --- Template ---
# parser.add_argument("-t",
#                     "--test",
#                     default="default string",   #Default value
#                     type=str,                   #Type conversion
#                     choices=['rock', 'paper', 'scissors'], #Whitelist of allowed choices
#                     required=False,
#                     help="This is the description for what the --test argument does.",
#                     dest="test"                 #Name when referencing the argument programmatically
#                     )
def parse_args():
    # Initialize parser
    parser = argparse.ArgumentParser(
                        #prog='ProgramName',            #Default value is name of .py file
                        #usage='how to use the progr'   #Prhaps the default value here is better
                        formatter_class=RawTextHelpFormatter,   #This lets me do \n and \t for example in the description of an argument
                        description='Usage example (unknown key length, partially known plaintext): python xor_freqxor.py -l 0 -k "CTF{************}" -C my_ciphertext.txt\n\n'
                                    'An XOR cryptanalysis tool capable of:\n'
                                    '\t- Performing known plaintext attacks\n'
                                    '\t- Brute-forcing unknown key characters\n'
                                    '\t- Figuring out key length by using IoC (only if cleartext is in alphabet [A-Z])\n'
                                    '\t- Finding most likely plaintext by using frequency analysis after key length has been determined (only if plaintext is in alphabet [A-Z])\n'
                                    '\t- Combining known plaintext attack with frequency analysis (only if plaintext is in alphabet [A-Z])\n\n',
                        epilog='Tips for cracking:\n'
                               '\t- It\'s entirely possible the key consists of just 1 char. Set key length to 1 and bruteforce all 256 possibilites.\n'
                               '\t- Definitely take a stab at guessing parts of the known plaintext, it Really helps (it reveals other parts of the plaintext and reduces brute-force space).\n'
                               '\t- Is the hint in the key? Perhaps the known parts of the key (obtained through known plaintext) provide hints to what the unknown parts are? Example: "KE*" --> "KEY", "000102***" --> "000102030405"  ')

    # Adding arguments    API docs: https://docs.python.org/3/library/argparse.html#the-add-argument-method
    parser.add_argument("-l",
                        "--key-length",
                        default=None,
                        type=int,                   
                        required=True,
                        help="Length of key. Use -l 0 if length is unknown.",
                        dest="key_length") 
                        
    parser.add_argument("-k",
                        "--known",
                        default=None,
                        type=str,                   
                        required=False,
                        help="Known plaintext in ascii, where '*' (by default) denotes unknown char. Example: \"CTF{**********}\"",
                        dest="known_plaintext")

    parser.add_argument("-K",
                        "--known-file",
                        default=None,
                        type=str,
                        required=False,
                        help="Path to file containing known plaintext.",
                        dest="known_plaintext_file")

    parser.add_argument("-u",
                        "--unknown",
                        default="*",
                        type=str,
                        required=False,
                        help="Character used to specify an unknown character in the known plaintext (-k, -K). Default: '*'",
                        dest="unknown")
                        
    parser.add_argument("-c",
                        "--ciphertext",
                        default=None,
                        type=str,                   
                        required=False,
                        help="Ciphertext in hexadecimal. Example: \"1911261e1a7d695a3a1f216d0c5004\"",
                        dest="ciphertext_hex")

    parser.add_argument("-C",
                        "--ciphertext-file",
                        default=None,
                        type=str,
                        required=False,
                        help="File to read hexadecimal ciphertext from. [A-F], [a-f] or a mixture of both works.",
                        dest="ciphertext_hex_file")

    parser.add_argument("-a",  # Also add base64, hexadecimal
                        "--cleartext-alphabet",
                        default="printable",
                        type=str,
                        required=False,
                        help="Which characters are allowed in the cleartext, Default: printable. Example usage:"
                             "\n\t-a printable - All printables in ascii range 0-127, which are all chars 32-126 + 5 chars from 0-31 (Use this if you are unsure)"
                        # "\n\t-a human-readable - Ascii 32-126"  # Just 95 chars vs printable's 100. No need to include.
                             "\n\t-a printable_extended - All printables in ascii 0-255"
                             "\n\t-a unprintable - All chars in ascii 0-255"
                             "\n\t-a ctf - Uppercase + lowercase + numbers + _-?!{}"  # What more chars are in ctf flags?   
                             "\n\t-a alphanumeric - Uppercase + lowercase + numbers"
                             "\n\t-a uppercase - Uppercase"
                             "\n\t-a lowercase - Lowercase"
                             "\n\t-a \"abcABC123\" - A custom string"
                             "\n\tTip: Use --add \"åäö\" to add those 3 chars to an existing option."
                             "\n\tTip: Playing a CTF? Sometimes regex for valid flag format is included in the rules page.",
                        dest="cleartext_alphabet"
                        )

    parser.add_argument("--add",
                        default=None,
                        type=str,
                        required=False,
                        help="Add characters to plaintext alphabet. This is useful when an existing option has most but not all characters you want. Can not be used to combine the available options in -a with each other. Example: -a lowercase --add \"åäö\"",
                        dest="add"
                        )

    parser.add_argument("-o",
                        "--output",
                        default="xor_freqxor_output.txt",
                        type=str,
                        required=False,
                        help="Name of the output file when performing a brute-force. Default: xor_freqxor_output.txt",
                        dest="output_file"
                        )

    parser.add_argument("--include-key",
                        default=1,
                        type=int,
                        choices=[0, 1],
                        required=False,
                        help="Whether the key used should be included in bruteforce output and some textual outputs. Default: 1",
                        dest="include_key"
                        )

    # parser.add_argument("-p",       # Currently not in use
    #                     "--processes",
    #                     default=multiprocessing.cpu_count(),
    #                     type=int,
    #                     required=False,
    #                     help="Number of processes to start while performing the brute-force. Default: your system's number of CPU cores",
    #                     dest="processes"
    #                     )

                        #TODO here: IoC input for different languages, not hardcoded to English's 1.73

    parser.add_argument("--expected-frequencies",
                        default="char_frequencies/english_frequencies_uppercase.json",
                        type=str,
                        required=False,
                        help="File path to character frequencies in .json format. Default: char_frequencies/english_frequencies_uppercase.json",
                        dest="expected_frequencies"
                        )

    parser.add_argument("-q",
                        "--quiet",
                        default=0,
                        type=int,
                        choices=[0, 1],
                        required=False,
                        help="Suppress all non-result and non-error output. Default: 0 (off)",
                        dest="quiet"
                        )

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()     # Store user arguments
    #print("DEBUG: here are your args:", args)
    g.init_globals_handle_errors(args)  # Handle arg-related errors, populate global variables

    known_plaintext_exists = False if(g.KNOWN_PLAINTEXT == None) else True
    print(f"__main__: xor_freqxor starting with:")
    print(f"\t- Key length: " + ("Unknown" if g.KEY_LENGTH == 0 else str(g.KEY_LENGTH)))
    print(f"\t- Partial plaintext known? " + ("Yes" if known_plaintext_exists else "No"))
    print(f"\t- Plaintext characters are in alphabet (length {len(g.CLEARTEXT_ALPHABET)}): {g.CLEARTEXT_ALPHABET}")
    print(f"IMPORTANT: Make sure your terminal supports colored output, the following text should be colored blue: {g.PRINT_BLUE}I'm blue bada bee{g.END_COLOR}\n")

    # generating stuff for testing purposes
    #print(f"Generated hex: {utils.generate_hex_in_range(127, 256)}")

    # Program execution path is based on two things: if key length is known and if there is partial known plaintext.

    if(g.KEY_LENGTH == 0):
        if(known_plaintext_exists):
            #print(f"__main__: Key length known: []. Partial plaintext known: [X]. Sending you to known_plaintext_attack() module...\n")
            print(f"__main__: Sending you to known_plaintext_attack() module...\n")
            known_plaintext_attack()
        else:
            #print(f"__main__: Key length known: []. Partial plaintext known: []. Sending you to determine_key_length() module...\n")
            print(f"__main__: Sending you to determine_key_length() module...\n")
            determine_key_length()

    elif(g.KEY_LENGTH > 0 and g.UNKNOWN_KEY_CHARS == 0):       # KEY_LENGTH was > 0 and all characters of it are known
        print("The provided information was enough to determine the key and obtain the plaintext:", file=sys.__stdout__)
        colored_key = utils.get_colored_text(utils.to_printable(g.KEY), g.KEY_KNOWN_LIST, g.PRINT_BLUE, False)
        colored_hex_key = utils.get_colored_text(utils.to_hex_string(c.replace(g.INTERNAL_UNKNOWN, g.UNKNOWN) for c in g.KEY), g.KEY_KNOWN_LIST, g.PRINT_BLUE, True)
        print(f"\t- Key hex: {colored_hex_key}", file=sys.__stdout__)
        print(f"\t- Key printable: {colored_key}", file=sys.__stdout__)
        printable_plaintext =  g.PRINT_GREEN + "".join(utils.to_printable(utils.perform_xor(g.KEY, g.CIPHERTEXT))) + g.END_COLOR
        print(f"\t- Plaintext: {printable_plaintext}", file=sys.__stdout__)

    elif(g.KEY_LENGTH > 0):                # If key length is known
        if(known_plaintext_exists):
            #print(f"__main__: Key length known: [X]. Partial plaintext known: [X].")
            colored_key = utils.get_colored_text(utils.to_printable(g.KEY), g.KEY_KNOWN_LIST, g.PRINT_BLUE, hex=False)
            colored_hex_key = utils.get_colored_text(utils.to_hex_string(c.replace(g.INTERNAL_UNKNOWN, g.UNKNOWN) for c in g.KEY), g.KEY_KNOWN_LIST, g.PRINT_BLUE, hex=True)
            print(f"Calculated initial part of the key, {g.PRINT_BLUE}blue{g.END_COLOR}-colored characters indicate a known key value whereas {utils.to_hex_string(g.UNKNOWN)} and {g.UNKNOWN} respectively denotes unknown:")
            print(f"\t- hex: {colored_hex_key}")
            print(f"\t- printable: {colored_key}\n")

            print(f"Do you wish to ...", file=sys.__stdout__)
            print(f"Blindly brute-force the remaining {str(g.UNKNOWN_KEY_CHARS)} unknown key chars? Input {g.PRINT_UINPUT}0{g.END_COLOR}", file=sys.__stdout__)
            print(f"Perform frequency analysis on the remaining unknown characters in order to find the most likely key values? Input {g.PRINT_UINPUT}1{g.END_COLOR}", file=sys.__stdout__)
            choice = input()
            if(choice == '0'):
                ciphertext_substrings = list(g.CIPHERTEXT[i::g.KEY_LENGTH] for i in range(g.KEY_LENGTH))
                possible_key_values = []
                for i in range(g.KEY_LENGTH):
                    possible_key_values.append(utils.get_possible_key_values(ciphertext_substrings[i], g.CLEARTEXT_ALPHABET))
                #print(f"DEBUG: possible_key_values: {possible_key_values}")
                print(f"__main__: Sending you to perform_bruteforce() module...\n")
                perform_bruteforce(g.KEY, possible_key_values)
            elif(choice == '1'):
                print(f"__main__: Sending you to freq_analysis() module with quiet-mode ON...\n")
                possible_keys, best_chi_indexes = freq_analysis(quiet=True)     # We use quiet mode because freq_analysis() prints all key value scores, including scores for key indexes which we already know which is missleading since these are not used.
                print(f"\n__main__: Frequnecy analysis finished and best-performing key values obtained.")

                # Show users known plaintext chars in green combined with the nr 1 guessed key values as non-green characters.
                top_performing_key = [str(x) for innerlist in get_n_best_key_values(possible_keys, best_chi_indexes, 1) for x in innerlist]
                known_list = utils.get_known_list(g.KEY, g.INTERNAL_UNKNOWN) * ((len(g.CIPHERTEXT) // len(g.KEY)) + 1)  # Only the 100% known values should be colored green. We also need make this list as least a long as ciphertext so we multiply it.
                combined_best_key = []  # Our current best guess of the key; a combination between 100% known values from known plaintext and the top scoring key values with regard to frequency analysis.
                for i in range(len(g.KEY)):
                    if(g.KEY[i] != g.INTERNAL_UNKNOWN):
                        combined_best_key.append(g.KEY[i])
                    else:
                        combined_best_key.append(top_performing_key[i])
                best_cleartext_guess = utils.perform_xor(combined_best_key, g.CIPHERTEXT)
                colored_best_cleartext_guess = utils.get_colored_text(best_cleartext_guess, known_list, g.PRINT_GREEN, hex=False, replace_original=False)
                print(f"Combining the known parts of the key (from supplied known plaintext) with the best performing key values (from frequency analysis) gives the following plaintext, where {g.PRINT_GREEN}green{g.END_COLOR}-marked characters are guaranteed correct (if supplied known plaintext is): {colored_best_cleartext_guess}", file=sys.__stdout__)

                # Show users known plaintext with uncertain characters as UNKNOWN's
                print_only_known = []
                for i in range(len(g.CIPHERTEXT)):
                    if(g.KEY[i%g.KEY_LENGTH] != g.INTERNAL_UNKNOWN):
                        known = "".join(utils.to_printable(utils.perform_xor(g.KEY[i%g.KEY_LENGTH], list(g.CIPHERTEXT[i]))))
                        print_only_known.append(known)
                    else:
                        print_only_known.append(g.UNKNOWN)
                print(f"To make guessing known plaintext easier for you, you may copy the following string and use it as known plaintext: " + "".join(print_only_known) + '\n')

                print(f"Input a number {g.PRINT_UINPUT}N{g.END_COLOR} for which the (if available) N top-scoring key values for each position in the key with regards to their chi-squared scores are tested.", file=sys.__stdout__)
                to_brute = int(input())
                keys_to_test = get_n_best_key_values(possible_keys, best_chi_indexes, to_brute)
                print(f"__main__: Sending you to perform_bruteforce() module...\n")
                perform_bruteforce(g.KEY, keys_to_test)
        else:
            #print(f"__main__: Key length known: [X]. Partial plaintext known: []. Sending you to freq_analysis() module...\n")
            print(f"__main__: Sending you to freq_analysis() module...\n")
            possible_keys, best_chi_indexes = freq_analysis()
            print(f"\n__main__: Frequnecy analysis finished and best-performing key values obtained. Sending you to brute_n_best_keys() module...\n")
            brute_n_best_keys(possible_keys, best_chi_indexes)


    g.PRINT_NULL.close()
    #print("\n__main__: PROGRAM TERMINATED CLEANLY")
    exit(0)
