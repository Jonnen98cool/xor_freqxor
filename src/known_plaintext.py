import sys

import src.utils as utils
import src.globals as g


def known_plaintext_attack():
    print(f"--- STARTING: KNOWN PLAINTEXT ATTACK ---")

    print(f"\tKey length is unknown, but maximum value is the length of the ciphertext ({len(g.CIPHERTEXT)}).")
    print(f"\tYou will have to manually determine the key length based on which cleartext \"looks\" correct.")
    print("\tRemember: if your supplied known plaintext is correct, ALL " + g.PRINT_GREEN + "green" + g.END_COLOR + "-colored characters must look like they belong to the deciphered plaintext for the corresponding key length to be likely.")

    min_key_length = 1  # Could this somehow be optimized?
    max_key_length = len(g.CIPHERTEXT)
    for i in range(min_key_length, max_key_length+1):
        current_key = utils.calculated_key(i)  # What the current key must look like given known plaintext and which key length we are currently testing.

        if(current_key == None):
            print("\tKey length = " + str(i) + ": Impossible (conflicting plaintext values)")
        else:
            # Obtain "known" list, needed for coloring the correct characters in the key and plaintext.
            known_list = utils.get_known_list(current_key, g.INTERNAL_UNKNOWN) * ((len(g.CIPHERTEXT) // i) + 1)

            # Color the key
            printable_key = utils.to_printable(current_key)
            colored_printable_key = utils.get_colored_text(printable_key, known_list, g.PRINT_BLUE, hex=False, replace_original=True, replacement_char=g.UNKNOWN)

            # Replace all unknown key values with 0x00. This doesn't really matter, it's just so we have a valid key to perform XOR with.
            for j in range(len(current_key)):
                if(current_key[j] == g.INTERNAL_UNKNOWN): current_key[j] = bytes.fromhex("00").decode('utf-8')  # Filler character is 0x00

            # From performing XOR, get resulting cleartext and color it according to known plaintext.
            cleartext = utils.perform_xor(current_key, g.CIPHERTEXT)
            printable_cleartext = utils.to_printable(cleartext)
            colored_printable_cleartext = utils.get_colored_text(printable_cleartext, known_list, g.PRINT_GREEN, hex=False, replace_original=True, replacement_char=g.UNKNOWN)

            # Build a list of characters which - given supplied known plaintext - we know are correct. If any of these
            # "correct" chars are not in supplied alphabet, that means user made a mistake.
            to_print_valid = []
            for j in range(len(cleartext)):
                if(known_list[j] == True):
                    to_print_valid.append(cleartext[j])

            # Only print cleartext if it belongs to user-specified alphabet
            if(utils.eligble_cleartext(to_print_valid)):
                if(g.INCLUDE_KEY == True):
                    print("\tKey length = " + str(i) + ": printable: " + colored_printable_cleartext + ", key: " + colored_printable_key, file=sys.__stdout__)
                else:
                    print("\tKey length = " + str(i) + ": printable: " + colored_printable_cleartext, file=sys.__stdout__)
            else:
                print("\tKey length = " + str(i) + ": Impossible (known parts of cleartext NOT in supplied alphabet)")


    print(f"\n\tFind the correct key length and re-run the program with that information.")
    print(f"\t OR")
    print(f"\tIteratively replace a non-green colored character in the known plaintext with a guess, rerun the program with -l 0.")

    print(f"--- ENDING: KNOWN PLAINTEXT ATTACK ---")