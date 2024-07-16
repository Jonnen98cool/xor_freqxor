import sys
import heapq        # Get N closest elements to target from a list
#import itertools    # Generate all permutations of list

import src.globals as g


def calculated_key(key_length:int) -> [str] or None:
    """Given a key length, uses the known plaintext to calculate parts of the key. Returns the calculated key as a list of strings (with unknown chars marked as INTERNAL_UNKNOWN) or None if - given the known plaintext - the solution is impossible."""
    calculated = [g.INTERNAL_UNKNOWN] * key_length

    if(key_length == 0): # If unknown key length, return None
        return None
    elif(g.KNOWN_PLAINTEXT == None):  # With no known plaintext, return a key full of INTERNAL_UNKNOWN.
        return calculated
    else:
        # Replace all UNKNOWN's with INTERNAL_UNKNOWN
        internal_known_plaintext = []
        for i in range(len(g.KNOWN_PLAINTEXT)):
            if(g.KNOWN_PLAINTEXT[i] == g.UNKNOWN):
                internal_known_plaintext.append(g.INTERNAL_UNKNOWN)
            else:
                internal_known_plaintext.append(g.KNOWN_PLAINTEXT[i])

        # Given known plaintext, calculate which values parts of the key must be.
        for i in range(len(internal_known_plaintext)):
            if(internal_known_plaintext[i] != g.INTERNAL_UNKNOWN):
                key_i = list(chr(ord(g.CIPHERTEXT[i]) ^ ord(internal_known_plaintext[i]))) #XOR:ing the ciphertext with the known chars gives us the key. We use list of length 1 rather than string because things get funky with chars like DEL and backspace in strings.
                if(calculated[i%key_length] != g.INTERNAL_UNKNOWN and calculated[i%key_length] != key_i[0]):
                    if(g.KEY_LENGTH != 0):  # If "find-key-length" mode was not used (-l != 0), this means the user made an error.
                        prefix = "0x"
                        str_value = "".join(to_printable(list(g.KNOWN_PLAINTEXT[i])))
                        print(f"ERROR: Key missmatch detected - the following was already calculated: key[{i % key_length}] = {to_hex_string([calculated[i % key_length]], hex_prefix=prefix)} but known_plaintext[{i}]: '{str_value}' would set key[{i % key_length}] = {to_hex_string(key_i[0], hex_prefix=prefix)}. Either the provided known plaintext is wrong or the key length is.", file=sys.stderr)
                        exit(1)
                    return None

                calculated[i%key_length] = key_i[0]

        # If both key length and partial plaintext is known, yet this results in plaintext outside of specified alphabet, throw error
        if (g.KEY_LENGTH != 0):  # If -l 0 was NOT used
            for i in range(g.KEY_LENGTH):
                if(calculated[i] != g.INTERNAL_UNKNOWN):
                    cleartext_substring = perform_xor(calculated[i], g.CIPHERTEXT[i::g.KEY_LENGTH])
                    if(not eligble_cleartext(cleartext_substring)):
                        print(f"ERROR: Supplied known plaintext would result in parts of full plaintext being outside of specified alphabet. Either known plaintext is wrong or alphabet is.", file=sys.stderr)
                        exit(1)

        return calculated

def perform_xor(key:[str], ciphertext:[str]) -> [str]:
    """Performs XOR on two lists of characters, return the resulting list of characters"""
    # #Increases time taken by about 50%      #TODO: leaving this ON, but it should eventually be removed
    # for i in range(len(key)):   #For debugging purposes
    #     if(ord(key[i]) > 255):
    #         print(f"ERROR: perform_xor(): supplied key[{i}] has integer value: {ord(key[i])}, the resulting XOR operation will be scruffed", file=sys.stderr)
    #         exit(1)
    # for i in range(len(ciphertext)):   #TODO: leaving this ON, but it should eventually be removed
    #     if(ord(ciphertext[i]) > 255):
    #         print(f"ERROR: perform_xor(): supplied ciphertext[{i}] has integer value: {ord(ciphertext[i])}, the resulting XOR operation will be scruffed", file=sys.stderr)
    #         exit(1)

    decrypted = []
    key_length = len(key)
    for i in range(len(ciphertext)):
        decrypted.append( chr(ord(ciphertext[i]) ^ ord(key[i%key_length])) )

    return decrypted


# def calculate_job(id:int):      # Currently unused, for parallel processing
#     amount_of_work = len(g.KEYSPACE) // g.CPU_CORES
#     extra_work = len(g.KEYSPACE) % g.CPU_CORES if (id == g.CPU_CORES-1) else 0 #For efficiency reasons (it gets join():ed last), final process always gets the extra work
#
#     work_range = (amount_of_work * id, (amount_of_work * (id+1)) + extra_work)
#     print(f"\tDEBUG: process {id} work range: {work_range} (work amount: {amount_of_work+extra_work})")
#     return work_range



def to_hex_string(ascii:str or [str], hex_prefix:str="", lowercase_hex:bool=True) -> str:
    """Given str or [str] as input and optional hex_prefix, returns (if no hex_prefix) 2-char hex code (e.g. 1f) as a string."""
    case = 'x' if lowercase_hex else 'X'
    format_option = "{:02" + case + "}"
    return "".join(hex_prefix+format_option.format(ord(c)) for c in ascii)


def to_printable(to_print:[str]) -> [str]:
    """Given a list of strings, returns a list of strings where some special chars are replaced by hexadecimal in \\x-prefixed form. Also, INTERNAL_UNKNOWN's are replaced by UNKNOWN."""
    printable = []
    for i in range(len(to_print)):
        if(to_print[i] == g.INTERNAL_UNKNOWN):    #Do I really always want to do this?
            printable.append(g.UNKNOWN)
        elif(to_print[i].isprintable()):
            printable.append(to_print[i])
        else:
            printable.append(to_hex_string(to_print[i], hex_prefix="\\x"))

    return printable


def get_known_list(key:[str], unknown_specifier) -> list[bool]:
    """Given a key and unknown_specifier, returns a boolean list with the length of the key which specifies if each key character is an unknown or not"""
    known = [False] * len(key)
    for i in range(len(key)):
        if(key[i] != unknown_specifier):
            known[i] = True

    return known


def get_colored_text(text:[str], should_color:list[bool], color:str, hex:bool, replace_original:bool = False, replacement_char:str = g.UNKNOWN) -> str:
    """Returns a partly colored string in a specified color based on a boolean list called should_color. There is the option to replace a non-colored character with a different char, default: \'X\'"""
    if(hex):
        if (len(text) > len(should_color) * 2):
            print(f"ERROR get_colored_text(): length of text was {len(text)} but length of should_color was {len(should_color)}. should_color need to have length of at least {(len(text) // 2) + 1}.", file=sys.stderr)
            exit(1)
    else:
        if(len(text) > len(should_color)):
            print(f"ERROR get_colored_text(): length of text was {len(text)} but length of should_color was {len(should_color)}. should_color need to have length of at least {len(text)}.", file=sys.stderr)
            exit(1)

    colored_text = ""
    for i in range(len(text) if not hex else int(len(text)/2)):
        if(hex):
            if(should_color[i] == True):
                colored_text += color + text[i*2 : (i*2)+2] + g.END_COLOR
            else:
                if(replace_original == True):
                    colored_text += replacement_char * 2
                else:
                    colored_text += text[i*2 : (i*2)+2]
        else:
            if(should_color[i] == True):
                colored_text += color + text[i] + g.END_COLOR
            else:
                if(replace_original == True):
                    colored_text += replacement_char
                else:
                    colored_text += text[i]

    return colored_text


def get_x_closest_values_ordered(list:[(int or float)], target_value:(int or float), nr:int) -> ([int or float], [int]):
    """Given a list of values, a target value, and a number "nr", returns the "nr" closest values of the list to the target value. Also returns the indexes of these values."""
    if(nr > len(list)):
        print(f"ERROR: get_x_closest_values_ordered(): There was a request for obtaining the {nr} closest values from a list of only {len(list)} elements.", file=sys.stderr)
        exit(1)

    ordered_values = heapq.nsmallest(nr, list, key=lambda x: abs(x - target_value))  # Sometimes you don't feel like re-inventing the wheel
    indexes = [None] * len(ordered_values)
    for i in range(len(ordered_values)):
        indexes[i] = list.index(ordered_values[i])

    return ordered_values, indexes


def get_number_percent_difference(nr1:(int, float), nr2:(int, float)) -> float:
    """Returns the percentage difference between two numbers greater than 0."""
    if(float(nr1) <= 0.0 or float(nr2) <= 0.0):
        print(f"ERROR: get_number_percent_difference(): Either of the numbers inputted were <= 0.0", file=sys.stderr)
        exit(1)
    return (abs(nr1 - nr2) / abs((nr1+nr2) / 2)) * 100


def eligble_cleartext(cleartext:[str]) -> bool:
    """Given a cleartext, returns True if all characters are in user-specified CLEARTEXT_ALPHABET, otherwise False."""
    # Deprecated small-brain solution
    # in_alphabet = True
    # for i in range(len(cleartext)):
    #     if(cleartext[i] not in g.CLEARTEXT_ALPHABET):
    #         in_alphabet = False
    #         break

    if(set(cleartext) <= set(g.CLEARTEXT_ALPHABET)):
        return True
    else:
        return False


def get_possible_key_values(ciphertext_substring:[str], alphabet:[str]) -> [str]:
    """Given a ciphertext (which should ONLY be encoded by the same key char) and an alphabet which plaintext must belong to, return valid key values as [str]."""
    possible_keys = []
    alphabet_set = set(alphabet)
    for key in g.KEYSPACE:
        plaintext_set = set(perform_xor(list(key), ciphertext_substring))
        if(plaintext_set <= alphabet_set):  # If result of the XOR is a subset of alphabet, this is a valid key
            possible_keys.append(key)

    return possible_keys


def get_key_permutations(possible_key_values:[[str]]) -> int:
    """Given a 2D list of key values, return all possible key permutations."""
    total_possible_keys = 1
    for i in range(len(possible_key_values)):
        total_possible_keys *= len(possible_key_values[i])

    return total_possible_keys


def generate_hex_in_range(start:int, finish:int) -> str:
    """Used for generating e.g. hex-encoded key values used for testing purposes."""
    hexcode = []
    for i in range(start, finish):
        hexcode.append(to_hex_string(chr(i)))

    return "".join(hexcode)


# #Unfinished/unused
# def get_all_possible_keys(possible_values:[[str]], pre:str='') -> [str]:
#     #TODO: Only warn if more than, say, 100Mb is going to get used
#     #TODO: ah, python is not very performance oriented. An empty string takes 21 bytes, adding chars adds more bytes (+4 bytes instead of +1?).
#     # An empty list also takes memory. Leave the parallelization for later, you might want to do some C-style
#     # memory implementation or just forget about it and write all possible keys to disk. Or figure out another way to achieve parallelism.
#     empty_list_size = sys.getsizeof([])
#     b = get_key_permutations(possible_values) * g.KEY_LENGTH * sys.getsizeof(str)
#     Gb = b / (10**9)
#     print(pre+f"WARNING: you are about to consume {b} bytes ({Gb} Gb) of memory. Do you wish to proceed? {g.PRINT_UINPUT}(y/n){g.END_COLOR}")
#     yes_no = input(pre)
#     if(yes_no == 'y'):
#         #return list(itertools.product(*possible_values))    #Danger
#         pass
#     else:
#         return None