import sys

import src.utils as utils
import src.globals as g
import src.bruteforce as bruteforce


# "The chi-square test checks whether the frequencies occurring in the sample differ significantly from the frequencies one would expect"
# The frequencies we would expect are those of the English lanugage, where 'E' is the most common and so on.
def freq_analysis(quiet:bool=False) -> ([[str]], [[int]]):
    """Given an alphabet (unimplemented ATM), returns two 2D lists containing:
    A: Possible key values for each index of the key
    B: The chi score rank for all key values ordered from best performing (i.e. most likely) to worst performing, for each index of the key."""
    print(f"--- STARTING: FREQUENCY ANALYSIS ---")
    if not quiet: print(f"\t... on {g.KEY_LENGTH} different substrings containing (on average) {round(len(g.CIPHERTEXT) / g.KEY_LENGTH, 1)} characters each.")
    if(g.CLEARTEXT_ALPHABET != list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")):
        print(f"ERROR: CURRENTLY ONLY SUPPORTS IF PLAINTEXT BELONGS TO ALPHABET OF [A-Z]", file=sys.stderr)
        exit(1)

    print(f"\n\tWord of caution: Frequency analysis usually only works well if:")
    print(f"\t\t- A: Ciphertext/cleartext is sufficiently long (it's impossible to give a \"minimum length\" number)")
    print(f"\t\t- B: Cleartext exhibits tendencies of the English language, i.e. it roughly follows the frequency distribution where 'E' is most common, 'T' second most etc. If the cleartext mentions the fictional abbreviation \"ZQX\" a lot for example, the frequency analysis is more likely to predict wrong.")

    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ") # Temp hardcoded
    chi_results = [list()] * g.KEY_LENGTH
    possible_keys = [list()] * g.KEY_LENGTH
    best_chi_values = [list()] * g.KEY_LENGTH
    best_chi_indexes = [list()] * g.KEY_LENGTH
    show_top = 3
    if not quiet: print(f"\n\tTop {show_top} most likely key values:")

    for i in range(g.KEY_LENGTH): #For each key character
        substring = g.CIPHERTEXT[i::g.KEY_LENGTH]
        #print(f"DEBUG: freq_analysis(): current substring on i={i}: {substring}")

        possible_keys[i] = utils.get_possible_key_values(substring, alphabet)  # We must find the key characters which makes the plaintext be of only characters in the alphabet [A-Z]
        if(len(possible_keys[i]) == 0):
            print(f"ERROR in freq_analysis(): Key[{i}] had 0 possible values. Either you have supplied incorrect key length or the plaintext alphabet is wrong.", file=sys.stderr)
            exit(1)
        chi_2 = [float] * len(possible_keys[i])

        # Perform chi-squared test for each substring.
        # This is essentially brute-forcing a Ceasar cipher with the intent of finding the best frequency distribution match.
        for j in range(len(possible_keys[i])):
            current_key = list(possible_keys[i][j])
            deciphered = utils.perform_xor(current_key, substring)    # Perform XOR with a 1-char key and only part of ciphertext
            #print(f"DEBUG freq_analysis(): iteration j={j}, deciphered: {deciphered}")
            observed_freq = get_frequencies_percentage(deciphered, alphabet)
            chi_2[j] = chi_squared(list(observed_freq.values()), list(g.EXPECTED_FREQUENCIES.values()))

        chi_results[i] = chi_2
        #print(f"DEBUG: chi_results[{i}]: {chi_results[i]}")

        best_chi_values[i], best_chi_indexes[i] = utils.get_x_closest_values_ordered(chi_results[i], 0.0, len(chi_results[i]))

        if not quiet: print(f"\tKey[{i}] ({len(possible_keys[i])} total possible):")
        iterations = show_top if show_top <= len(best_chi_values[i]) else len(best_chi_values[i])
        for j in range(iterations):
            if not quiet: print(f"\t\t- Chi-squared: {round(best_chi_values[i][j], 4)}, Key value hex: {utils.to_hex_string(possible_keys[i][best_chi_indexes[i][j]])}, Key value printable: {utils.to_printable([possible_keys[i][best_chi_indexes[i][j]]])}")

    if quiet: print(f"\t(Finished successfully in quiet mode)")
    print(f"--- ENDING: FREQUENCY ANALYSIS ---")
    return possible_keys, best_chi_indexes


def chi_squared(observed:[float], expected:[float]) -> float:
    """Given two list of floats - observed and expected - return the chi squared value after comparison; a metric of how similar the two lists are to each other."""
    if(len(observed) != len(expected)):
        print(f"ERROR: chi_squared(): Length of the two input lists were not the same", file=sys.stderr)
        exit(1)

    chi_squared = 0.0
    for i in range(len(expected)):
        chi_squared += ((observed[i] - expected[i]) ** 2) / expected[i]

    return chi_squared


def get_frequencies_percentage(text:[str], eligible_alphabet:[str]) -> {str: float}:
    """Given a text and an alphabet as [str], return a dictionary containing the character frequencies in that text."""

    occurrences = dict().fromkeys(eligible_alphabet, 0)  # Initialize a dict of occurrences for each alphabet char to 0.
    #print(f"DEBUG get_frequencies(): Initialized dict: {occurrences}")
    for i in range(len(text)):
        if(text[i] in eligible_alphabet):
            occurrences[text[i]] += 1
        else:
            print(f"ERROR in get_frequencies(): text[{i}]: {text[i]} was not in eligible alphabet ({eligible_alphabet}). Supplied text was: " + "".join(utils.to_printable(text)), file=sys.stderr)
            exit(1)

    #print(f"DEBUG get_frequencies(): occurrences: {occurrences}")
    len_alphabet = len(eligible_alphabet)
    for key in occurrences:     # For each key (character) in the dict, replace the integer-represented occurences with a float-represented percentage.
        #occurrences[key] /= len_alphabet  # Deprecated, bug
        occurrences[key] = (occurrences[key] / len_alphabet) * 100  # Represent frequency as percentage in order to match that of the .json file.

    #print(f"DEBUG get_frequencies(): Returning following: {occurrences}")
    return occurrences


def get_n_best_key_values(possible_key_values:[[str]], top_key_indexes:[[int]], depth:int) -> [[str]]:
    """Given the results from freq_analysis(), i.e. two [[str]] containing possible key values and their respective rank, return a [[str]] containing the \"depth\" best key values."""

    keys_to_test = [list()] * g.KEY_LENGTH
    for i in range(g.KEY_LENGTH):
        values_to_test = []
        for j in range(depth):
            if (j < len(top_key_indexes[i])):  # Only add value to test if it exists
                values_to_test.append(possible_key_values[i][top_key_indexes[i][j]])
        keys_to_test[i] = values_to_test

    return keys_to_test


# This function should only be used when there is absolutely NO IDEA of the known plaintext. It should ONLY be used for brute-forcing top-scoring key values.
def brute_n_best_keys(possible_key_values:[[str]], top_key_indexes:[[int]]):
    """Given possible key values and the top-performing indexes for each index in the key, brute-force the N top-performing values."""
    print(f"--- STARTING: BRUTE N BEST KEYS ---")

    top_performing_key = [str(x) for innerlist in get_n_best_key_values(possible_key_values, top_key_indexes, 1) for x in innerlist]  # 2D-list to 1D-list
    print(f"\tThe frequency analysis' best prediction for the key is the following: {top_performing_key}", file=sys.__stdout__)
    print(f"\tThis would result in the plaintext looking like: " + "".join(utils.to_printable(utils.perform_xor(top_performing_key, g.CIPHERTEXT))), file=sys.__stdout__ )
    print(f"\tIf this guessed plaintext gives you an idea for partial known plaintext, you should re-run the program with that.")

    total_possible_keys = utils.get_key_permutations(possible_key_values)
    print(f"\n\tThere are a total of {total_possible_keys} valid key permutations to brute-force. Input {g.PRINT_UINPUT}0{g.END_COLOR} if you wish to do this.", file=sys.__stdout__)
    print(f"\tYou may also select a number {g.PRINT_UINPUT}N{g.END_COLOR} for which the (if available) N top-scoring key values for each position in the key with regards to their chi-squared scores are tested. Input a number N greater than 0 if you wish to do this.", file=sys.__stdout__)
    to_brute = int(input("\t"))

    # Send a "to test" list of key values away for brute-forcing
    keys_to_test = get_n_best_key_values(possible_key_values, top_key_indexes, to_brute) if to_brute > 0 else possible_key_values
    key = [g.INTERNAL_UNKNOWN] * g.KEY_LENGTH  # Fully unknown key. We don't have any known/certain values of the key, only targets which we wish to test.
    print(f"Sending you to perform_bruteforce() module...\n")
    bruteforce.perform_bruteforce(key, keys_to_test, '\t')

    print(f"\n\tFrom the result of the brute-force, hopefully the complete correct plaintext is now known")
    print(f"\t OR")
    print(f"\tYou got some idea of a partial known plaintext which you can rerun the program with.")

    print(f"--- ENDING: BRUTE N BEST KEYS ---")