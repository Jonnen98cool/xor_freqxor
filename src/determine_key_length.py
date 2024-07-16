import sys

import src.utils as utils
import src.globals as g


# --- IoC ---
'''
IoC: The probability that upon selecting two characters from a ciphertext, they are the same.
For monoalphabetically encrypted texts (e.g. Ceasar cipher), the IoC is the same as plaintext.
The same is true for transposed text. The order of the characters don't matter for IoC, only their frequency.
'''

#Cryptanalysis of Vigenere (XOR is the same):
'''
1. Find key length L.
2. Break up ciphertext in X ciphertexts with length L.
3. Each broken up ciphertext X1, X2 etc is now only a monoalphabetic crypto. Here we can use unigram frequency analysis.
'''

'''
Correct IoC values for key lengths 1-10 (Wikipedia):
1 	1.12
2 	1.19
3 	1.05
4 	1.17
5 	1.82
6 	0.99
7 	1.00
8 	1.05
9 	1.16        #This is the only one which doesn't match, I get 1.1746
10 	2.07 
'''


#TODO: Is averaging the IoC results for all substrings really the best metric for determining key length? What about median for example?
def determine_key_length():
    print(f"--- STARTING: DETERMINE KEY LENGTH ---")
    if(g.CLEARTEXT_ALPHABET != list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")):
        print(f"ERROR: CURRENTLY ONLY SUPPORTS IF PLAINTEXT BELONGS TO ALPHABET OF [A-Z]", file=sys.stderr)
        exit(1)

    max_allowed = len(g.CIPHERTEXT) // 2
    print(f"\tPlease input a number {g.PRINT_UINPUT}X{g.END_COLOR}:   X > 0,   X <= {max_allowed} (length of ciphertext // 2).", file=sys.__stdout__)
    print(f"\t\t- A larger number will provide more evidence for what the correct key length is")
    print(f"\t\t- A smaller number would make the analysis finish quicker")
    print(f"\t\t- If not above {max_allowed}, a number 3 times the size of the expected maximum key length is a good start")
    print(f"\t\t- If maximum key length is unknown, recommended input is: {max_allowed}")
    max_key_length = int(input("\t"))

    # TODO: This block of text should be updated if more than English is supported
    # It's hard to thread the line between informing users enough so they can make an educated guess vs printing a whole book in their face.
    # And I refuse to let the program automatically determine the best guess. User must be in control.
    print(f"\n\tAverage Index of Coincidence (IoC) is used to determine a likely key length used on the ciphertext.")
    print(f"\tWord of caution: IoC analysis usually only works well if:")
    print(f"\t\t- A: Ciphertext/cleartext is sufficiently long (it's impossible to give a \"minimum length\" number)")
    print(f"\t\t- B: Cleartext exhibits tendencies of the english language, i.e. it has an IoC of around 1.73. It's not impossible to craft a text that has an IoC of 1.00, which just means that all characters A-Z are equally likely to occur in the text.")
    #print(f"\tA value of 1.00 means that all characters appear equally often, Q is as common as E for example. A value of 1.73 means ")  #ehh let's just not explain it for now
    #print(f"\tAn average value close to 1.00 suggests that the characters in the plaintext representation of the supplied ciphertext are uniformly distributed across the alphabet, i.e. that e.g. characters 'Q' and 'E' are equally likely to occur in the plaintext. This is not the case for most English plaintexts, as 'E' is much more likely to occur. As such, an IoC close to 1.00 suggests that this is probably not the correct key length.")
    #print(f"\tAn average value close to 1.73 suggests the plaintext is not random gibberish but rather that it matches with that of English texts. You would expect multiples of this key length to also have a value close to 1.73. If they don't, this is probably not the correct key length.")
    print(f"\tThe results which are less than 20% different (arbitrary percentage) to an IoC of 1.73 will be highlighted in {g.PRINT_GREEN}green{g.END_COLOR}.")
    print(f"\tThe likely key length:")
    print(f"\t\t- ... and multiples of this length should have IoC close to 1.73.")
    print(f"\t\t- Is the lowest value of the multiples. For example, if key lengths 5, 10 and 15 have IoC close to 1.73, the likely key length is 5.")
    print(f"\tFocus on the lower key-length values. The higher the key length, the more unreliable the results are.")
    print(f"") #\n

    min_key_length = 1
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")   # temp hardcoded
    results = [] # Eventually holds lists each containing (key length, IoC values, average IoC)


    for i in range(min_key_length, max_key_length+1): # Find average IoC values for all key lenghts
        impossible_alphabet = False
        impossible_unique_chars = False
        IoC = [float] * i

        # For every key length, split the text into that many substrings (or "columns" of a Vigenere cipher).
        # Then, perform IoC analysis for each of the substrings. The correct key length will have IoC values for most substrings close to the English language.
        for j in range(i):
            substring = g.CIPHERTEXT[j::i]  # List slicing is fantastic
            #print(f"\tDEBUG: substring {j} (not in list format): " + "".join(substring))
            #print(f"\tDEBUG: Length of substring: {len(substring)}")
            IoC[j-min_key_length] = calculate_IoC(substring, alphabet)

            if(len(utils.get_possible_key_values(substring, alphabet)) == 0):
                impossible_alphabet = True
                break
            if(IoC[j] == -100.0):
                impossible_unique_chars = True
                break

        if(impossible_alphabet):
            results.append([i, None, None])
            print(f"\tKey length: {i}, Impossible, 0 possible key values (due to either incorrect key length or specified alphabet)")
        elif(impossible_unique_chars):
            results.append([i, IoC, -100.0])
            print(f"\tKey length: {i}, Impossible, there were more unique characters in a substring than present in supplied alphabet")
        else:
            results.append([i, IoC, sum(IoC) / len(IoC)])
            #print(f"DEBUG: determine_key_length(): results[{i}]: {results[i-min_key_length]}]")

            if(results[i-min_key_length][2] == 0.0):      # Average (thus all) IoC was 0.0, can't calculate a percentage difference on this so it gets a special case
                print(f"\tKey length: {results[i - min_key_length][0]}, Average IoC: {round(results[i - min_key_length][2], 4)}, Difference from target: Inf",)
            else:
                percentage_from_target = utils.get_number_percent_difference(results[i-min_key_length][2], 1.73)
                print_percent = str(round(percentage_from_target, 2))+'%' if percentage_from_target > 20.0 else g.PRINT_GREEN + str(round(percentage_from_target, 2))+'%' + g.END_COLOR
                print(f"\tKey length: {results[i-min_key_length][0]}, Average IoC: {round(results[i-min_key_length][2], 4)}, Difference from target: {print_percent}", file=sys.__stdout__)


    #closest_values = get_x_closest_values_ordered([results[x][2] for x in range(len(results))], 1.73, 5)
    #print(f"The 5 values closest to 1.73, in order, are: {closest_values}")

    print(f"\n\tFrom above information, determine the most probable key length and re-run the program with that.")
    print(f"\tWith known key length, cryptanalysis can continue in the form of frequency analysis.")
    print(f"--- ENDING: DETERMINE KEY LENGTH ---")


# English language IoC:     1.73 (0.067)
# Random [a-z]string IoC:   1.00 (0.0385 = 1/26)
# The IoC value lets us determine whether a cryptic text is closer to random or closer to a language.

def calculate_IoC(text:[str], plaintext_alphabet:[str]) -> float:
    """Takes a piece of text belonging to a specified alphabet and calculates the Index of Coincidence; The probability that two randomly drawn characters from the text are the same."""
    if(len(text) < 2):
        print(f"ERROR in calculate_IoC(): Length of text was < 2", file=sys.stderr)
        exit(1)

    unique_characters = set(text)
    if(unique_characters > set(plaintext_alphabet)):
        # This just means that either the plaintext has characters outside the specified alphabet OR the key length guess occurring before this function call is wrong.
        return -100.0   # Special value handled by caller

    # Make lists equal size if they are not. Example: If supplied plaintext_alphabet is 26 long, but only 24 unique chars occurred in the text,
    # we still must account for those 2 missing chars, by acknowledging that they occurred 0 times (which is not the same as neglecting that acknowledgement)
    unique_characters = list(unique_characters)  # We now must allow duplicates, so we transform from set to list
    len_difference = len(plaintext_alphabet) - len(unique_characters)
    for i in range(len_difference):
        unique_characters.append(g.INTERNAL_UNKNOWN)  # If INTERNAL_UNKNOWN ever occurs in the supplied text, we are in trouble. But it shouldn't.

    ioc = 0.0
    N = len(text)
    c = len(plaintext_alphabet)
    for i in range(c):
        n_i = text.count(unique_characters[i])
        ioc += (n_i/N) * ((n_i-1) / (N-1))

    # if(ioc == 0.0): #Is this correct? If not a single character occurred more than once, final IOC gets set to 1.0
    #     #Edit: gives way more false positives to an otherwise very well-performing result, perhaps it's not the best approach
    #     ioc = 1 / len(plaintext_alphabet)

    #return ioc     # Not normalized    (0.0385 for random text and 0.067 for English)
    return c * ioc  # Normalized        (1.00   for random text and 1.73  for English)
