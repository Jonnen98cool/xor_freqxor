import sys
import time
# from time import process_time
# from multiprocessing import Process
# from multiprocessing import Value #DEbug
# import os

import src.utils as utils
import src.globals as g

# Currently not in use
class PsInfo:
    def __init__(self, id, file_name):
        self.id = id
        self.pid = None
        self.fp = None
        self.file_name = file_name
        self.process = None
        self.run_time = None
        self.job_allocation = None


# Deprecated
# def perform_bruteforce_deprecated():
#     # --- NON-PARALLEL PROCESSING BENCHMARKS ---
#     # Command used:   python solver.py -l 5 -k "T%%{%%%%%%%%%%}" -c 1911261e1a7d695a3a1f216d0c5004 -u %
#     # File size for 1st: 50255, 2nd, 3rd, 4th: 52440 (this is because first jobset includes the UNKNOWN character). File size for all four (32-128): 207575
#
#     # command used: python solver.py -l 5 -k "%%%{%%%%%%%%%%}" -c 1911261e1a7d695a3a1f216d0c5004 -u %
#     # File size: 19719625 (exactly 95x larger)
#     # Process Time taken:  3.4560065019999997s
#     # 3.4318117239999997s
#     # 3.376715795s
#
#     print("--- BRUTE-FORCE STARTING ---")
#     bruteforce_start_time = time.time()
#     print(f"\tSpecified valid cleartext alphabet of length {len(g.CLEARTEXT_ALPHABET)}:", bytearray("".join(g.CLEARTEXT_ALPHABET), 'utf-8'))
#     f = open(g.OUTPUT_FILE, "w")
#
#     lines_written = Value('i', 0)  # DEBUG
#     Processes = []  # Holds PsInfo objects corresponding to each process
#     spawn_processes = False if (g.UNKNOWN_KEY_CHARS <= 1) else True
#     # internal_key = KEY.replace(UNKNOWN, INTERNAL_UNKNOWN)   #no longer necessary
#
#     if (not spawn_processes):  # Don't spawn multiple processes if number of unknowns is 1 or less
#         brute_recursive(g.KEY, True, (-1, -1), f, -1, lines_written)
#
#     else:  # Start up the processes
#         for i in range(g.CPU_CORES):
#             # The approach of letting each process write their results to their own file avoids race conditions.
#             # It is costly time-wise to write to file yes, but for bruteforcing a large amount of unknown's, storing the results in memory
#             # will mean that the memory quickly runs out, and then we're back to paging and writing to disk again, which is
#             # more costly than merely writing to disk to begin with.
#             Processes.append(PsInfo(id=i, file_name="p" + str(i) + "_output.txt"))
#             Processes[i].fp = open(Processes[i].file_name, "w")
#             Processes[i].process = Process(target=brute_recursive, args=(g.KEY, True, utils.calculate_job(Processes[i].id), Processes[i].fp, Processes[i].id, lines_written,))
#             Processes[i].process.start()
#
#         merge_files_start_time = None
#         for i in range(g.CPU_CORES):  # Wait for all the processes to finish
#             # time.sleep(2)
#             Processes[i].process.join()
#
#             # Transfer process output from separate files to a single file
#             if (i == 0):
#                 merge_files_start_time = process_time()
#             Processes[i].fp = open(Processes[i].file_name, 'r')
#             f.write(Processes[i].fp.read())
#             Processes[i].fp.close()
#             # os.remove(Processes[i].file_name)  # This terrifies me
#
#     f.close()
#     if (spawn_processes):
#         print(f"\tFinished merging processes output files into one file in {process_time() - merge_files_start_time}s")
#     print(f"\tMaximum amount of lines written if ALL cleartexts are valid: {g.KEYSPACE_LENGTH ** g.UNKNOWN_KEY_CHARS}")
#     print(f"\tActual lines written: {lines_written.value}")  # WHY DOESNT THIS MATCH THE ACTUAL TEXTFILE, should be 18 not 27
#
#     bruteforce_stop_time = time.time() - bruteforce_start_time  # Uh, can't use process time here :D
#     print(f"\tFinished after a wall time of {bruteforce_stop_time}s. Check " + g.OUTPUT_FILE + " for output.")  # Why does this sometimes take WAY longer than file merge time, shouldnt program be mostly finished after file merge?
#     print("--- BRUTE-FORCE COMPLETED ---")


# Deprecated
# def brute_recursive(key, first_call: bool, job, out_file, id, lines_written):  # The "key" argument is different from the global constant "KEY". Tt contains progresively fewer of the unknowns as the recursion gets deeper.
#     '''Deprecated'''
#     key_list = list(key)
#
#     # The outermost KEY_SPACE nr. of recursive calls should be divided between multiple processes. This should avoid any of the processes performing the same work.
#     if (first_call and key.count(g.INTERNAL_UNKNOWN) > 1):
#         process_start_time = process_time()
#         first_unknown_index = key_list.index(g.INTERNAL_UNKNOWN)
#         for i in range(job[0], job[1]):
#             key_list[first_unknown_index] = g.KEYSPACE[i]
#             guessed_key = "".join(key_list)
#             brute_recursive(guessed_key, False, (-1, -1), out_file, id, lines_written)
#
#             if (i == job[1] - 1):  # THIS SOLVE THE ANNOYING BUG WHICH TOOK WAY TO LONG.
#                 out_file.close()  # For python to write to the file (consistently), you need to close your fp. And you can't do Processes[i].fp.close() outside of this function after the process has exited. It should work since Processes[i].fp is different from Processes[i].process (which has exited/joined), but it doesnt!
#                 print(f"\tProcess {id} with PID={os.getpid()} finished in {process_time() - process_start_time}s.")
#                 if (id == 0):
#                     print("\tCommencing file copying ...")
#
#     # Recursively calls itself until there is only 1 INTERNAL_UNKNOWN character in the key
#     # This code block is essentially the same as the above one with the exception that this isn't one of the outermost recursive calls, and so no job-splitting is done.
#     elif (key.count(g.INTERNAL_UNKNOWN) > 1):
#         first_unknown_index = key_list.index(g.INTERNAL_UNKNOWN)
#         for i in range(g.KEYSPACE_LENGTH):
#             key_list[first_unknown_index] = g.KEYSPACE[i]
#             guessed_key = "".join(key_list)
#             brute_recursive(guessed_key, False, (-1, -1), out_file, id, lines_written)
#
#     else:
#         # This var can be moved to the top of this function instead of appearing in all 3 if-statements?
#         only_unknown_index = key_list.index(g.INTERNAL_UNKNOWN)  # Find only occurence of INTERNAL_UNKNOWN
#         for i in range(g.KEYSPACE_LENGTH):
#             key_list[only_unknown_index] = g.KEYSPACE[
#                 i]  # Sets the first INTERNAL_UNKNOWN to a character in the key_space
#             guessed_key = "".join(key_list)  # Convert list back to string again
#             guessed_decrypted = utils.perform_xor(guessed_key, g.CIPHERTEXT)
#             if (utils.eligble_cleartext(
#                     guessed_decrypted)):  # It's not very efficient calling it ONLY here, I want to call it in the outermost recursive loop for example. That way I can skip entering this innermost one A LOT of times.
#                 if (g.STORE_KEY):
#                     out_file.write(guessed_key + ': ' + guessed_decrypted + '\n')
#                 else:
#                     out_file.write(guessed_decrypted + '\n')
#                 lines_written.value = lines_written.value + 1
#
#             # --- eligble_cleartext() benchmarks ---
#             # python solver.py -l 5 -k "%%%{%%%%%%%%%%}" -c 1911261e1a7d695a3a1f216d0c5004 -u "%" -o xor_bruteforced.txt -p 2
#             # Without   eligble_cleartext() check: 50s
#             # With      eligble_cleartext() check: 61s
#             # Overall wall time took longer, WITHOUT eligble_cleartext(). It took 86s/75s/65s/64s (wtf) as opposed to 61s. This is because the file copying is much slower, and there is more to copy with no filtering.
#         return



def perform_bruteforce(known_key:[str], keys_to_test:[[str]], pre:str=''):
    print(pre+"--- STARTING: BRUTE-FORCE ---")

    if(known_key.count(g.INTERNAL_UNKNOWN) <= 0):
        print(f"ERROR in perform_bruteforce(): There were no occurrences of INTERNAL_UNKNOWN in supplied known_key. There is nothing to bruteforce.", file=sys.stderr)
        exit(1)

    bruteforce_start_time = time.time()
    f = open(g.OUTPUT_FILE, "w")
    key_copy = known_key.copy()  # Make shallow copy of key, because passing it to brute_keys_recursive changes it and we don't want to change our global constant KEY.

    # Output how many key permutations are going to be tested to give user an estimate of the time it's going to take
    will_test = []
    for i in range(g.KEY_LENGTH):
        if(key_copy[i] != g.INTERNAL_UNKNOWN):
            will_test.append([key_copy[i]])
        else:
            will_test.append(keys_to_test[i])
    #TODO: maybe don't show this in the case of full guess bruteforce? Because it will print way too many chars if key length and supplied alphabet is even decently long.
    print(pre+f"\tThe following values of the key at their respective key index are going to be tested: {will_test}")
    print(pre+f"\tThis is going to result in {utils.get_key_permutations(will_test)} different key permutations to be tested.")
    if(g.INCLUDE_KEY == True): print(pre+f"\tTip: run with \"--include-key 0\" to prevent key from being stored in output file. This saves both time and disk space.")
    print(pre+f"\tStarting now...\n")
    if(g.QUIET == True): print(pre+f"\tStarting brute-force on {utils.get_key_permutations(will_test)} key permutations...", file=sys.__stdout__)


    #lines_written = Value('i', 0)  # DEBUG
    #Processes = []  # Holds PsInfo objects corresponding to each process
    #spawn_processes = False if (known_key.count(g.INTERNAL_UNKNOWN) <= 1) else True
    spawn_processes = False     #Temp hardcoded


    if (not spawn_processes):  # Don't spawn multiple processes if number of unknowns is 1 or less
        brute_keys_recursive(key_copy, keys_to_test, f)

    else:
        print(pre+f"\tDEBUG: PARALLEL PROCESSING SUPPORT NOT IMPLEMENTED YET")
        brute_keys_recursive(key_copy, keys_to_test, f)

    # else:  # Start up the processes
    #     for i in range(g.CPU_CORES):
    #         # The approach of letting each process write their results to their own file avoids race conditions.
    #         # It is costly time-wise to write to file yes, but for bruteforcing a large amount of unknown's, storing the results in memory
    #         # will mean that the memory quickly runs out, and then we're back to using virtual memory and writing to disk again, which is
    #         # more costly than merely writing to disk to begin with.
    #         Processes.append(PsInfo(id=i, file_name="p" + str(i) + "_output.txt"))
    #         Processes[i].fp = open(Processes[i].file_name, "w")  # TODO: If file already exists, exit program with error. This ensures we dont overwrite the users file if they happened to be namend the same
    #         #Processes[i].process = Process(target=brute_recursive, args=(g.KEY, True, utils.calculate_job(Processes[i].id), Processes[i].fp, Processes[i].id, lines_written,))
    #         Processes[i].process = Process(target=brute_keys_recursive, args=(g.KEY, True, utils.calculate_job(Processes[i].id), Processes[i].fp, Processes[i].id, lines_written,))
    #         Processes[i].process.start()
    #
    #     merge_files_start_time = None
    #     for i in range(g.CPU_CORES):  # Wait for all the processes to finish
    #         # time.sleep(2)
    #         Processes[i].process.join()
    #
    #         # Transfer process output from separate files to a single file
    #         if (i == 0):
    #             merge_files_start_time = process_time()
    #         Processes[i].fp = open(Processes[i].file_name, 'r')
    #         f.write(Processes[i].fp.read())
    #         Processes[i].fp.close()
    #         # os.remove(Processes[i].file_name)  # This terrifies me

    f.close()
    # if (spawn_processes):
    #     print(f"\tFinished merging processes output files into one file in {process_time() - merge_files_start_time}s")

    bruteforce_stop_time = time.time() - bruteforce_start_time
    print(pre+f"\tFinished after a wall time of {bruteforce_stop_time}s. Check " + g.OUTPUT_FILE + " for output.", file=sys.__stdout__)
    if(g.INCLUDE_KEY): print(pre+f"\tOutput is split into key and cleartext parts as such: *key*: *cleartext*")
    print(pre+"--- ENDING: BRUTE-FORCE ---")




# This updated recursive function doesn't have to call eligible_cleartext() a million times, becuase we pass valid key values as an argument.
# I've yet to work out a good way to parallelize this however.
def brute_keys_recursive(key: [str], to_test: [[str]], fp):
    """Given a key containing at least 1 INTERNAL_UNKNOWN and a 2D list of keys to test, brute-force all the unknown parts of the key. Write results to file already opened by fp."""
    #TODO: Performance enhancements for all code in here, including function calls

    unknown_index = key.index(g.INTERNAL_UNKNOWN)  # Find first occurrence of INTERNAL_UNKNOWN

    # Recursively call itself until there is only 1 INTERNAL_UNKNOWN in the key
    if (key.count(g.INTERNAL_UNKNOWN) > 1):
        for i in range(len(to_test[unknown_index])):
            key[unknown_index] = to_test[unknown_index][i]
            brute_keys_recursive(key, to_test, fp)
        key[unknown_index] = g.INTERNAL_UNKNOWN

    # Brute force the index on which the INTERNAL_UNKNOWN char is located. Don't test all values, only those in to_test.
    else:
        for i in range(len(to_test[unknown_index])):
            key[unknown_index] = to_test[unknown_index][i]
            cleartext = "".join(utils.to_printable(utils.perform_xor(key, g.CIPHERTEXT)))
            if(g.INCLUDE_KEY):  # I wonder how much this decreases performance
                printable_key = "".join(utils.to_printable(key))
                fp.write(printable_key + ": " + cleartext + '\n')
            else:
                fp.write(cleartext + '\n')
        key[unknown_index] = g.INTERNAL_UNKNOWN
        return