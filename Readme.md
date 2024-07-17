# Description
An XOR cryptanalysis tool.

## Features
xor_freqxor is capable of:
- Performing known plaintext attacks
- Brute-forcing unknown key characters
- Figuring out key length by using IoC (currently only if cleartext is in alphabet [A-Z])
- Finding most likely plaintext by using frequency analysis after key length has been determined (currently only if plaintext is in alphabet [A-Z])
- Combining known plaintext attack with frequency analysis (currently only if plaintext is in alphabet [A-Z])

# Installation
Requires Python 3.9.0 or above (you can't strongly type like `key:[str]` prior to 3.9 without having to import stuff...)
- Check your version: `python --version`
- If < 3.9, update. Here are some examples which *may* work for you:
  - **Windows**
    - Easiest way is probably to run the official installer: https://www.python.org/downloads/
    - Tough luck for Windows 7 users, as official python releases stopped supporting it from 3.9 and onwards. There still exist unofficial python versions 3.9 and above with Windows 7 support however.
  - **Linux**
    - `sudo apt install python3`

# Usage
Here are some examples to get you started:
- Unknown key length (`-l 0`), partially known plaintext (3rd & 4th chars are "co"):\
`python xor_freqxor.py -l 0 -k "**co*************************" -c "22451a040b0d0a0c174b161c08171c1f45100503161908181f0c160544"`
- Only knowledge is that plaintext consists of characters [A-Z] (we specify this with `-a`):\
`python xor_freqxor.py -l 0 -a uppercase -c "702126202633772633242c7e202b283c3e6c2c303937633c31283335762b2220236e3126383d2c6b2c3a382e732731383d2c6c303d283174362d20203077373c392a7e3d28383d2c6f2d3921247e3d27353a3c752d3b39307e3436283c3e7231263935762720293d2c6c223a3f2c652026373737792a31292d792737332b376a213c2a2a633a3732312c6a3730293b78262b20243c7a2130233576212d2436"`
- Use `-h` for more info on usage.

# Scenarios
Have a crack at cracking some ciphertexts, try out the scenarios in `scenarios.txt`!
