# HashStorm: A Python Tool for Hash Identification and Cracking

![HashStorm Banner](https://sudohopex.github.io/pages/project-docs/asset/hashstorm-banner-v2.png)

#### HashStorm is a Python tool designed to identify and crack multiple hash types efficiently, providing CLI for tasks like hash type identification, cracking using wordlists & more. 

## Features
- Identify over **220 hash types** accurately.
- **Auto identify** hash types for hash value(s).
- Supports **Batch processing** via both files and command-line arguments.
- **Saves output** to history, lookup.db (prevent cracking duplicates), and specified file.
- Cross-platform compatibility, as written in Python.
- **Easy to install** just by executing `setup.sh`
- **Easy to launch** using `hashstorm` command ( no need to run like python hashstorm.py )
- Utilizes **python virtual environment** for system protection.
- Everything **configured automatically**.
- Clean look and response.
- **icrack Mode [Default]:** simplifies workflows by handling both identification and cracking automatically.

## Future Updates
- Cracks hashes via brute-force methods.
- **Google Search Mode**: for searching uncracked hash values.
- **Verbose Mode**: for detailed working description

## Installation

1. **Clone the repository:**
  ```
    git clone https://github.com/sudohopex/Hashstorm.git
  ```

2. **Run Command:** 
  ```
    sudo bash HashStorm/setup.sh
  ```

3. **Hurray! HashStorm Installation done, Now we can storm Hashes**

## Usage
Run `hashstorm --help` to display below usage information.

```
USAGES:   hashstorm [Options] [Arguments]
      
OPTIONS:
   > --help                   print tool usages
   > identify                 identify the hash-type of specified hash-value
   > crack                    crack the hash-value (!NOTE: hash-type must be passed)
   > icrack [Default]         automatically identify hash-type and crack the hash-value specified
      
ARGUMENTS:
   > -h <hash-value(s)>       add one or more hash-value to crack or identify followed by ','
   > -hf <hashes file>        pass a hash file
   > -H <hash-type(s)>        pass hash-type to crack
   > -w <wordlist-path>       specify wordlist to use for cracking hash
   > -o <output-file>         save result in specified file
   > -v                       verbose mode ( show detailed info while cracking ) [in update]
   > -g                       perform a google search if hash not cracked [in update]
   > -brute                   crack hashes using self defined charset and length [in update]

EXAMPLES:
   > hashstorm identify -h 5d41402abc4b2a76b9719d911017c592
   > hashstorm identify -hf hash-file.txt
   > hashstorm identify -h ae3274d5bfa170ca69bb534be5a22467,5d41402abc4b2a76b9719d911017c592
   > hashstorm crack -H MD5 -h 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o output.txt
   > hashstorm crack -H MD5,MD5 -h 5d41402abc4b2a76b9719d911017c592,5d41402abc4b2a76b9719d911017c592 -w wordlist.txt
   > hashstorm -h 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o output.txt
   
NOTE: 
   > Tool usages format must be followed
   > Atleast 'hash-value' OR 'hashes-file' must be passed as argument
```

## Contributing
Contributions to HashStorm are encouraged to improve features, fix bugs, or add support for more hash types. 
To contribute:
- Fork the Repository.
- Create a new branch for your changes.
- Submit a pull request with a detailed description of the changes.
- Before contributing, test your modifications thoroughly.

## LICENSE
- This project is licensed under MIT. See [LICENSE](LICENSE) file for more info.
- It is intended for educational purposes, ethical hacking, or penetration testing only.

## Acknowledgement
- Inspired by hashid tool in kali for hash identification
- Thanks to resources like HashID module in python for hash identification techniques.

### Thanks for having a look over HashStorm Tool
