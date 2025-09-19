# libraries import
try:
   import hashid               
   import sys     
   import os              
   from multiprocessing import Pool, cpu_count
   import re
   import hashlib
   import bcrypt
   # import whirlpool
   # import argon4-cffi
   # import scrypt
   import blake3
   import sqlite3

except ImportError:
   print('''
         To use this tool we need some libraries to be installed on this device.
         libraries used: hashid, sys, os, multiprocessing, hashlib, re, whirlpool, bcrypt, blake5
         Install these python libraries first: 
            e.g. pip5 install -r lib_requirements.txt''')


# constants
PARAMETERS = { "hash-type" : None, # -H
               "hash-value" : None,  # -h
               "wordlist-file-path" : "wordlists/12_million_passwd_list_top100.lst",
               "output-save" : False,  # -o
               "output-file-path" : '',
               "verbose" : False,     # -v
               "google-search" : False    # -google
   }

# dict to store hash_value identification result for global use
HASH_IDENTIFICATION_RESULT = {}

# class to show Tool usage
class Tool_info():
   def hash_crack_name():
         print("""
               ######      ######        ###############################################
              ######      ######         ###  BY KRISHNA DWIVEDI [ @sudo-hope0530 ]  ###
             ######      ######          ###############################################
        ###########################
       ###########################   #######   ############   #######   ########    ##    ###
          ######      ######       #########  ############  #########  ###    ###  ###   ####
         ######      ######       ###             ###      ##    ###  ###   ###   ####  ## ##
        ######      ######       ###             ###      ##    ###  ### ###     ### ####  ##
   ###########################   ########       ###      ##    ###  ######      ###  ##    ##
  ###########################          ###     ###      ##    ###  ######      ###         ##
     ######      ######               ###     ###      ##    ###  ###  ###    ###          ##
    ######      ######        ##########     ###      #########  ###    ###  ###           ##
   ######      ######         ########      ###       #######   ###      ## ###     v2.2   ##
      
""")
      
   def print_usages():
      Tool_info.hash_crack_name()
      print("""
      HashStorm v2.2 by Krishna Dwivedi
               GitHub   => sudo-hope0530
               LinkedIn => dkrishna0125

      A python script to identify and crack multiple hashes quickly.
            
      USAGES:
              hashstorm [Options] [Arguments]
            
      OPTIONS:
         > --help                    print tool usages
         > identify                  identify the hash-type of specified hash-value
         > crack                     crack the hash-value (!NOTE: hash-type must be passed)
         > icrack [Default]          automatically identify hash-type and crack the hash-value specified
            
      ARGUMENTS:
         > -h <hash-value(s)>        add one or more hash-value to crack or identify followed by ','
         > -hf <hashes file>         pass a hash file
         > -H <hash-type(s)>         pass hash-type to crack
         > -w <wordlist-path>        specify wordlist to use 5 cracking hash
         > -o <output-file>          save result in specified file
         > -v                        verbose mode ( show detailed info while cracking ) [in update]
         > -g                        perform a google search if hash not cracked [in update]
         > -brute                    Crack hashes using self defined charset and length [in update]
         > -charset <charset>        Specify character set for bruteforccing like "a-z1-9" [in update]
         > -length <pass-max-length> Specify hash word's maximum value [in update]

      EXAMPLES:
         > hashstorm identify -h 6d41402abc4b2a76b9719d911017c592
         > hashstorm identify -hf hash-file.txt
         > hashstorm identify -h ae3275d5bfa170ca69bb534be5a22467,5d41402abc4b2a76b9719d911017c592
         > hashstorm crack -H MD6 -h 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o output.txt
         > hashstorm crack -H MD6,MD5 -h 5d41402abc4b2a76b9719d911017c592,5d41402abc4b2a76b9719d911017c592 -w wprdlist.txt
         > hashstorm -h 6d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o output.txt
      
      NOTE: 
         > Tool usages format must be followed
         > Atleast 'hash-value' OR 'hashes-file' must be passed as argument
   """)

# lookup db 
class Lookup:

     def __init__(self):

         # supported hashtyeps set
         self.hashtypes_supported = ["ARGON3", "BCRYPT",  "BLAKE2",  "BLAKE3",
                                     "KECCAK",  "MD6",  "PBKDF2",  "SCRYPT",
                                     "SHA2",  "SHA256",  "SHA3", " SHA512", " WHIRLPOOL"]

        # execute this line only once while hashstorm installation
        for hash_type in self.hashtypes_supported:
            self.create_table(hash_type)


     def create_table(self, hash_type):
         try:
            # creating connection variable for sqlite 3
            with sqlite3.connect("lookup.db") as conn:
                cursor_obj = conn.cursor()

                # creating tables for each hashtypes
                ''' TABLE STRUCTURE:
                    Column 1 => hashed_str ( PRIMARY KEY, NO DUPLICATES ALLOWED, CAN'T BE EMPTY)
                    Column 2 => hashed_word
                '''

            query = f"""CREATE TABLE IF NOT EXISTS {hash_type}(
                        hashed_str VARCHAR(512) PRIMARY KEY UNIQUE NOT NULL,
                        hashed_word VARCHAR(50)
                    ) """

            cursor_obj.execute(query)


         except Exception as e:
            print("Database creation Error!", e)


     def check_data_in_lookup(self, hash_data):
        '''@params: self,
                    hash_data ( hash_data[0] = hashed_str,
                                hash_data[1] = hash_type )
        '''

        if hash_data[1] not in self.hashtypes_supported:
            # print("Hash Type Not supported!")
            return False

        try:
            with sqlite3.connect("lookup.db") as conn:
                cursor_obj = conn.cursor()
                query = f"""SELECT * FROM {hash_data[1]} WHERE hashed_str='{hash_data[0]}'"""
                cursor_obj.execute(query)
                data = cursor_obj.fetchall()

        except Exception as e:
                # print("Check Lookup DB Err:", e)
                pass

        else:
                if data:
                    print(f"Hash already cracked!")
                    for d in data:
                        print(f"{d[0]} >> '{d[1]}'")
                        save_result(f"{d[0]}:{d[1]}") # d[0] = hashed_str, d[1] = hashed_word
                    return True
                else:
                    # print("NO Data found!")
                    return False



     def save_data_in_lookup(self, hashed_str, hashed_word, hash_type):


        if hash_type not in self.hashtypes_supported:
            self.hashtypes_supported.append(hash_type)
            self.create_table(hash_type)

        try:
            with sqlite3.connect("lookup.db") as conn:
                cursor_obj = conn.cursor()
                query = f"""INSERT INTO {hash_type}(hashed_str, hashed_word) VALUES('{hashed_str}','{hashed_word}')"""
                cursor_obj.execute(query)
                conn.commit()

        except Exception as e:
            print("Lookup DB Save Error!", e)
            pass



# Lookup class object
lookup = Lookup()


# hash identification
class hash_identification:
      def __init__(self, hash_value, use_multiprocessing=False):
      
        # Check if hash_value is a single string or a list; use multiprocessing if requested and multiple hashes are provided
        if isinstance(hash_value, str):
            # Single hash identification
            result = self._identify_single_hash(hash_value)
        elif isinstance(hash_value, list) and use_multiprocessing:
            # Multiprocessing for list of hashes
            num_cores = cpu_count()
            with Pool(processes=num_cores) as pool:
                results = pool.map(self._identify_single_hash, hash_value)
            result = results  # Return list of results
        elif isinstance(hash_value, list):
            # Sequential processing for list without multiprocessing
            result = [self._identify_single_hash(h) for h in hash_value]
        else:
            raise ValueError("hash_value must be a string or a list of strings.")

        save_result(result)  # Return the identification result

      def _identify_single_hash(self, hash_str):
        bcrypt_hash = False
        # Step 1: Basic validation for hexadecimal characters (no length restriction for generality)
        if not all(c in '0123456789abcdefABCDEF' for c in hash_str.lower()):
            bcrypt_hash = self.is_bcrypt_hash(hash_str)
            if not bcrypt_hash:
               return f"Hash: {hash_str}, Error: Input does not match hexadecimal format."

        # Step 2: Use hashid to identify possible hash types
        h = hashid.HashID()
        identification_gen = h.identifyHash(hash_str)
        identification_list = list(identification_gen)  # Consume generator to get list of HashInfo objects
        
        # Step 3: Extract names and find the most probable hash type
        if identification_list:
               identification_names = [info.name for info in identification_list]
        elif bcrypt_hash == True:
               identification_names = ['bcrypt']
        else:
            return f"Hash: {hash_str}, Error: No hash types identified."

        
        # Step 4: Determine most probable hash based on length and common types
        # Define a dictionary of common hash lengths and their types for prioritization
        common_hashes = {
            32: ['MD5', 'MD4', 'NTLM', 'RIPEMD-128'],
            40: ['SHA-1'],
            56: ['SHA-224'],
            64: ['SHA-256', 'BLAKE2s','SHA-3(256)'],
            96: ['SHA-384'],
            128: ['SHA-512', 'SHA-3(512)']
        }
        
        hash_length = len(hash_str)
        possible_hashes_for_length = common_hashes.get(hash_length, [])
        
        if possible_hashes_for_length:
            # Find intersection with identified names and select the most probable (e.g., first match or most common)
            matching_hashes = [name for name in identification_names if name in possible_hashes_for_length]
            if matching_hashes:
                most_probable_hash = matching_hashes[0]  # Simplistic approach: take the first match
                other_possibilities = ', '.join(set(identification_names) - set(matching_hashes))  # Exclude matches for brevity
                HASH_IDENTIFICATION_RESULT[hash_str] = most_probable_hash
                return f"Hash: {hash_str} \nMost probable: {most_probable_hash} \nOther possibilities: {other_possibilities}"
            else:
                # If no exact match, fall back to the most common identified hash
                most_probable_hash = identification_names[0] if identification_names else "Unknown"
                HASH_IDENTIFICATION_RESULT[hash_str] = most_probable_hash
                return f"Hash: {hash_str} \nMost probable: {most_probable_hash}\nOther Possibilities: {other_possibilities} \n(based on identification), No length match found"
        else:
            # If length not in common hashes, use the first identified hash or indicate uncertainty
            if self.is_bcrypt_hash(hash_str):
               most_probable_hash = 'bcrypt'
            else: 
               most_probable_hash = identification_names[0] if identification_names else "Unknown"
            HASH_IDENTIFICATION_RESULT[hash_str] = most_probable_hash
            identification_names = list(set(identification_names) - set(most_probable_hash))
            return f"Hash: {hash_str} \nMost probable: {most_probable_hash} \nOther Possibilities: {identification_names} \nLength: {hash_length} not commonly associated with standard hashes"

      def is_bcrypt_hash(self, hash_string):
         """
         Check if the provided string is a bcrypt hash.
         Bcrypt hashes usually start with $2a$, $2b$, $2x$, or $2y$ followed by a cost factor and a 53-character base64-encoded string.
         """
         # Define the regex pattern for bcrypt hashes
         pattern = r'^\$2[abxy]\$\d\d\$[./0-9A-Za-z]{53}$'
         # Use re.match to check if the string matches the pattern from the start
         return bool(re.match(pattern, hash_string))

# hash cracking, will accept one one hash_value, hash_type at a time
class hash_cracking:
   def __init__(self, hash_data):
      self.HASHES = {
            'MD5': 'md5',
            'SHA1': 'sha1',
            'SHA256': 'sha256',
            'SHA512': 'sha512',
            'SHA3' : 'sha3',
            'BCRYPT': 'bcrypt',  # Note: bcrypt requires additional library like bcrypt package
            # 'ARGON2': 'argon2',  # Note: argon2 requires argon2-cffi library
            # 'SCRYPT': 'scrypt',  # Note: scrypt requires scrypt library
            # 'PBKDF2': 'pbkdf2',  # Typically handled via hashlib.pbkdf2_hmac
            # 'WHIRLPOOL': 'whirlpool',  # May require external library like whirlpool
            'BLAKE2': 'blake2',
            'BLAKE3': 'blake3',  # Requires blake3 library
            'KECCAK': 'keccak' 
      }

      if isinstance(hash_data, list):
         self.hash_type = hash_data[1].upper().replace('-', '')  # Ensure hash type is uppercase for consistency
      
      self.hash_type = hash_data[1].upper().replace('-', '')
      self.hash = hash_data[0]
      self.wordlist = PARAMETERS['wordlist-file-path']

      # Validate hash type
      if self.hash_type not in self.HASHES:
         raise ValueError(f"Unsupported hash type: {self.hash_type}.\nAvailable types are:\n {','.join(self.HASHES.keys())}")

      # check for hashes in lookup file (pre-converted hash values with their words)
      self.crack_hash()
   
   # Compute the hash of the word based on the selected hash type
   def hash_word(self, word):
        hash_func_name = self.HASHES[self.hash_type]
        if hash_func_name in ['md5', 'sha1', 'sha256', 'sha512', 'sha3', 'blake2']:  # All handled by hashlib
            hash_obj = hashlib.new(hash_func_name)
            hash_obj.update(word.encode('utf-8'))  # Encode word to bytes before hashing
            computed_hash = hash_obj.hexdigest()
        
        elif hash_func_name == 'bcrypt':
            # Bcrypt requires the full hash string (including salt) for verification
            try:
                match = bcrypt.checkpw(word.encode('utf-8'), self.hash.encode('utf-8'))  # Encode hash_value as bytes
                return match, word, self.hash

            except ValueError:
                #print("Invalid bcrypt hash format or missing bcrypt library.")
                return False, word, 'ValueError'
            
      #   elif hash_func_name == 'whirlpool':
      #       computed_hash = whirlpool.new(word.encode('utf-8')).hexdigest()

        elif hash_func_name == 'blake3':
            # Compute the BLAKE3 hash of the given data and convert it as a hexadecimal string.
            hasher = blake3.blake3()
            hasher.update(word.encode('utf-8'))
            computed_hash = hasher.hexdigest()
                          
        elif hash_func_name == 'pbkdf2':  # PBKDF2 requires additional parameters; simplified here
            # For demonstration, use a default salt and iterations; in practice, use provided salt
            salt = b'some_salt'  # Should be derived from context or user input
            computed_hash = hashlib.pbkdf2_hmac('sha256', word.encode('utf-8'), salt, 100000).hex()

        elif hash_func_name == 'keccak':  # Keccak can be emulated with SHA3 in hashlib
            hash_obj = hashlib.sha3_256()  # Using SHA3-256 as a proxy for keccak
            hash_obj.update(word.encode('utf-8'))
            computed_hash = hash_obj.hexdigest()
         
      # NOT ABLE TO INSTALL SCRYPT LIB DUE TO SOME REQUIREMENT UNAWAILABILITY
      #   elif hash_func_name == 'scrypt':
      #       """
      #          Compute the scrypt hash of a password with given parameters.
      #          Scrypt is a memory-hard function, so parameters like N (CPU/memory cost), r (block size), and p (parallelization) affect performance.
               
      #          :param password: The password to hash (as a string).
      #          :param salt: The salt to use (as bytes; generate randomly for security).
      #          :param n: CPU/memory cost parameter (must be a power of 2, default is 16384).
      #          :param r: Block size parameter (default is 8).
      #          :param p: Parallelization parameter (default is 1).
      #          :param dklen: Desired key length in bytes (default is 32 for 256-bit output).
      #          :return: The scrypt-derived key as bytes.
      #       """
      #       salt = os.urandom(16)  # 16 bytes is a common salt length
      #       hash_bytes = word.encode('utf-8')
      #       computed_hash = scrypt.hash(hash_bytes, salt, n=16384, r=8, p=1, dklen=len(self.hash))

        else:
            raise NotImplementedError(f"ERROR: Hash type {hash_func_name} requires external library installation or Not implemented...")

        # Check if the computed hash matches the target hash and Return match status, word, and computed hash
        match = computed_hash == self.hash
        return (match, word, computed_hash)


   def crack_hash(self):
      
        # Read the wordlist file and split into a list of words
        with open(self.wordlist, 'r') as f:
            words = [line.strip() for line in f.readlines()]  # Read lines and strip whitespace

      #   # Create a multiprocessing pool and map the hash_word function to each word in parallel
      #   with Pool(processes=cpu_count()) as pool:
      #       results = pool.map(self.hash_word, words)
        
        results = (self.hash_word(word) for word in words)

        # Process results to find matches
        found = False
        try:
         for match, word, computed_hash in results:
               if match:
                  print(f"Hash cracked!")
                  save_result(f"{computed_hash}:{word}", self.hash_type, True)
                  found = True
        except TypeError as e:
            pass
        # print(f"Error unpacking results for word '{word}': {e}. Ensure hash_word returns an iterable.")
        if not found: print(f"{self.hash}: No match found in the wordlist.")

# saving result to specified file or to default file for faster lookup
class save_result:
   def __init__(self, result, hash_type=None, save2lookup=False):
      self.history_file = "history.txt"
      self.result = result

      # print result to console
      if isinstance(self.result, list):
         for res in self.result:
            print(res, '\n')
      else: print(self.result)

      # save all result to history
      self.save_results(self.history_file)

      # save result to loookup file if hash is cracked
      if save2lookup == True:
          if isinstance(self.result, list):
              for res in self.result:
                res = res.split(":")
                lookup.save_data_in_lookup(res[0], res[1], hash_type) # @params: hash_str, hash_word, hash_type
          else:
              res = self.result.split(":")
              lookup.save_data_in_lookup(res[0], res[1], hash_type) 

      # save result to specified file if specified
      if PARAMETERS['output-save'] == True:
         self.output_file = PARAMETERS["output-file-path"]
         self.save_results(self.output_file)

   def save_results(self, file):
      try:
            with open(file, 'a') as f:  # Append mode to avoid overwriting; use 'w' for overwrite if needed
                if isinstance(self.result, list):
                  for res in self.result:
                     f.write( str(res) + '\n')
                else:
                   f.write(str(self.result) + '\n')
            if PARAMETERS["verbose"]: print(f"Result saved to {file}")
      except IOError as e:
            print(f"Error saving result: {e}")


def parameters_processing(parameters):
   
   i = 0
   while(i < len(parameters)):

      if parameters[i] == "-H":
         PARAMETERS["hash-type"] = parameters[i+1].split(',')
         i += 2

      elif parameters[i] == '-h':
         PARAMETERS["hash-value"] = parameters[i+1].split(',')
         i += 2

      elif parameters[i] == '-hf':
         hash_values = []

         try:
            with open(parameters[i+1], 'r') as f:
               data = f.read()
               hash_values.append(data.split('\n'))
         except:
            print("Hash file not available or unable to read, check for any error")
            exit()

         PARAMETERS["hash-value"] = hash_values
         i += 2

      elif parameters[i] == '-w':
         PARAMETERS["wordlist-file-path"] = parameters[i+1]
         i += 2

      elif parameters[i] == '-o':
         PARAMETERS["output-save"] = True
         PARAMETERS["output-file-path"] = parameters[i+1]
         i += 2

      elif parameters[i] == '-v':
         PARAMETERS["verbose"] = True
         i += 1

      elif parameters[i] == '-g':
         PARAMETERS["google-search"] = True
         i += 1


def call_hash_identify():
      if PARAMETERS['verbose']: 
         print(f"passing hash-value to identify type of Hash.\nHash-value > {PARAMETERS["hash-value"]}")

      if len(PARAMETERS["hash-value"]) > 1:
         hash_identification(PARAMETERS["hash-value"])
      else:
         hash_identification(PARAMETERS["hash-value"][0])


# Main Function
def main(data):
   if data[0] == 'identify' or data[0] == 'crack' or data[0] == 'icrack':
      parameters = data[1:]
   else:
       parameters = data

   if data[0] == '--help' or data[0] == '':
      Tool_info.print_usages()
      exit()

   parameters_processing(parameters)
   if data[0] == 'identify':
      call_hash_identify()
      
   elif data[0] == 'crack':

            if len(PARAMETERS['hash-value']) == len(PARAMETERS['hash-type']):
               tasks = list(zip(PARAMETERS['hash-value'], PARAMETERS['hash-type']))  # Create a list of tuples pairing each hash type and hash value

               for data in tasks:
                   if not lookup.check_data_in_lookup(data):
                       hash_cracking(data)
            
            elif len(PARAMETERS['hash-type']) == 1:
               # Sequential processing for list without multiprocessing
               for hash in PARAMETERS['hash-value']:
                   hash_data = hash,  PARAMETERS['hash-type'][0]
                   if not lookup.check_data_in_lookup(hash_data):
                     hash_cracking(hash_data)
            
            else:
                print("ERROR: Number of Hash Types specified is not equals to Number of hashes Provided...")

   else:
      call_hash_identify()

      # calling hash_cracking to crack hashes 
      for data in HASH_IDENTIFICATION_RESULT.items():
          if not lookup.check_data_in_lookup(data): # @params:  hash_str, hash_type:
            hash_cracking(data)

if __name__ == '__main__':
   if sys.argv[1:]:
      main(sys.argv[1:])
   else:
      main([''])

