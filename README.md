# Hashing
This is an update to my Final Year Project code that includes SHA2, SHA3 and Keccak as well as multiple digest lengths.

# Running the Program
There are 2 main methods in this project. The main method in the SHA class just runs through all of the different combinations of hashing algorithms and prints the digest of an empty message to the standard out. This is just a test to make sure that all of the hashing algorithms are running.
The second main method is in the HASH class. In theory this is where the program would actually start. It reads arguments from the command line and generates the required digest where the arguments set the algorithm to use, wordlength and digest length. As you can probably tell from the empty function the file hashing has not been implemented yet.

# SHA
This is a wrapper class for all of the hashing functions. The basic algorithm for the hashing function is to initialize the sha object, update the object with data until there is no more and then get the hash from the sha object. Each object can be used for multiple hashes of the same digest length, the reset method is called everytime you retrieve the hash from the object.

# SHA2
SHA2 now includes digest lengths of 224, 256, 384, 512. The code is divided into 4 classes, one for each digest length. Digest 224 is included in the 256 file and Digest 384 is included in the 512 file as seperate classes. These smaller digests are similar to the longer classes except that they use difference constants.

# KECCAK
There are two versions of the Keccak algorithm. One that uses 32 bit words and one that uses 64 bit words. All the calculations for the variables are included in the code to make it more understandable. Also the absorb and squeeze functions are seperate from the process buffer and get hash functions for the same reason. You could retrieve more than the set amount of bytes from the state using the squeeze function instead of the get hash function.
I could not find test vectors for Keccak-f[800] so I can not guantee the correctness (yet!)

# SHA3
As of April 2014 NIST updated the standard and as a result SHA3 and Keccak produce different digest values. For hashing the message is appended with bits 01 before padding is added. For extended output the message is appended with bits 11 but this implementation does not implement extended output.
Also the SHA3 standard is for the Keccak implemented with 64 bit words but both 64 bit and 32 bit are included here.

# TO DO
- find Test Vectors for SHA3
- fix SHA2 512 so messagelength2 is used
- add the read from file update method
