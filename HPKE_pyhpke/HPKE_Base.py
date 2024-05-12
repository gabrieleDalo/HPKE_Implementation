import json
import timeit
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface, KEMKeyPair
from pyhpke.kem import KEM
from pyhpke.kem_key import KEMKey


f = open('test_vectors.json')
data = json.load(f)
n_repeat = 10000         # N° of times the experiment must be performed for each mode
total_time = 0

for i in range(4):
    print_on = True             # Print enabled only for the first cicle
    for j in range(n_repeat):
        test = "test" + str(i+1)
        test_data = data[test]

        # Extract all the data from test_vectors in the correct format
        mode = test_data["mode"]
        if print_on:
            print("Mode: " + str(mode))
        
        kemID = test_data["kem_id"] if "kem_id" in test_data else  16
        kdfID = test_data["kdf_id"] if "kdf_id" in test_data else 1
        aeadID = test_data["aead_id"] if "aead_id" in test_data else 3
    
        info = bytes.fromhex(test_data["info"]) if "info" in test_data else b""
        psk = bytes.fromhex(test_data["psk"]) if "psk" in test_data else b""
        psk_id = bytes.fromhex(test_data["psk_id"]) if "psk_id" in test_data else b""
        aad = bytes.fromhex(test_data["aad"]) if "aad" in test_data else b""
        pt = bytes.fromhex(test_data["pt"]) if "pt" in test_data else ""
        ct = bytes.fromhex(test_data["ct"]) if "ct" in test_data else ""
        enc = bytes.fromhex(test_data["enc"]) if "enc" in test_data else ""
        ikme = bytes.fromhex(test_data["ikmE"])
        ikmr = bytes.fromhex(test_data["ikmR"])

        start = timeit.default_timer()

        # Create the suite, a structure that holds identifiers for the algorithms used for KEM, KDF and AEAD operations
        suite = CipherSuite.new(
            KEMId(kemID),
            KDFId(kdfID),
            AEADId(aeadID)
        )

        total_time = total_time + (timeit.default_timer() - start) * 1000

        # Get keys from test_vectors and check if they are the same generated with the pyhpke library from the corresponding ikm
        pke = suite.kem.deserialize_public_key(bytes.fromhex(test_data["pkEm"]))
        ske = suite.kem.deserialize_private_key(bytes.fromhex(test_data["skEm"]))
        eks = KEMKeyPair(ske, pke)

        # Check ephemereal keys
        ikme_keypair = suite.kem.derive_key_pair(ikme)
        if ikme_keypair.private_key.to_private_bytes() != ske.to_private_bytes():
            print("Error in key generation")
            break
        if ikme_keypair.public_key.to_public_bytes() != pke.to_public_bytes():
            print("Error in key generation")
            break
        
        pkr = suite.kem.deserialize_public_key(bytes.fromhex(test_data["pkRm"]))
        skr = suite.kem.deserialize_private_key(bytes.fromhex(test_data["skRm"]))

        # Check receiver keys
        ikmr_keypair = suite.kem.derive_key_pair(ikmr)
        if ikmr_keypair.private_key.to_private_bytes() != skr.to_private_bytes():
            print("Error in key generation")
            break
        if ikmr_keypair.public_key.to_public_bytes() != pkr.to_public_bytes():
            print("Error in key generation")
            break
    
        sks = None
        pks = None

        # Check sender keys, only if they are present, depending on the mode
        if "skSm" in test_data and "pkSm" in test_data:
            ikms = bytes.fromhex(test_data["ikmS"])
            sks = suite.kem.deserialize_private_key(bytes.fromhex(test_data["skSm"]))
            pks = suite.kem.deserialize_public_key(bytes.fromhex(test_data["pkSm"]))

            ikms_keypair = suite.kem.derive_key_pair(ikms)
            if ikms_keypair.private_key.to_private_bytes() != sks.to_private_bytes():
                print("Error in key generation")
                break
            if ikms_keypair.public_key.to_public_bytes() != pks.to_public_bytes():
                print("Error in key generation")
                break
        
        start = timeit.default_timer()
    
        # Create the context, that maintains internal state as HPKE operations are carried out
        # Separated context must be used for the sender and receiver
        # From the sender context we retrive the enc
        enc_key, sending = suite.create_sender_context(pkr, info, sks, psk, psk_id, eks)
        if enc_key != enc:              # Check if the enc generated is the same present in the test_vectors
            print("Different enc")
            break
        
        # Sealing the plaintext using the aad
        ciphertext = sending.seal(pt, aad)
        pt = pt.decode()        # Decode the plaintext to utf-8 format, so we can print it later

        if ciphertext != ct:    # Check if the ciphertext generated is the same present in the test_vectors
            print("Different ciphertext")
            break

        receiving = suite.create_recipient_context(enc_key, skr, info, pks, psk, psk_id)
        plaintext = receiving.open(ciphertext, aad).decode()
        
        if print_on:
            print("Original plaintext: "+plaintext)
            print("Deciphered plaintext: "+pt)
            print_on = False
        
        if plaintext != pt:
           print("Error in decryption")

        total_time = total_time + (timeit.default_timer() - start) * 1000      

    print("Total execution time in milliseconds: ", total_time/n_repeat)    # We do a mean of the execution time registered at each iteration
    print("")
    print_on = True
    total_time = 0
f.close()