# HPKE_Implementation

Questa repository contiene gli script per testare il funzionamento di 2 implementazioni del protocollo HPKE (Hybrid Public Key Encryption), una della libreria pyhpke ed una di OpenSSL. \
Per la libreria pyhpke di Python, dopo averla installata, è sufficiente eseguire lo script HPKE_Base.py \
Per la libreria di OpenSSL, è necessario aver prima installato almeno la versione 3.2 di OpenSSL ed eseguire lo script main.c presente nella cartella HPKE_OpenSSL (se fatto da terminale potrebbe dover essere necessario compilare lo script ad es. con clang main.c cJSON.c -o program -lcrypto ed eseguirlo con ./program (su MacOS)).
