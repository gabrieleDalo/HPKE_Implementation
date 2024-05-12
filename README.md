# HPKE_Implementation

Questa repository contiene gli script per testare il funzionamento di 2 implementazioni del protocollo HPKE (Hybrid Public Key Encryption), una della libreria pyhpke ed una di OpenSSL. \
Per la libreria pyhpke di Python, dopo averla installata, è sufficiente eseguire lo script HPKE_Base.py \
Per la libreria di OpenSSL, è necessario aver prima installato almeno la versione 3.2 di OpenSSL ed eseguire lo script main.c presente nella cartella HPKE_OpenSSL (se fatto da terminale potrebbe dover essere necessario compilare lo script ad es. con clang HPKE_Base.c cJSON.c -o program -lcrypto ed eseguirlo con ./program (su MacOS)).

Se si vuole invece testare l'interoperabilità delle 2 librerie si distinguono 2 casi:
- Sender pyhpke e receiver OpenSSL: è sufficiente eseguire lo script HPKE_Interoperability.c e tutti i dati necessari verrano presi dai test_vectors
- Sender OpenSSL e receiver pyhpke: è necessario eseguire prima lo script HPKE_Interoperability.c e spostare i file .bin che verranno generati all'interno della stessa cartella dello script HPKE_Interoperability.py e poi eseguire quest'ultimo (chiaramente le modalità HPKE da specificare dovranno essere le stesse per entrambe le librerie altrimenti il test fallirà)
