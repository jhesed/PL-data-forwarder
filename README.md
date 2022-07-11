# PL-data-forwarder
Forwards data from a CSV file to a PL API that will convert to a database type of storage.

## Flow
1. Retrieve csv file generated by another PL process. 
2. Read the content and encrypt it using a combination of API key and secret.
3. Forward the encrypted data to a centralized server of database (REST API)
4. Delete the csv file.

## Maintainer

* Jhesed Tacadena
* dev.jhesed@gmail.com

