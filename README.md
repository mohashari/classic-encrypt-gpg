# Classic Encrypt GPG

## Generate GPG Key 
``` bash
gpg --gen-key
 ```
 ## Check list Key
 ``` bash
  gpg --list-secret-key
 ```
 ## Export GPG publickey armor
 ```
  gpg --output public.gpg --armor --export <receipt email>
 ```

 ## Export GPG sercretkey armor

 ```
 gpg --output private.gpg --armor --export-secret-key <receipt email>
 ```

 ## Encrypt File to GPG
 ```
gpg --output myfile.txt.gpg --encrypt --recipient <receipt email> myfile.txt
 ```

 ## Decrypt File GPG

```
gpg --output myfile.txt --decrypt myfile.txt.gpg
```