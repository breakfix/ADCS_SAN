# ADCS_SAN.py

Request a certificate from AD CS using a user supplied Subject Alternative Name (SAN).

Makes use of existing code added to SecureAuthCorp's Impacket library by the below authors as well as the attacks and techniques outline by SpecterOps in their paper [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf).

Alberto Solino (@agsolino)
Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
Ex Android Dev (@ExAndroidDev)

# Usage

    python ADCS_SAN.py -s http://ADCS-Server -u ADusername -p 'password' -d ADdomain -t template -i impersonate_user -o 'pfx password'
