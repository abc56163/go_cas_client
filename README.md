# go_cas_client
This is a cas client that can be used for sso verification

Principle:

1. open the home page to verify whether the cookie contains session
2. if there is an encrypted string, decrypt the encrypted string, if not or decryption fails, jump to the login page. 3.
3. if not, then jump to the login page, login according to the callback address to get a ticket
4. according to the ticket authentication (authentication failed to jump to re-login), get the information, and then encrypt the information, stored in the cookie

