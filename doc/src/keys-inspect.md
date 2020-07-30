Once our OpenPGP CA database is populated with data, we may want to
inspect that data.

In this chapter we assume that our OpenPGP CA instance contains the two users
Alice and Bob.

### Listing all users

We can inspect the state of all users in our OpenPGP CA instance like this:

`$ openpgp-ca -d example.oca user list`

```
usercert for 'Alice Adams'
fingerprint F27CB2E92C3E01DA1C656FB21758251C75E25DDD
user cert (or subkey) signed by CA: true
user cert has tsigned CA: true
- email alice@example.org
 no expiration date is set for this certificate
 1 revocation certificate(s) available

usercert for 'Bob Baker'
fingerprint 0EE935F56AC4381E007370E956A10EB1ABED2321
user cert (or subkey) signed by CA: true
user cert has tsigned CA: true
- email bob@example.org
 expires: 12/08/2020
 1 revocation certificate(s) available
```

### Exporting keys

Export an individual user key (the public key is
printed to stdout):

`$ openpgp-ca -d example.oca user export -e alice@example.org`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: F27C B2E9 2C3E 01DA 1C65  6FB2 1758 251C 75E2 5DDD
Comment: Alice Adams <alice@example.org>

xjMEXv8FyxYJKwYBBAHaRw8BAQdADeFuwt/+AtkUWNMxmi/nKwpF/Nnf76QX7qNi
v2JWUxjCfgQfFgoADwWCXv8FywIVCgKbAQIeAQAhCRAXWCUcdeJd3RYhBPJ8suks
[...]
6Sw+AdocZW+yF1glHHXiXd1lcgD/byHHRjsKEux07gYeGUs+MpP4trLr6SL3Gyqf
bRcVqcMA/0RsK9WcWw5ZHmVqCM7OXOu1Fdk81xqVJVggKhdgMwcD
=TFLi
-----END PGP PUBLIC KEY BLOCK-----
```

To output all public user keys from OpenPGP CA to stdout:

`$ openpgp-ca -d example.oca user export`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: F27C B2E9 2C3E 01DA 1C65  6FB2 1758 251C 75E2 5DDD
Comment: Alice Adams <alice@example.org>

xjMEXv8FyxYJKwYBBAHaRw8BAQdADeFuwt/+AtkUWNMxmi/nKwpF/Nnf76QX7qNi
v2JWUxjCfgQfFgoADwWCXv8FywIVCgKbAQIeAQAhCRAXWCUcdeJd3RYhBPJ8suks
[...]
6Sw+AdocZW+yF1glHHXiXd1lcgD/byHHRjsKEux07gYeGUs+MpP4trLr6SL3Gyqf
bRcVqcMA/0RsK9WcWw5ZHmVqCM7OXOu1Fdk81xqVJVggKhdgMwcD
=TFLi
-----END PGP PUBLIC KEY BLOCK-----

-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: 0EE9 35F5 6AC4 381E 0073  70E9 56A1 0EB1 ABED 2321
Comment: Bob Baker <bob@example.org>

xsDNBF7/BgMBDADGqq+EenMXzetD1mO2L2APhuOKzOQRcJrztXRly6gd4asjx50T
X2RH0D/8ahDuisLF7//HcwYUntH/BFG6Tvxf703Bg4+Uo+8+s6+9gZ/9yEH1yf/r
[...]
wfGODYtIstlqFbesf1m8WRneB13FlzFxngM3+6Oq4fu/XOVJNlo5ZMEBShkrpU25
75YuEbrUY++9El5KuIHzCmf73NFagLszXfZjb261+lzGQEb0ln3LTVZL
=vqMk
-----END PGP PUBLIC KEY BLOCK-----
```

To output the public key of our OpenPGP CA instance:

`$ openpgp-ca -d example.oca ca export`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: 138C 1D33 E462 4BFB CCC4  0C20 3EA1 01D6 8A4B 92F5
Comment: OpenPGP CA <openpgp-ca@example.org>

xjMEXv8FxxYJKwYBBAHaRw8BAQdAPULzjk6Hr+0PahT42WxfaDSgHfqPOmNLB4q9
fVC1g9jCfgQfFgoADwWCXv8FxwIVCgKbAQIeAQAhCRA+oQHWikuS9RYhBBOMHTPk
[...]
IvO+f3pFqLZEzoFJXUm4oxr7CXADfWUgQj7yAtIa3ZUA/ApZKKmp0E/S8VGjhe0Q
Ni+wbKBJIe94AE3A6ZggKd4B
=vt2K
-----END PGP PUBLIC KEY BLOCK-----
```

### Checking certifications

To check if all keys are mutually certified:

- All user keys have tsigned the CA key, and
- the CA key has certified all user keys.
 
`$ openpgp-ca -d example.oca user check sigs`

```
Checked 2 certificates, 2 of them had good certifications in both directions.
```

### Checking expiry of user keys
 
To get an overview of the expiry of user keys:
 
`$ openpgp-ca -d example.oca user check expiry`

```
name Alice Adams, fingerprint F27CB2E92C3E01DA1C656FB21758251C75E25DDD
 no expiration date is set for this certificate

name Bob Baker, fingerprint 0EE935F56AC4381E007370E956A10EB1ABED2321
 expires: 12/08/2020
```

To check if any user keys will expire within a specified number of days:
 
`$ openpgp-ca -d example.oca user check expiry --days 60`

```
name Alice Adams, fingerprint F27CB2E92C3E01DA1C656FB21758251C75E25DDD
 no expiration date is set for this certificate

name Bob Baker, fingerprint 0EE935F56AC4381E007370E956A10EB1ABED2321
 expires: 12/08/2020
 user cert EXPIRED/EXPIRING!
```

This output shows us that Bob's key will have expired 60 days from now.
