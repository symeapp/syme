<img src="https://getsyme.com/img/sidebar-logo.png" />
 
Syme
================
A zero-knowledge key architecture and encrypted messaging platform 


### Introduction and motivation

There is currently renewed interest in encrypted communication protocols that are adapted to live communication tools such as instant messaging. However, these protocols are not well suited for persistent communication systems, such as social networks, where users are not necessarily online at the same time. In this paper, we describe a zero-knowledge key infrastructure that uses end-to-end encryption to enable persistent multiparty communication and secure key exchanges on minimally trusted servers and relays. 

### Objectives and assumptions

Our security objectives are to:

1. provide a means for users and servers to establish mutual authentication without communicating password-equivalent data;

2. provide a means for users to securely establish and maintain lists of trusted keys, with mechanisms for adding and revoking keys;

3. and provide a system for multiparty communication of encrypted data that ensures integrity and non-repudiation.

Providing anonymity or forward secrecy is not part of our security objectives. We assume that the members of a group have a mutual interest in keeping their shared data confidential.

### Highlights

#### Cryptographic Primitives

 - **Password-Based Key Derivation Function (PBKDF2)**: PBKDF2 with 10,000 iterations of HMAC-SHA256 is used to derive keys from the user’s master password .
 - **Advanced Encryption Standard in Counter mode with CBC-MAC (AES-CCM)**: the AES-CCM cipher mode is used for symmetric encryption. The CCM mode provides message authentication and confidentiality .
 - **Elliptic Curve Cryptography (ECC)**: ECC and ECDSA with a 384-bit prime are used for encrypting and signing session keys, respectively .

#### Key Exchange Protocols

 - **Secure Remote Password Protocol (SRP)**: user authentication is performed by means of the Secure Remote Password protocol (SRP) . Version 6A of the protocol is used, with 2048-bit group parameters.
 - **Elliptic Curve Diffie-Hellman (ECDH)**: an Elliptic-Curve Diffie Hellman key exchange scheme is used for the transfer of the keypairs between users.

#### Random Number Generation

<!-- - **Salsa20 Pseudo-Random Function**: we use the Salsa20 pseudorandom function for random number generation. -->
 - **Native Sources of Entropy**: our PRNG is seeded exclusively with values retrieve from the Crypto.getRandomValues API, which has access to OS-level sources of entropy.

### Application protocols

#### 4.1 – User Registration

**4.2.1 – Identifier Creation**

The first step in registration is the creation of an identifier (I) for the user. The server verifies that the identifier supplied by the user is available, in which case the client is allowed to proceed with registration.

**4.2.2 – Key Derivation**

The user’s master password, which inputted on registration, is transformed into a 512-bit master key using the PBKDF2 key-derivation function. The output from PBKDF2 is split into two 256-bit keys (K1 and K2). The first 256 bits (K1) are used as the authentication key, while the 256 last bits (K2) are used as the initialization key.

**4.2.3 – Verifier Creation**

The user creates an authentication salt (`s`) and an authentication verifier (`v`) by calculating:

    s = randomBits(128)
    x = H(salt |  H(I |  ":" | K1))
    v = g^x  mod N

The user sends the authentication salt and the authentication verifier to the server, which stores them in the database.

#### 4.2.4 – User Authentication

User authentication is performed by means of the Secure Remote Protocol, as described in Wu, 2002.

#### 4.2.5 – Keyfile Creation

A keyfile (KF) is initialized as an empty data structure, serialized, encrypted with K2 using AES-256-CCM, and then stored on the server. The initialization vector (IV) is changed every time the keyfile is modified.

 
#### 4.3 – Keylist Creation

The client requests a new keylist from the server, which replies with a unique identifier. An entry is created in the keyfile for the new keylist. A set of two 384-bit keypairs (one for encryption, and one for signatures) is generated and inserted into the keylist under the current user’s unique identifier. The new version of the keyfile is then encrypted with K2 and stored on the server.

#### 4.4 – Key Exchange

_**Key exchange procedure**_

![Key encryption](https://getsyme.com/img/paper/key_exchange.png)

In brief, keys are exchanged in a five-step process, which correspond to:

- user A generating an ephemeral keypair, and sending the public key to user B;
 
- user B generating an ephemeral keypair; sending his ephemeral public key to user A; and sending his long-term public keys, encrypted with the ephemeral secret key, to user A;  

- user A decrypting user B’s long-term public keys, broadcasting them to existing group members, and transferring the keylist and the session key history to user B*; 

- user B receiving the keylist and the session key history from A;

- existing group members receiving B’s long-term keypairs and updating their keyfiles.


* In order to grant user B access to messages that were sent prior to his arrival, session keys are transferred during the third step of the keylist transfer process. User A downloads a copy of all existing session keys, decrypts and verifies them, signs them with her own private signature key, and re-encrypts them with B’s public key.


#### 4.5 – Message Exchange

For every message sent, a random 256-bit session key is generated and used to encrypt the message using AES-CCM. The sender then generates encrypted copies of the session key for each keylist member. The sender appends the recipient’s identifier to the key, signs the resulting message, and encrypts using the recipient’s public encryption key. Finally, the session key is destroyed and the sender pushes the encrypted message and the list of keys to the server.

_**Send procedure**_

![Send procedure](https://getsyme.com/img/paper/send.png)

_**Key encryption procedure**_

<img src="https://getsyme.com/img/paper/key_encryption.png" width="581" height="293">

_**Receive procedure**_

![Send procedure](https://getsyme.com/img/paper/send.png)

### Threat Model

This section identifies threats and potential vulnerabilities.

#### 5.1 – User Registration

**5.1.1 – Key Derivation**

- _Compromised password._ Compromise of a user’s password enables an attacker to authenticate as the user and read his keyfile. Since the SRP protocol does not require exchange of password-equivalent data, online interception of a user’s password is not feasible. As stated above, it is not viable to recover the master password through a brute force attack on the password verifier. Attacks at the application level constitute the main threat to password security.

**5.1.2 – Verifier Creation**

- _Compromised verifier._ Compromise of a user’s authentication verifier, through a man-in-the-middle attack or a database vulnerability, may enable two types of attacks: (i) server impersonation and (ii) dictionary attacks against the authentication key. An isolation layer of PBKDF2 between the password and the authentication key deters brute-force attacks and ensures server impersonation cannot function unless the keyfile encryption key or master password is also compromised.

**5.1.2 – User Authentication**

The SRP protocol is used for authentication of users. It is resistant against both passive and active network attacks, and provides perfect forward secrecy for user sessions.

#### 5.2 – Keylist Creation

- _Keylist tampering or loss of integrity._ The use of AES-256 in CCM mode prevents unauthorized manipulation of the keyfile as it travels across the network or while it is stored on the server. 

#### 5.3 – Keylist Transfer

- _Man in the middle attack._ The keylist transfer process is resistant against man in the middle and masquerading attacks, which could lead to interception or substitution of long-term keys. The integrity of exchanged ECDH public keys is protected by mutual authentication through key fingerprints via an outside channel.

- _Key modification attack._ The keylist administrator may tamper with previous message keys during their transfer to a new keylist member. Since the server handles storage of encrypted messages and session keys separately, only omission of message keys is feasible. Forging messages is not possible unless the malicious user also controls the server.

#### 5.4 – Message Exchange

- _Eavesdropping of transmitted information._ Messages contain both the sender’s and the recipient’s unique identifiers. Using SSL for all API calls deters eavesdropping of this data while it is sent over the network. However, the possibility of eavesdropping cannot be excluded in the event that SSL certificates are compromised. 

- _Related key and related IV attacks._ All session keys and initialization vectors are generated using a cryptographically secure pseudo-random number generator (CSPRNG) seeded with native sources of entropy. Under no circumstance is the same key used to encrypt two different pieces of data. Unless the CSPRNG is compromised, related key or related IV attacks are not feasible.

### Concluding Remarks

Addressing the problem of data confidentiality and message authentication in the context of social networks is challenging due to the asynchronous nature of user interactions and the limitations of the browser environment. The zero-knowledge key infrastructure we have put forward is resistant against all known active and passive attacks unless both the server and the client are compromised. Our architecture as it stands neither provides nor precludes forward secrecy. Forward-secure public-key infrastructures remain an area of active research, and promise to be useful in building more resilient asynchronous multiparty message exchange protocols (7).

_______________

#### References

(1) Moscaritolo V., Belvin G. and Zimmerman P. Silent Circle Instant Messaging Protocol (SCIMP). https://silentcircle.com/static/download/SCIMP%20paper.pdf 

(2) Kobeissi N. Cryptocat : Adopting Accessibility and Ease of Use as Security Properties. June 2013. http://arxiv.org/abs/1306.5156

(3) Turan M., Barker E, Burr W. and Chen L. Special Publication 800-132 : Recommendation for Password-Based Key Derivation. December 2010. http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

(4) Dworking, M. Special Publication 800-38C : Recommendation for Block Cipher Modes 
of Operation: the CCM Mode for Authentication and Confidentiality. May 2004. http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf

(5) ANSI  X9.62-2005. The Ellptic Curve Digital Signature Algorithm (ECDA). https://www.x9.org/home/

(6) Talyor D., Wu T., Mavrogiannopoulos N. and Perrin L. Using the Secure Remote Password (SRP) Protocol for TLS Authentication. RFC 5054. November 2007. http://tools.ietf.org/html/rfc5054

(7) Cannetti R., Halevi S., Katz J. A Forward-Secure Public-Key Encryption Scheme. 2012. http://www.cs.umd.edu/~jkatz/papers/forward-enc-full.pdf
