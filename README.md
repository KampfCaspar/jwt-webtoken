# JWT frontend for web-token

I often have the need to let a program
just call an object to encode/decode a payload,
without fussing about keys, algorithms etc.

The 'coder' object can be prepared and then
given to a consumer that only has to call
decode/encode.

This is an implementation of the 
mini interface for JWS, JWE and Nested JWT
using the [web-token](https://github.com/web-token/jwt-framework) library.


