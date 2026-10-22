# Third-party notices

## Where the protocol work comes from

Proton publishes its own API and login libraries under the MIT license. This
project is a Python port of those, not a reverse-engineering effort:

| Upstream | License | What was used, and where |
|---|---|---|
| [ProtonMail/go-srp](https://github.com/ProtonMail/go-srp) | MIT | The SRP handshake, the `expandHash` construction and the bcrypt password/key derivations → `protonlite/srp.py`. The modulus signing key is reproduced verbatim in `protonlite/_modulus_key.py`. |
| [ProtonMail/go-proton-api](https://github.com/ProtonMail/go-proton-api) | MIT | Endpoint paths and payload shapes, the token refresh request, the migrated-key unlock rules, and the send-package format → `protonlite/api.py`, `protonlite/client.py`, `protonlite/crypto.py`, `protonlite/send.py`. |

Both carry this notice:

```
The MIT License

Copyright (c) 2019 Proton Technologies AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## What was deliberately *not* used

No GPL-licensed source was read or copied while writing this, so the result can
stay MIT. Proton also ships its SRP and API libraries in Go under the MIT
license, which is why this port went through the Go code rather than any
GPL-licensed Python client.

## Runtime dependencies

| Package | License | Why |
|---|---|---|
| [PGPy13](https://pypi.org/project/PGPy13/) | BSD-3-Clause | OpenPGP: unlocks the account keys, decrypts bodies, wraps session keys. A fork of PGPy carrying the Python 3.13+ fix. |
| [bcrypt](https://pypi.org/project/bcrypt/) | Apache-2.0 | Proton's password and key derivations are bcrypt-based. |
| [requests](https://pypi.org/project/requests/) | Apache-2.0 | HTTP. |
