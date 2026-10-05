"""
routes
------
HTTP layer. Routes validate input, call services, and render templates.

No cryptographic logic. No direct Firestore access. Those live in
services/ and crypto/.
"""
