# cloudflare-advanced-basic-auth-worker

Inspired by the cloudflare version
https://developers.cloudflare.com/workers/examples/basic-auth/


This version adds the ability to define a list of users and their passwords.

To avoid storing credentials uncrypted, passwords must be entered in SHA-256. 

Finally, to avoid having known hashes, you can set the salt constant