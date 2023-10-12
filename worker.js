/**
 * Shows how to restrict access using the HTTP Basic schema.
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
 * @see https://tools.ietf.org/html/rfc7617
 *
 * A user-id containing a colon (":") character is invalid, as the
 * first colon in a user-pass string separates user and password.
 */
export default {
    async fetch(request) {

        /** @var {string} salt Add SALT to the hash */
        const salt = "awesome_salt";
        /** @var {[{user:string,pass:string}]} credential List of authorized credentials */
        const credentials = [
            //pass = password
            {user: "my_user", pass: "45be8c1629d97bb4e6f960dc6c1ffc48bc0991b970dfd34326dc78285a06b1f1"},
        ];

        /**
         * Hash a text and return it in hexa format for easy comparison
         * @param {string} text Text to hash
         * @returns hexadecimal hash format
         */
        async function digestText(text) {
            const msgUint8 = new TextEncoder().encode(salt + text);
            const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8);
            const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
            return hashArray
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(""); // convert bytes to hex string
        }

        /*
       * Throws exception on verification failure.
       * @param {string} user
       * @param {string} pass
       * @returns true if credential is authorized
       */
        async function verifyCredentials(user, pass) {
            let passHashed = await digestText(pass);

            let accessGranted = false;
            credentials.forEach(function (credential) {
                if (credential.user === user) {
                    if (credential.pass === passHashed) {
                        accessGranted = true;
                        return true;
                    }
                }
            });

            return accessGranted;
        }

        /**
         * Parse HTTP Basic Authorization value.
         * @param {Request} request
         * @throws {BadRequestException}
         * @returns {{ user: string, pass: string }}
         */
        function basicAuthentication(request) {
            const Authorization = request.headers.get("Authorization");

            const [scheme, encoded] = Authorization.split(" ");
            // The Authorization header must start with Basic, followed by a space.
            if (!encoded || scheme !== "Basic") {
                throw new BadRequestException("Malformed authorization header.");
            }

            // Decodes the base64 value and performs unicode normalization.
            // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
            // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
            const buffer = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
            const decoded = new TextDecoder().decode(buffer).normalize();

            // The username & password are split by the first colon.
            //=> example: "username:password"
            const index = decoded.indexOf(":");

            // The user & password are split by the first colon and MUST NOT contain control characters.
            // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
            if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
                throw new BadRequestException("Invalid authorization value.");
            }

            return {
                user: decoded.substring(0, index),
                pass: decoded.substring(index + 1),
            };
        }

        function UnauthorizedException(reason) {
            this.status = 401;
            this.statusText = "Unauthorized";
            this.reason = reason;
        }

        function BadRequestException(reason) {
            this.status = 400;
            this.statusText = "Bad Request";
            this.reason = reason;
        }

        const {protocol} = new URL(request.url);

        // In the case of a Basic authentication, the exchange MUST happen over an HTTPS (TLS) connection to be secure.
        if (
            "https:" !== protocol ||
            "https" !== request.headers.get("x-forwarded-proto")
        ) {
            throw new BadRequestException("Please use a HTTPS connection.");
        }

        if (request.headers.has("Authorization")) {
            // Throws exception when authorization fails.
            const {user, pass} = basicAuthentication(request);
            if (await verifyCredentials(user, pass)) {
                return fetch(request);
            }
        }

        // Not authenticated.
        return new Response("You need to login.", {
            status: 401,
            headers: {
                // Prompts the user for credentials.
                "WWW-Authenticate": 'Basic realm="my scope", charset="UTF-8"',
            },
        });
    },
};