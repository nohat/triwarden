import Foundation
import TriCrypto

/// "Log in with passkey", Bitwarden's protocol: the server hands out a one-use challenge without knowing the account,
/// the authenticator signs it with a discoverable passkey, and `grant_type=webauthn` exchanges the assertion for
/// tokens. A passkey enrolled with PRF also unlocks: its PRF output unwraps the user key (`PasskeyUnlock`).
extension VaultClient {
    /// What the authenticator needs for a discoverable assertion.
    public struct PasskeyChallenge: Sendable {
        public let challenge: Data
        /// The relying party: the server's host name, unless the server says otherwise.
        public let relyingParty: String
        public let timeout: TimeInterval?
        /// Identifies the challenge when the assertion comes back.
        let token: String
    }

    /// A signed assertion from a platform authenticator, with the raw fields WebAuthn returns.
    public struct PasskeyAssertion: Sendable {
        public let credentialID: Data
        public let userHandle: Data
        public let authenticatorData: Data
        public let clientDataJSON: Data
        public let signature: Data
        /// The first PRF output for `PasskeyUnlock.prfSalt`, when the passkey supports PRF. Never sent to the server.
        public let prfOutput: Data?

        public init(credentialID: Data, userHandle: Data, authenticatorData: Data, clientDataJSON: Data,
                    signature: Data, prfOutput: Data?) {
            self.credentialID = credentialID
            self.userHandle = userHandle
            self.authenticatorData = authenticatorData
            self.clientDataJSON = clientDataJSON
            self.signature = signature
            self.prfOutput = prfOutput
        }

        /// The `deviceResponse` form field, shaped like Bitwarden's `WebAuthnLoginAssertionResponseRequest`.
        /// Extension results stay on the device: sending the PRF output would hand the server the unlock key.
        var deviceResponse: String {
            let id = credentialID.base64URLEncoded
            let object: [String: Any] = [
                "id": id, "rawId": id, "type": "public-key", "extensions": [String: Any](),
                "response": [
                    "authenticatorData": authenticatorData.base64URLEncoded,
                    "signature": signature.base64URLEncoded,
                    "clientDataJSON": clientDataJSON.base64URLEncoded,
                    "userHandle": userHandle.base64URLEncoded,
                ],
            ]
            let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
            return String(decoding: data, as: UTF8.self)
        }
    }

    /// Signed in with a passkey. `userKey` is set when the passkey unlocked the vault too (PRF); otherwise finish
    /// with the master password through `unlockSSO(_:password:)` on `session`, as after single sign-on.
    public struct PasskeyLogin: Sendable {
        public let session: SSOSession
        public let userKey: SymmetricKeyPair?
    }

    /// Step 1: a fresh challenge for any of the server's passkeys.
    public func passkeyChallenge() async throws(APIError) -> PasskeyChallenge {
        struct Response: Decodable {
            struct Options: Decodable {
                let challenge: String
                let rpId: String?
                let timeout: Double?
            }
            let options: Options
            let token: String
        }
        let response: Response
        do {
            response = try await send(request(environment.identityURL, "accounts/webauthn/assertion-options"))
        } catch .http(let status, _) where status == 404 || status == 405 {
            throw .http(status: status, message: "This server doesn't support signing in with a passkey.")
        }
        guard let challenge = Data(base64URL: response.options.challenge),
              let host = environment.identityURL.host() else {
            throw .http(status: -1, message: "The server's passkey challenge couldn't be read.")
        }
        return PasskeyChallenge(challenge: challenge, relyingParty: response.options.rpId ?? host,
                                timeout: response.options.timeout.map { $0 / 1000 }, token: response.token)
    }

    /// Step 2: trade the assertion for tokens, and unwrap the user key when the passkey has PRF.
    public func loginWithPasskey(_ assertion: PasskeyAssertion, challenge: PasskeyChallenge) async throws(APIError)
        -> PasskeyLogin {
        struct Token: Decodable {
            struct DecryptionOptions: Decodable {
                struct PRF: Decodable {
                    let encryptedPrivateKey: String
                    let encryptedUserKey: String
                }
                let webAuthnPrfOption: PRF?
            }
            let access_token: String
            let refresh_token: String?
            let key: String?
            let kdf: Int?
            let kdfIterations: Int?
            let kdfMemory: Int?
            let kdfParallelism: Int?
            let userDecryptionOptions: DecryptionOptions?
        }
        let token: Token = try await send(post(environment.identityURL, "connect/token", formBody: [
            "grant_type": "webauthn", "token": challenge.token, "deviceResponse": assertion.deviceResponse,
            "scope": "api offline_access", "client_id": Self.clientName,
            "deviceType": "7", "deviceIdentifier": deviceIdentifier, "deviceName": "triwarden",
        ]))
        setTokens(access: token.access_token, refresh: token.refresh_token)
        guard let email = Self.jwtClaim("email", token.access_token) else {
            throw .http(status: -1, message: "The server's token has no email address.")
        }
        guard let protectedUserKey = token.key else { throw .missingUserKey }
        let kdf: KDFConfig = switch token.kdf {
        case 1?: .argon2id(iterations: token.kdfIterations ?? 3, memoryMiB: token.kdfMemory ?? 64,
                           parallelism: token.kdfParallelism ?? 4)
        default: .pbkdf2(iterations: token.kdfIterations ?? 600_000)
        }
        do { try kdf.validate() } catch { throw .crypto(error) }
        let session = SSOSession(email: email, kdf: kdf, protectedUserKey: protectedUserKey,
                                 refreshToken: token.refresh_token)
        guard let prf = token.userDecryptionOptions?.webAuthnPrfOption, let output = assertion.prfOutput else {
            return PasskeyLogin(session: session, userKey: nil)
        }
        do {
            let userKey = try PasskeyUnlock.userKey(prfOutput: output, encryptedPrivateKey: prf.encryptedPrivateKey,
                                                    encryptedUserKey: prf.encryptedUserKey)
            return PasskeyLogin(session: session, userKey: userKey)
        } catch {
            throw .crypto(error)
        }
    }
}
