import CryptoKit
import Foundation

/// Unlocking with a passkey's PRF output (WebAuthn `prf` extension), as Bitwarden clients do: the PRF output is
/// stretched into a symmetric key, which unwraps an RSA private key kept for that passkey, which unwraps the user key.
/// The server only stores the two wrapped values; the PRF output never leaves the device.
public enum PasskeyUnlock {
    /// The PRF input every Bitwarden client asks for at sign-in: SHA-256 of "passwordless-login".
    public static let prfSalt = Data(SHA256.hash(data: Data("passwordless-login".utf8)))

    /// HKDF-Expand ("enc" / "mac") of the 32-byte PRF output, the same stretch as a master key.
    public static func prfKey(_ prfOutput: Data) throws(CryptoError) -> SymmetricKeyPair {
        try SymmetricKeyPair.stretched(masterKey: prfOutput)
    }

    /// - Parameters:
    ///   - encryptedPrivateKey: EncString (type 2) of the PKCS#8 private key, under the PRF key.
    ///   - encryptedUserKey: RSA EncString of the 64-byte user key, under that private key's public half.
    public static func userKey(prfOutput: Data, encryptedPrivateKey: String,
                               encryptedUserKey: String) throws(CryptoError) -> SymmetricKeyPair {
        let privateKeyDER = try EncString(encryptedPrivateKey).decrypt(with: prfKey(prfOutput))
        let privateKey = try RSAPrivateKey(pkcs8: privateKeyDER)
        return try SymmetricKeyPair(combined: privateKey.decrypt(encryptedUserKey))
    }
}
