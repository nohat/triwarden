import AppKit
import AuthenticationServices
import CryptoKit
import Security
import TriCrypto
import VaultwardenAPI

/// Asks macOS for one of the server's passkeys (the system sheet: Touch ID, iPhone, or a security key in Passwords)
/// and returns the signed assertion, with the PRF output that unlocks the vault when the passkey has one.
///
/// macOS only lets an app use passkeys for domains in its `com.apple.developer.associated-domains` entitlement
/// (`webcredentials:host`), confirmed by the site's apple-app-site-association file. `isAvailable(for:)` reads the
/// entitlement so the sign-in screen offers passkeys only where they can work.
@MainActor
final class PasskeySignIn: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    enum Failure: LocalizedError {
        case cancelled
        case notAllowed(host: String)
        case noAssertion

        var errorDescription: String? {
            switch self {
            case .cancelled: nil
            case .notAllowed(let host):
                String(localized: "macOS didn't allow passkeys for \(host). Check that the server lists Triwarden in its apple-app-site-association file.")
            case .noAssertion: String(localized: "The passkey didn't answer. Try again.")
            }
        }
    }

    /// Hosts this build may use passkeys for, from its `webcredentials:` associated domains.
    static let passkeyHosts: Set<String> = {
        guard let task = SecTaskCreateFromSelf(nil),
              let value = SecTaskCopyValueForEntitlement(task, "com.apple.developer.associated-domains" as CFString, nil),
              let domains = value as? [String] else { return [] }
        return Set(domains.compactMap { domain in
            guard domain.hasPrefix("webcredentials:") else { return nil }
            // "webcredentials:host?mode=developer" → "host"
            return domain.dropFirst("webcredentials:".count).split(separator: "?").first.map { $0.lowercased() }
        })
    }()

    static func isAvailable(for environment: ServerEnvironment) -> Bool {
        guard let host = environment.identityURL.host()?.lowercased() else { return false }
        return passkeyHosts.contains(host)
    }

    private var continuation: CheckedContinuation<VaultClient.PasskeyAssertion, Error>?
    private var relyingParty = ""
    /// The system doesn't keep the controller alive while its sheet is up.
    private var controller: ASAuthorizationController?

    /// Shows the system passkey sheet for a discoverable credential and waits for the person.
    static func assert(_ challenge: VaultClient.PasskeyChallenge) async throws -> VaultClient.PasskeyAssertion {
        let signIn = PasskeySignIn()
        return try await signIn.run(challenge)
    }

    private func run(_ challenge: VaultClient.PasskeyChallenge) async throws -> VaultClient.PasskeyAssertion {
        relyingParty = challenge.relyingParty
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: challenge.relyingParty)
        let request = provider.createCredentialAssertionRequest(challenge: challenge.challenge)
        request.userVerificationPreference = .required
        request.prf = .inputValues(.init(saltInput1: PasskeyUnlock.prfSalt))
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        self.controller = controller
        defer { self.controller = nil }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            controller.performRequests()
        }
    }

    nonisolated func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        MainActor.assumeIsolated { NSApp.keyWindow ?? NSApp.windows.first ?? ASPresentationAnchor() }
    }

    nonisolated func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithAuthorization authorization: ASAuthorization) {
        let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion
        let assertion = credential.flatMap { c -> VaultClient.PasskeyAssertion? in
            guard let userID = c.userID, let authenticatorData = c.rawAuthenticatorData, let signature = c.signature
            else { return nil }
            return VaultClient.PasskeyAssertion(
                credentialID: c.credentialID, userHandle: userID, authenticatorData: authenticatorData,
                clientDataJSON: c.rawClientDataJSON, signature: signature,
                prfOutput: c.prf?.first.withUnsafeBytes { Data($0) })
        }
        MainActor.assumeIsolated {
            if let assertion { finish(.success(assertion)) } else { finish(.failure(Failure.noAssertion)) }
        }
    }

    nonisolated func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        MainActor.assumeIsolated {
            let nsError = error as NSError
            if (error as? ASAuthorizationError)?.code == .canceled {
                finish(.failure(Failure.cancelled))
            } else if "\(nsError.localizedDescription) \(nsError.userInfo)".localizedCaseInsensitiveContains("not associated") {
                // The app-site-association check failed: the server doesn't list this app (yet), or macOS can't fetch it.
                finish(.failure(Failure.notAllowed(host: relyingParty)))
            } else {
                finish(.failure(error))
            }
        }
    }

    private func finish(_ result: Result<VaultClient.PasskeyAssertion, Error>) {
        continuation?.resume(with: result)
        continuation = nil
    }
}
