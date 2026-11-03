import Foundation
import Testing
import TriCrypto
@testable import VaultwardenAPI

/// The passkey sign-in exchange against canned server answers shaped like Vaultwarden's (PascalCase token response).
@Suite(.serialized) struct PasskeyLoginTests {
    static let encryptedPrivateKey = "2.BwcHBwcHBwcHBwcHBwcHBw==|ATYLdVULo9s/TdTnnQA2SfVLYJc5Q/GvoRSCGXYDoH7YINWjt9wvaUDVMvq+JkLYkvc//xMWd2pCirfB6zIJFhyY/lG87V5O1jEMDLkaGEz1C9M4Jr3XSOJ3Dc9zWeLLuoXj30etDXU+OQAVPAeTf8CqW27gsup9CxDNiJFbbOCk13hxXbvlQ3+Vfc+YOnAMdU52PrkdkGJ6Z8nBANdVsIsQn+tGmb6wRXvN7XZG46Odyqo+zeJDDiuL8a9X9HixUdSo/gmJ/Bkv13BHF7JQB1I/NdFMjDoRmXs24Rd9eUB63SYB8j+nFA/hMqpFPJU6TOpZMoBxX6X7G/we2H3iAtEhMa0RXc3hMKqSl92+Z6jXGIZmzVveeqamFtRsiPbeSqjbX/hKorE4Ox3OgwaNBsCMCfC6QthCtO25xxVyyUGC4BDZGO7quks8XVkg7+BsRaNDcQ483jkI+q4dMosDdyJGXYbldokGUeBVAQFnrlAFDJt7BT4JABi+TNz1V1cACkoVZ2ldEa2EoJO/7X88xbNQJ3ZSDIwenRSYK+KkHYq/b1VcPYgvdWogn25epL8V8W5xr0VkPjNoRyiV6KF1OpKYqXw7a9UdRKMfZQAgWcWS+xJ9tZuLfFeH1xSTWS5P0rOhHN12ZkN3+xFDsbXO8ZevkXRQXHBPRhCARvcVlHR149Xo/XW1gU9U5kfP8MZF+g2TJI7Ppz7rX1fIJgb2Z8E4DKA3PC14ncd0xujkCFWDX0aRjO3KJfrDlpU1UnwFKyIXYdDQpFmLguXoFx+U4XZgGU5S31KBzA2Oe3y2/DAtJtSohFWcQs/BijIpLOxsLndLkxfWvcAtZK8QVUb37SJ0j/A/mMkUoh8qsMDwDrBrqgHcdGozuQMC7JUNuSnx+oOiRtDraPH4GLQrb2VxLRRHti/T6sAcz3G7CzT+vY6Hmb12VULYG+zyHtCWQwpvriK0maVqs5XIfzZvMuqwpvDYzbPb9KuOm3Ij8byHVflDqv+4VfUbW4tUbFvChKHzMD0LOpwwzdEJY6nt5UXR5rEwDF+3JntEAnvto+26Qax0Y3q6yPxeceC2Mbv2qwwN25jtcQkGER9n4HybDuuYnZIlA+ZhZOLWkNPl2dPWeGtK6sy50OJxdRPOlWtM++UzMFUAc6IGe84IbBWY65flUqiiG8bOr40d+LfFxCtklBiY/fsfRXvMxtRn5cOGxF4EKRdK4KJ7rQ38wlhtAIWIE2rZo3/KRJvHMyK2eZGN0a1QEwr5QLje2rZF/622vcNCa3GKckYaXTqQCo5dhdtb1Z5SsEJVf+GMXCkNc/nDSUfn0/Idksa/cCTiehEIAREWCN/uWy/4HpGop/Sq7JeYcUo70R5ycGrMThfKxI0gEPFyu6xFde02i9k3uTVd0+8t5vYttdFtwS6bzNgTJDInsVBUMR4xo3wFcKhiZWGV6Ev7UDI+sv0p8dCo0GejbMEFhKQ0IqmHgGRs+fD2KW4a0xYcuFbJ8Xv2iyf94Kb2nZT0mmpLV+9eBEg5wgOgBCig7YAgA0nkB4x9hnKtsbXRN9t3DVGk4e6wQAWwBodPRek0RJSQcHbxtH4OlRum6hqvBddBI8z0/gjyKJ66PiI77xJo01maloav3HY8u+33V/k=|DYAvYIRaC3OIddsg4sTH8MQVXy0+gmPGmXnKVHINEUs="
    static let encryptedUserKey = "4.VD/Fu3gVHl6vLKUYuOieJWWCCus5wCoC6SZrPYRUorRyjetSj6dYcq+k9/KBg7oa2dNOLp/EryaF8kycfouZWV6NCSaH98S45GnAIpiPz/6ZafsBu4Lpu5OrC8Im0pA8+Vsmbm6Jh0lpnrbwjpFHqmUeVhwOaFavIvq3FTBCI63iN9Mjt/xlsMaM4jBtAtLFeMHAEw1uMpSeDwH9AWN6uERCJQi3HXdOGzbQtukJ4zeF1/Sy8d+YbndkcnRWVMA2tsNZfZ8o5jZngJIb/P+Dxmscc/iklMxpgcFxk06yFzpbH7oqVXw36TejFDRXEbGudotyE4C6yn92KOpC4f7IPA=="

    /// email=usagi@chiikawarden.test in an unsigned JWT; the client only reads the claim.
    static let accessToken = "e30." + Data(#"{"email":"usagi@chiikawarden.test"}"#.utf8).base64URLEncoded + ".sig"

    static func client() -> VaultClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CannedServer.self]
        return VaultClient(environment: .selfHosted(URL(string: "https://vault.example.test")!), deviceIdentifier: "device-1",
                           session: URLSession(configuration: config))
    }

    static let assertion = VaultClient.PasskeyAssertion(
        credentialID: Data([1, 2, 3]), userHandle: Data([4, 5]), authenticatorData: Data([6]), clientDataJSON: Data([7]),
        signature: Data([8]), prfOutput: Data(0..<32))

    static func tokenBody(prf: Bool) -> Data {
        var body: [String: Any] = [
            "access_token": accessToken, "refresh_token": "refresh-1", "expires_in": 3600,
            "Key": "2.AAAA|BBBB|CCCC", "Kdf": 0, "KdfIterations": 600_000,
            "UserDecryptionOptions": ["HasMasterPassword": true],
        ]
        if prf {
            body["UserDecryptionOptions"] = ["HasMasterPassword": true, "WebAuthnPrfOption": [
                "CredentialId": "AQID", "Transports": ["internal"],
                "EncryptedPrivateKey": encryptedPrivateKey, "EncryptedUserKey": encryptedUserKey,
            ]]
        }
        return try! JSONSerialization.data(withJSONObject: body)
    }

    @Test func challengeUsesTheServersRelyingParty() async throws {
        CannedServer.respond = { request in
            #expect(request.url?.path() == "/identity/accounts/webauthn/assertion-options")
            return (200, Data(#"{"options":{"challenge":"AQIDBA","rpId":"vault.example.test","timeout":60000,"allowCredentials":[]},"token":"t-1","object":"webAuthnLoginAssertionOptions"}"#.utf8))
        }
        let challenge = try await Self.client().passkeyChallenge()
        #expect(challenge.challenge == Data([1, 2, 3, 4]))
        #expect(challenge.relyingParty == "vault.example.test")
        #expect(challenge.timeout == 60)
        #expect(challenge.token == "t-1")
    }

    @Test func prfPasskeySignsInAndUnlocksWithoutSendingThePRFOutput() async throws {
        var form: [String: String] = [:]
        CannedServer.respond = { request in
            form = CannedServer.form(request)
            return (200, Self.tokenBody(prf: true))
        }
        let challenge = VaultClient.PasskeyChallenge(challenge: Data([1]), relyingParty: "vault.example.test", timeout: nil, token: "t-1")
        let login = try await Self.client().loginWithPasskey(Self.assertion, challenge: challenge)
        #expect(login.session.email == "usagi@chiikawarden.test")
        #expect(login.session.kdf == .pbkdf2(iterations: 600_000))
        #expect(login.session.refreshToken == "refresh-1")
        #expect(login.userKey == (try SymmetricKeyPair(combined: Data(100..<164))))
        #expect(form["grant_type"] == "webauthn")
        #expect(form["token"] == "t-1")
        let response = try #require(form["deviceResponse"])
        let json = try #require(try JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: Any])
        #expect(json["rawId"] as? String == "AQID")
        #expect((json["extensions"] as? [String: Any])?.isEmpty == true)
        #expect((json["response"] as? [String: String])?["userHandle"] == "BAU")
        #expect(!response.contains(Data(0..<32).base64URLEncoded))
    }

    @Test func passkeyWithoutPRFStillNeedsTheMasterPassword() async throws {
        CannedServer.respond = { _ in (200, Self.tokenBody(prf: false)) }
        let challenge = VaultClient.PasskeyChallenge(challenge: Data([1]), relyingParty: "vault.example.test", timeout: nil, token: "t-1")
        let login = try await Self.client().loginWithPasskey(Self.assertion, challenge: challenge)
        #expect(login.userKey == nil)
        #expect(login.session.protectedUserKey == "2.AAAA|BBBB|CCCC")
    }

    @Test func serverWithoutPasskeysSaysSo() async {
        CannedServer.respond = { _ in (404, Data()) }
        await #expect(throws: APIError.self) { try await Self.client().passkeyChallenge() }
    }
}

/// Answers every request in a test's URLSession with `respond`.
final class CannedServer: URLProtocol {
    nonisolated(unsafe) static var respond: (URLRequest) -> (Int, Data) = { _ in (500, Data()) }

    static func form(_ request: URLRequest) -> [String: String] {
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            defer { stream.close() }
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                body.append(buffer, count: n)
            }
        }
        var c = URLComponents()
        c.percentEncodedQuery = String(decoding: body, as: UTF8.self).replacingOccurrences(of: "+", with: "%20")
        return Dictionary((c.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (status, data) = Self.respond(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
