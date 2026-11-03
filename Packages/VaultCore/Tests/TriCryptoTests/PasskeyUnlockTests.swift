import Foundation
import Testing
@testable import TriCrypto

/// Vectors made independently with Python's `cryptography` (HKDF-Expand, AES-CBC + HMAC, RSA-OAEP-SHA1), the way
/// Bitwarden's web client wraps keys when it enrolls a passkey with PRF.
@Suite struct PasskeyUnlockTests {
    static let prfOutput = Data(0..<32)
    static let userKey = Data(100..<164)
    static let encryptedPrivateKey = "2.BwcHBwcHBwcHBwcHBwcHBw==|ATYLdVULo9s/TdTnnQA2SfVLYJc5Q/GvoRSCGXYDoH7YINWjt9wvaUDVMvq+JkLYkvc//xMWd2pCirfB6zIJFhyY/lG87V5O1jEMDLkaGEz1C9M4Jr3XSOJ3Dc9zWeLLuoXj30etDXU+OQAVPAeTf8CqW27gsup9CxDNiJFbbOCk13hxXbvlQ3+Vfc+YOnAMdU52PrkdkGJ6Z8nBANdVsIsQn+tGmb6wRXvN7XZG46Odyqo+zeJDDiuL8a9X9HixUdSo/gmJ/Bkv13BHF7JQB1I/NdFMjDoRmXs24Rd9eUB63SYB8j+nFA/hMqpFPJU6TOpZMoBxX6X7G/we2H3iAtEhMa0RXc3hMKqSl92+Z6jXGIZmzVveeqamFtRsiPbeSqjbX/hKorE4Ox3OgwaNBsCMCfC6QthCtO25xxVyyUGC4BDZGO7quks8XVkg7+BsRaNDcQ483jkI+q4dMosDdyJGXYbldokGUeBVAQFnrlAFDJt7BT4JABi+TNz1V1cACkoVZ2ldEa2EoJO/7X88xbNQJ3ZSDIwenRSYK+KkHYq/b1VcPYgvdWogn25epL8V8W5xr0VkPjNoRyiV6KF1OpKYqXw7a9UdRKMfZQAgWcWS+xJ9tZuLfFeH1xSTWS5P0rOhHN12ZkN3+xFDsbXO8ZevkXRQXHBPRhCARvcVlHR149Xo/XW1gU9U5kfP8MZF+g2TJI7Ppz7rX1fIJgb2Z8E4DKA3PC14ncd0xujkCFWDX0aRjO3KJfrDlpU1UnwFKyIXYdDQpFmLguXoFx+U4XZgGU5S31KBzA2Oe3y2/DAtJtSohFWcQs/BijIpLOxsLndLkxfWvcAtZK8QVUb37SJ0j/A/mMkUoh8qsMDwDrBrqgHcdGozuQMC7JUNuSnx+oOiRtDraPH4GLQrb2VxLRRHti/T6sAcz3G7CzT+vY6Hmb12VULYG+zyHtCWQwpvriK0maVqs5XIfzZvMuqwpvDYzbPb9KuOm3Ij8byHVflDqv+4VfUbW4tUbFvChKHzMD0LOpwwzdEJY6nt5UXR5rEwDF+3JntEAnvto+26Qax0Y3q6yPxeceC2Mbv2qwwN25jtcQkGER9n4HybDuuYnZIlA+ZhZOLWkNPl2dPWeGtK6sy50OJxdRPOlWtM++UzMFUAc6IGe84IbBWY65flUqiiG8bOr40d+LfFxCtklBiY/fsfRXvMxtRn5cOGxF4EKRdK4KJ7rQ38wlhtAIWIE2rZo3/KRJvHMyK2eZGN0a1QEwr5QLje2rZF/622vcNCa3GKckYaXTqQCo5dhdtb1Z5SsEJVf+GMXCkNc/nDSUfn0/Idksa/cCTiehEIAREWCN/uWy/4HpGop/Sq7JeYcUo70R5ycGrMThfKxI0gEPFyu6xFde02i9k3uTVd0+8t5vYttdFtwS6bzNgTJDInsVBUMR4xo3wFcKhiZWGV6Ev7UDI+sv0p8dCo0GejbMEFhKQ0IqmHgGRs+fD2KW4a0xYcuFbJ8Xv2iyf94Kb2nZT0mmpLV+9eBEg5wgOgBCig7YAgA0nkB4x9hnKtsbXRN9t3DVGk4e6wQAWwBodPRek0RJSQcHbxtH4OlRum6hqvBddBI8z0/gjyKJ66PiI77xJo01maloav3HY8u+33V/k=|DYAvYIRaC3OIddsg4sTH8MQVXy0+gmPGmXnKVHINEUs="
    static let encryptedUserKey = "4.VD/Fu3gVHl6vLKUYuOieJWWCCus5wCoC6SZrPYRUorRyjetSj6dYcq+k9/KBg7oa2dNOLp/EryaF8kycfouZWV6NCSaH98S45GnAIpiPz/6ZafsBu4Lpu5OrC8Im0pA8+Vsmbm6Jh0lpnrbwjpFHqmUeVhwOaFavIvq3FTBCI63iN9Mjt/xlsMaM4jBtAtLFeMHAEw1uMpSeDwH9AWN6uERCJQi3HXdOGzbQtukJ4zeF1/Sy8d+YbndkcnRWVMA2tsNZfZ8o5jZngJIb/P+Dxmscc/iklMxpgcFxk06yFzpbH7oqVXw36TejFDRXEbGudotyE4C6yn92KOpC4f7IPA=="

    @Test func saltIsSHA256OfPasswordlessLogin() {
        #expect(PasskeyUnlock.prfSalt.map { String(format: "%02x", $0) }.joined()
            == "97b006dfd8db597b892c9a50343b5248ba6c328059ef812cec347ce0d774390b")
    }

    @Test func prfOutputUnwrapsTheUserKey() throws {
        let key = try PasskeyUnlock.userKey(prfOutput: Self.prfOutput, encryptedPrivateKey: Self.encryptedPrivateKey,
                                            encryptedUserKey: Self.encryptedUserKey)
        #expect(key == (try SymmetricKeyPair(combined: Self.userKey)))
    }

    @Test func anotherPasskeysOutputIsRejected() {
        var wrong = Self.prfOutput
        wrong[0] ^= 1
        #expect(throws: CryptoError.self) {
            try PasskeyUnlock.userKey(prfOutput: wrong, encryptedPrivateKey: Self.encryptedPrivateKey,
                                      encryptedUserKey: Self.encryptedUserKey)
        }
    }
}
