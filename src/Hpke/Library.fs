namespace Hpke

open Hpke.Core

module Hpke =
    let BaseSeal = Base.Seal
    let BaseOpen = Base.Open
    let PskSeal = Psk.Seal
    let PskOpen = Psk.Open
    let AuthSeal = Auth.Seal
    let AuthOpen = Auth.Open
    let AuthPskSeal = AuthPsk.Seal
    let AuthPskOpen = AuthPsk.Open

    let BaseSealWithAlgorithms kem kdf aead (request: BaseSealRequest) =
        Base.Seal { request with Suite = Suites.create kem kdf aead }

    let BaseOpenWithAlgorithms kem kdf aead (request: BaseOpenRequest) =
        Base.Open { request with Suite = Suites.create kem kdf aead }

    let PskSealWithAlgorithms kem kdf aead (request: PskSealRequest) =
        Psk.Seal { request with Suite = Suites.create kem kdf aead }

    let PskOpenWithAlgorithms kem kdf aead (request: PskOpenRequest) =
        Psk.Open { request with Suite = Suites.create kem kdf aead }

    let AuthSealWithAlgorithms kem kdf aead (request: AuthSealRequest) =
        Auth.Seal { request with Suite = Suites.create kem kdf aead }

    let AuthOpenWithAlgorithms kem kdf aead (request: AuthOpenRequest) =
        Auth.Open { request with Suite = Suites.create kem kdf aead }

    let AuthPskSealWithAlgorithms kem kdf aead (request: AuthPskSealRequest) =
        AuthPsk.Seal { request with Suite = Suites.create kem kdf aead }

    let AuthPskOpenWithAlgorithms kem kdf aead (request: AuthPskOpenRequest) =
        AuthPsk.Open { request with Suite = Suites.create kem kdf aead }
