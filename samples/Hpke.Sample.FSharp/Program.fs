module Program

open System
open System.Text
open Hpke.Core

let utf8 = Encoding.UTF8
let kem = DhKemP256HkdfSha256
let kdf = HkdfSha256
let aead = Aes128Gcm

let suite = Suites.create kem kdf aead

let printRoundtrip label plaintext opened =
    printfn "%s: %s -> %s" label (utf8.GetString plaintext) (utf8.GetString opened)

let requireOk stage = function
    | Ok value -> value
    | Error error -> failwithf "%s failed: %A" stage error

let runBase () =
    let recipientSk, recipientPk = Crypto.generateEcdhP256KeyPair ()
    let plaintext = utf8.GetBytes "base mode from F#"

    let sealedValue =
        Hpke.Hpke.BaseSealWithAlgorithms kem kdf aead {
            Suite = suite
            RecipientPublicKey = recipientPk
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "Base seal"

    Hpke.Hpke.BaseOpenWithAlgorithms kem kdf aead {
        Suite = suite
        RecipientPrivateKey = recipientSk
        EncappedKey = sealedValue.EncappedKey
        Info = [||]
        Aad = [||]
        Ciphertext = sealedValue.Ciphertext
    }
    |> requireOk "Base open"
    |> printRoundtrip "Base" plaintext

let runPsk () =
    let recipientSk, recipientPk = Crypto.generateEcdhP256KeyPair ()
    let plaintext = utf8.GetBytes "psk mode from F#"
    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealedValue =
        Hpke.Hpke.PskSealWithAlgorithms kem kdf aead {
            Suite = suite
            RecipientPublicKey = recipientPk
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "PSK seal"

    Hpke.Hpke.PskOpenWithAlgorithms kem kdf aead {
        Suite = suite
        RecipientPrivateKey = recipientSk
        EncappedKey = sealedValue.EncappedKey
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Ciphertext = sealedValue.Ciphertext
    }
    |> requireOk "PSK open"
    |> printRoundtrip "PSK" plaintext

let runAuth () =
    let recipientSk, recipientPk = Crypto.generateEcdhP256KeyPair ()
    let senderSk, senderPk = Crypto.generateEcdhP256KeyPair ()
    let plaintext = utf8.GetBytes "auth mode from F#"

    let sealedValue =
        Hpke.Hpke.AuthSealWithAlgorithms kem kdf aead {
            Suite = suite
            RecipientPublicKey = recipientPk
            SenderPrivateKey = senderSk
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "Auth seal"

    Hpke.Hpke.AuthOpenWithAlgorithms kem kdf aead {
        Suite = suite
        RecipientPrivateKey = recipientSk
        SenderPublicKey = senderPk
        EncappedKey = sealedValue.EncappedKey
        Info = [||]
        Aad = [||]
        Ciphertext = sealedValue.Ciphertext
    }
    |> requireOk "Auth open"
    |> printRoundtrip "Auth" plaintext

let runAuthPsk () =
    let recipientSk, recipientPk = Crypto.generateEcdhP256KeyPair ()
    let senderSk, senderPk = Crypto.generateEcdhP256KeyPair ()
    let plaintext = utf8.GetBytes "auth psk mode from F#"
    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealedValue =
        Hpke.Hpke.AuthPskSealWithAlgorithms kem kdf aead {
            Suite = suite
            RecipientPublicKey = recipientPk
            SenderPrivateKey = senderSk
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "AuthPSK seal"

    Hpke.Hpke.AuthPskOpenWithAlgorithms kem kdf aead {
        Suite = suite
        RecipientPrivateKey = recipientSk
        SenderPublicKey = senderPk
        EncappedKey = sealedValue.EncappedKey
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Ciphertext = sealedValue.Ciphertext
    }
    |> requireOk "AuthPSK open"
    |> printRoundtrip "AuthPSK" plaintext

[<EntryPoint>]
let main _ =
    runBase ()
    runPsk ()
    runAuth ()
    runAuthPsk ()
    0
