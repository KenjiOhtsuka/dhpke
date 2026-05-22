module Program

open System
open System.Text
open Hpke.Core

let utf8 = Encoding.UTF8
let suite = Suites.Default

let printRoundtrip label plaintext opened =
    printfn "%s: %s -> %s" label (utf8.GetString plaintext) (utf8.GetString opened)

let requireOk stage = function
    | Ok value -> value
    | Error error -> failwithf "%s failed: %A" stage error

let runBase () =
    let recipientSk, recipientPk = Crypto.generateEcdhP256KeyPair ()
    let plaintext = utf8.GetBytes "base mode from F#"

    let sealedValue =
        Base.Seal {
            Suite = suite
            RecipientPublicKey = recipientPk
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "Base seal"

    Base.Open {
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
        Psk.Seal {
            Suite = suite
            RecipientPublicKey = recipientPk
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "PSK seal"

    Psk.Open {
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
        Auth.Seal {
            Suite = suite
            RecipientPublicKey = recipientPk
            SenderPrivateKey = senderSk
            Info = [||]
            Aad = [||]
            Plaintext = plaintext
        }
        |> requireOk "Auth seal"

    Auth.Open {
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
        AuthPsk.Seal {
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

    AuthPsk.Open {
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

do
    runBase ()
    runPsk ()
    runAuth ()
    runAuthPsk ()
