module BaseTests

open Hpke.Core
open Xunit

[<Fact>]
let ``base seal and open roundtrip`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 9uy; 10uy |]
    }

    match Base.Seal sealReq with
    | Error _ -> failwith "Base.Seal not implemented"
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Base.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 9uy; 10uy |], pt)

[<Fact>]
let ``base seal and open roundtrip with aes256gcm`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes256Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 1uy; 2uy; 3uy; 4uy |]
    }

    match Base.Seal sealReq with
    | Error _ -> failwith "Base.Seal not implemented for AES-256-GCM"
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Base.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 1uy; 2uy; 3uy; 4uy |], pt)

[<Fact>]
let ``base open fails when ciphertext tampered`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 9uy; 10uy |]
    }

    match Base.Seal sealReq with
    | Error _ -> failwith "Base.Seal not implemented"
    | Ok res ->
        let tampered = Array.copy res.Ciphertext
        if tampered.Length > 0 then tampered.[tampered.Length-1] <- tampered.[tampered.Length-1] ^^^ 0xFFuy

        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = tampered
        }

        match Base.Open openReq with
        | Ok _ -> failwith "Open succeeded but should have failed on tampered ciphertext"
        | Error (InvalidArgument(name, _)) -> Assert.Equal("Ciphertext", name)
        | Error e -> failwithf "Unexpected error: %A" e

[<Fact>]
let ``base seal and open roundtrip with p384 suite`` () =
    let suite = {
        Kem = DhKemP384HkdfSha384
        Kdf = HkdfSha384
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP384KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 11uy; 12uy; 13uy |]
    }

    match Base.Seal sealReq with
    | Error e -> failwithf "Base.Seal failed: %A" e
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Base.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 11uy; 12uy; 13uy |], pt)

[<Fact>]
let ``base seal and open roundtrip with p521 suite`` () =
    let suite = {
        Kem = DhKemP521HkdfSha512
        Kdf = HkdfSha512
        Aead = Aes256Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP521KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 21uy; 22uy; 23uy; 24uy |]
    }

    match Base.Seal sealReq with
    | Error e -> failwithf "Base.Seal failed: %A" e
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Base.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 21uy; 22uy; 23uy; 24uy |], pt)

