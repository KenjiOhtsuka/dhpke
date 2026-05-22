module Tests

open Hpke.Core
open Xunit

[<Fact>]
let ``base seal is scaffolded and returns not implemented`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let request = {
        Suite = suite
        RecipientPublicKey = [| 1uy |]
        Info = [||]
        Aad = [||]
        Plaintext = [| 42uy |]
    }

    match Base.Seal request with
    | Error (NotImplemented feature) -> Assert.Equal("HPKE Base seal", feature)
    | result -> failwithf "Unexpected result: %A" result
