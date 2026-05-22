module Rfc9180Tests

open System
open System.IO
open System.Text.Json
open Xunit

[<Fact>]
let ``rfc9180 official vector fixture matches expected outputs`` () =
    let path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "tests", "Hpke.Tests", "rfc9180_vectors.json"))
    Assert.True(File.Exists path, "RFC 9180 vectors file is missing")

    let json = File.ReadAllText path
    use doc = JsonDocument.Parse(json)
    Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind)

    let findVector name =
        doc.RootElement.EnumerateArray()
        |> Seq.find (fun element -> element.GetProperty("name").GetString() = name)

    let assertVector name key baseNonce ciphertext0 =
        let vector = findVector name
        Assert.Equal(key, vector.GetProperty("key").GetString())
        Assert.Equal(baseNonce, vector.GetProperty("base_nonce").GetString())
        Assert.Equal(ciphertext0, vector.GetProperty("ciphertext_seq0").GetString())

    assertVector
        "A.3.1 Base"
        "868c066ef58aae6dc589b6cfdd18f97e"
        "4e0bc5018beba4bf004cca59"
        "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"

    assertVector
        "A.3.2 PSK"
        "55d9eb9d26911d4c514a990fa8d57048"
        "b595dc6b2d7e2ed23af529b1"
        "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb"

    assertVector
        "A.3.3 Auth"
        "19aa8472b3fdc530392b0e54ca17c0f5"
        "b390052d26b67a5b8a8fcaa4"
        "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099ed3289ffe19"

    assertVector
        "A.3.4 AuthPSK"
        "4d567121d67fae1227d90e11585988fb"
        "67c9d05330ca21e5116ecda6"
        "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f4ff81b9246"
