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

    let hex (s: string) =
        s |> Seq.chunkBySize 2 |> Seq.map (fun cs -> cs |> Array.ofSeq |> System.String) |> Seq.map (fun ss -> Convert.ToByte(ss, 16)) |> Seq.toArray

    let bytesToHex (b: byte[]) = BitConverter.ToString(b).Replace("-", "").ToLowerInvariant()

    let xorNonce (baseNonce: byte[]) (seq: int) =
        let n = baseNonce.Length
        let seqBytes = Array.zeroCreate<byte> n
        // write seq as big-endian into the rightmost bytes
        let mutable v = seq
        for i in 1..n do
            seqBytes.[n - i] <- byte (v &&& 0xFF)
            v <- v >>> 8
        Array.init n (fun i -> byte (baseNonce.[i] ^^^ seqBytes.[i]))

    let get (e: JsonElement) (name: string) =
        let mutable v = Unchecked.defaultof<JsonElement>
        if e.TryGetProperty(name, &v) then Some v else None

    let toString (e: JsonElement) = e.GetString()

    // Helper to attempt verifying fields if present in the vector JSON.
    // HKDF-Expand-Label per RFC-style: HkdfLabel = length(2) || labelLen(1) || label || ctxLen(1) || context
    let hkdfExpandLabel (prk: byte[]) (label: string) (context: byte[]) (length: int) : byte[] =
        let prefix = "HPKE-v1 "
        let lblBytes = System.Text.Encoding.ASCII.GetBytes(sprintf "%s%s" prefix label)
        let lenBytes = [| byte (length >>> 8); byte (length &&& 0xFF) |]
        let lblLen = [| byte lblBytes.Length |]
        let ctxLen = [| byte context.Length |]
        let info = Array.concat [| lenBytes; lblLen; lblBytes; ctxLen; context |]
        Hpke.Core.Crypto.hkdfExpand prk info length

    for element in doc.RootElement.EnumerateArray() do
        match get element "name" with
        | Some nameEl ->
            let name = nameEl.GetString()
            // If the vector contains explicit ephemeral private key, encapped key, etc. we can recompute
            // and validate more fields. Use Crypto helpers to derive public from private and derive shared secret.
            match (get element "esk_private", get element "recipient_public", get element "recipient_private") with
            | Some eskPrivEl, Some recipPubEl, _ ->
                // We have esk private and recipient public; recompute encapped_key and shared secret
                let esk = hex (eskPrivEl.GetString())
                let recipPub = hex (recipPubEl.GetString())
                let (epk, shared) = Hpke.Core.Crypto.encapsulateWithEphemeralPrivate esk recipPub
                // Compare encapped_key if present
                match get element "encapped_key" with
                | Some enc -> Assert.Equal(enc.GetString().ToLowerInvariant(), bytesToHex epk)
                | None -> ()
                // If expected shared_secret present, verify
                match get element "shared_secret" with
                | Some ssEl ->
                    let expectedSs = hex (ssEl.GetString())
                    Assert.Equal<byte[]>(expectedSs, shared)
                | None -> ()
                // If expected key/base_nonce present, verify derived key/nonce and sequences
                match get element "key" with
                | Some keyEl ->
                    let expected = hex (keyEl.GetString())
                    let prk = Hpke.Core.Crypto.hkdfExtract null shared
                    let actualKey = Hpke.Core.Crypto.hkdfExpand prk (Array.empty<byte>) expected.Length
                    Assert.Equal<byte[]>(expected, actualKey)
                    // If base_nonce present and sequences exist, verify sequence ciphertexts
                    match get element "base_nonce" with
                    | Some bnEl ->
                        let baseNonce = hex (bnEl.GetString())
                        match get element "sequences" with
                        | Some seqsEl ->
                            for sElem in seqsEl.EnumerateArray() do
                                let mutable tmpSeq = Unchecked.defaultof<JsonElement>
                                let seq = if sElem.TryGetProperty("seq", &tmpSeq) then tmpSeq.GetInt32() else 0
                                let mutable tmpPt = Unchecked.defaultof<JsonElement>
                                let pt = if sElem.TryGetProperty("pt", &tmpPt) then hex (tmpPt.GetString()) else Array.empty<byte>
                                let mutable tmpAad = Unchecked.defaultof<JsonElement>
                                let aad = if sElem.TryGetProperty("aad", &tmpAad) then hex (tmpAad.GetString()) else Array.empty<byte>
                                let mutable tmpCt = Unchecked.defaultof<JsonElement>
                                let ct = if sElem.TryGetProperty("ct", &tmpCt) then hex (tmpCt.GetString()) else Array.empty<byte>
                                let nonce = xorNonce baseNonce seq
                                // decrypt and compare
                                match Hpke.Core.Crypto.aesGcmDecrypt actualKey nonce aad ct with
                                | Some clear -> Assert.Equal<byte[]>(pt, clear)
                                | None -> Assert.True(false, sprintf "Decryption failed for vector %s seq %d" name seq)
                        | None -> ()
                    | None -> ()
                | None -> ()
                // If expected key/base_nonce present, verify derived key/nonce
                match get element "key" with
                | Some keyEl ->
                    let expected = hex (keyEl.GetString())
                    let prk = Hpke.Core.Crypto.hkdfExtract null shared
                    let actualKey = Hpke.Core.Crypto.hkdfExpand prk (Array.empty<byte>) expected.Length
                    Assert.Equal<byte[]>(expected, actualKey)
                | None -> ()

                // Verify exporter outputs if present: hkdfExpand(exporter_secret, exporter_context, L)
                match get element "exporter_secret" with
                | Some expEl ->
                    let expSec = hex (expEl.GetString())
                    match get element "exports" with
                    | Some exportsEl ->
                        for ex in exportsEl.EnumerateArray() do
                            let mutable tmp = Unchecked.defaultof<JsonElement>
                            let ctx = if ex.TryGetProperty("exporter_context", &tmp) then hex (tmp.GetString()) else Array.empty<byte>
                            let mutable tmp2 = Unchecked.defaultof<JsonElement>
                            let l = if ex.TryGetProperty("L", &tmp2) then tmp2.GetInt32() else 0
                            let mutable tmp3 = Unchecked.defaultof<JsonElement>
                            let expected = if ex.TryGetProperty("exported_value", &tmp3) then hex (tmp3.GetString()) else Array.empty<byte>
                            // Strict HKDF-Expand-Label construction (no fallback)
                            let labeled = hkdfExpandLabel expSec "exporter" ctx expected.Length
                            Assert.Equal<byte[]>(expected, labeled)
                    | None -> ()
                | None -> ()
            | _ -> ()
        | None -> ()
