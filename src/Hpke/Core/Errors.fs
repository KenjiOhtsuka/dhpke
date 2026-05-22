namespace Hpke.Core

type HpkeError =
    | InvalidArgument of name: string * reason: string
    | InvalidLength of name: string * expected: string * actual: int
    | UnsupportedMode of HpkeMode
    | UnsupportedAlgorithm of string
    | MissingPsk
    | MissingAuthKey
    | NotImplemented of feature: string