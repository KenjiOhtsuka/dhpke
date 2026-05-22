namespace Hpke.Core

module RequestValidation =
    let requireNotNull name value =
        if obj.ReferenceEquals(box value, null) then
            Error (HpkeError.InvalidArgument(name, "value must not be null"))
        else
            Ok value

    let requireNotEmptyBytes name (value: byte[]) =
        if obj.ReferenceEquals(box value, null) then
            Error (HpkeError.InvalidArgument(name, "value must not be null"))
        elif value.Length = 0 then
            Error (HpkeError.InvalidLength(name, "at least 1 byte", 0))
        else
            Ok value

    let requireNullableNotNull name value =
        requireNotNull name value