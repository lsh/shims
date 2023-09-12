from math.bit import bswap
from sys.info import is_little_endian, sizeof


@always_inline
fn read_simd_native[
    T: DType
](owned bytes: SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]) -> SIMD[T, 1]:
    let ptr = Pointer.address_of(bytes).bitcast[SIMD[T, 1]]()
    return ptr.load()


@always_inline
fn read_simd_foreign[
    T: DType
](owned bytes: SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]) -> SIMD[T, 1]:
    return bswap[T, 1](read_simd_native[T](bytes))


@always_inline
fn from_le_bytes[
    T: DType
](owned bytes: SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]) -> SIMD[T, 1]:
    @parameter
    if is_little_endian():
        return read_simd_native[T](bytes)
    else:
        return read_simd_foreign[T](bytes)


@always_inline
fn from_be_bytes[
    T: DType, N: Int
](owned bytes: SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]) -> SIMD[T, 1]:
    @parameter
    if is_little_endian():
        return read_simd_foreign[T](bytes)
    else:
        return read_simd_native[T](bytes)


@always_inline
fn write_simd_native[
    T: DType
](owned value: SIMD[T, 1]) -> SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]:
    let ptr = DTypePointer[T](Pointer.address_of[SIMD[T, 1]](value)).bitcast[
        DType.uint8
    ]()
    return ptr.simd_load[sizeof[SIMD[T, 1]]()](0)


@always_inline
fn write_simd_foreign[
    T: DType
](owned value: SIMD[T, 1]) -> SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]:
    return bswap[DType.uint8, sizeof[SIMD[T, 1]]()](write_simd_native[T](value))


@always_inline
fn to_le_bytes[
    T: DType
](owned value: SIMD[T, 1]) -> SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]:
    @parameter
    if is_little_endian():
        return write_simd_native[T](value)
    else:
        return write_simd_foreign[T](value)


@always_inline
fn to_be_bytes[
    T: DType
](owned value: SIMD[T, 1]) -> SIMD[DType.uint8, sizeof[SIMD[T, 1]]()]:
    @parameter
    if is_little_endian():
        return write_simd_foreign[T](value)
    else:
        return write_simd_native[T](value)
