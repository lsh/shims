"""
A port of Zig's Wyhash
See: https://github.com/ziglang/zig/blob/master/lib/std/hash/wyhash.zig
"""
from memory.unsafe import DTypePointer, Pointer
from memory import memcpy, memset_zero, stack_allocation
from utils.static_tuple import StaticTuple
from utils.list import Dim
import testing

from shims.bitcast import from_le_bytes

alias UInt64x4 = SIMD[DType.uint64, 4]


@always_inline
fn mum(inout a: UInt64, inout b: UInt64):
    let x = _umul128(a, b)
    a = x[0]
    b = x[1]


@always_inline
fn mix(a_: UInt64, b_: UInt64) -> UInt64:
    var a = a_
    var b = b_
    mum(a, b)
    return a ^ b


@always_inline
fn _umul128(multiplier: UInt64, multiplicand: UInt64) -> SIMD[DType.uint64, 2]:
    """Taken from stack overflow.
    https://stackoverflow.com/a/46923106
    """
    # multiplier   = ab = a * 2^32 + b
    # multiplicand = cd = c * 2^32 + d
    # ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    let a = multiplier >> 32
    let b = multiplier & 0xFFFFFFFF
    let c = multiplicand >> 32
    let d = multiplicand & 0xFFFFFFFF

    # let ac = a * c
    let ad = a * d
    # let bc = b * c
    let bd = b * d

    let adbc = ad + (b * c)
    let adbc_carry = 1 if adbc < ad else 0

    # multiplier * multiplicand = product_hi * 2^64 + product_lo
    let product_lo = bd + (adbc << 32)
    let product_lo_carry = 1 if product_lo < bd else 0
    let product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry

    return SIMD[DType.uint64, 2](product_hi, product_lo)


fn test_umul128() raises:
    let a: UInt64
    let b: UInt64
    a, b = UInt64(0x0FFFFFFFFFFFFFFF), UInt64(0xF0000000)
    # testing.assert_equal(
    #     _umul128(a, b), SIMD[DType.uint64, 2](0xEFFFFFF, 0xFFFFFFFF10000000)
    # )


struct Wyhash:
    var _secret: UInt64x4
    var a: UInt64
    var b: UInt64

    # we only care about the first three values
    var state: StaticTuple[3, UInt64]
    var total_len: Int

    var buf: StaticTuple[48, UInt8]
    var buf_len: Int

    fn __init__(inout self, seed: UInt64):
        self._secret = SIMD[DType.uint64, 4](
            0xA0761D6478BD642F,
            0xE7037ED1A0B428DB,
            0x8EBC6AF09C88C6E3,
            0x589965CC75374CC3,
        )
        self.a = 0
        self.b = 0
        self.buf_len = 0
        self.total_len = 0
        self.state = StaticTuple[3, UInt64]()
        self.buf = StaticTuple[48, UInt8]()
        memset_zero(Pointer.address_of(self.buf).bitcast[UInt8](), 48)

        self.state[0] = seed ^ mix(seed ^ self._secret[0], self._secret[1])
        self.state[1] = self.state[0]
        self.state[2] = self.state[0]

    @always_inline
    fn __copyinit__(inout self, other: Self):
        self.a = other.a
        self.b = other.b
        self.state = other.state
        self.total_len = other.total_len
        self.buf_len = 0
        self.buf = StaticTuple[48, UInt8]()
        self._secret = UInt64x4(
            0xA0761D6478BD642F,
            0xE7037ED1A0B428DB,
            0x8EBC6AF09C88C6E3,
            0x589965CC75374CC3,
        )

    # This is subtly different from other hash function update calls. Wyhash requires the last
    # full 48-byte block to be run through final1 if is exactly aligned to 48-bytes.
    @always_inline
    fn update[D: Dim](inout self, input: Buffer[D, DType.uint8]):
        self.total_len += len(input)

        if len(input) <= 48 - self.buf_len:
            memcpy(
                DTypePointer[DType.uint8](
                    Pointer.address_of(self.buf).bitcast[UInt8]().offset(self.buf_len)
                ),
                input.data,
                len(input),
            )
            self.buf_len += len(input)
            return

        var i = 0
        if self.buf_len > 0:
            i = 48 - self.buf_len
            memcpy(
                Pointer.address_of(self.buf).bitcast[UInt8]().offset(self.buf_len),
                input.data,
                i,
            )
            self.round(
                Buffer[48, DType.uint8](Pointer.address_of(self.buf).bitcast[UInt8]())
            )
            self.buf_len = 0

        for i in range(i, len(input), 48):
            self.round(
                Buffer[48, DType.uint8](input.data.offset(i).as_scalar_pointer())
            )

        let remaining_bytes = Buffer[Dim(), DType.uint8](
            input.data.offset(i), len(input) - i
        )
        if len(remaining_bytes) < 16 and i >= 48:
            let rem = 16 - len(remaining_bytes)
            memcpy(
                Pointer.address_of(self.buf)
                .bitcast[UInt8]()
                .offset(self.buf.__len__() - rem),
                input.data.offset(i - rem),
                i,
            )
        memcpy(
            Pointer.address_of(self.buf).bitcast[UInt8](),
            remaining_bytes.data.as_scalar_pointer(),
            len(remaining_bytes),
        )
        self.buf_len = len(remaining_bytes)

    @always_inline
    fn final(inout self) -> UInt64:
        let input_ptr = Pointer.address_of(self.buf).bitcast[UInt8]()
        var input = Buffer[Dim(), DType.uint8](input_ptr, self.buf_len)
        var new_self = self  # ensure idempotency

        if self.total_len <= 16:
            new_self.small_key(input)
        else:
            var offset: Int = 0
            if self.buf_len < 16:
                var scratch = StaticTuple[16, UInt8]()
                let scratch_pointer = Pointer.address_of(scratch).bitcast[UInt8]()
                let buf_ptr = Pointer.address_of(self.buf).bitcast[UInt8]()
                let rem = 16 - self.buf_len
                memcpy(scratch_pointer, buf_ptr.offset(self.buf.__len__() - rem), rem)
                memcpy(scratch_pointer.offset(rem), buf_ptr, self.buf_len)

                # Same as input but with additional bytes preceeding start in case of a short buffer
                input = Buffer[Dim(), DType.uint8](scratch_pointer, 16)
                offset = rem

            new_self.final0()
            new_self.final1(input, offset)

        return new_self.final2()

    @staticmethod
    fn hash[D: Dim](seed: UInt64, input: Buffer[D, DType.uint8]) -> UInt64:
        var self = Self(seed)

        if len(input) <= 16:
            self.small_key(input)
        else:
            var i: Int = 0
            if len(input) >= 48:
                while i + 48 < len(input):
                    self.round(Buffer[48, DType.uint8](input.data.offset(i)))
                    i += 48
                self.final0()
            self.final1(input, i)

        self.total_len = len(input)
        return self.final2()

    @always_inline
    fn small_key[D: Dim](inout self, input: Buffer[D, DType.uint8]):
        # constrained[D.get() <= 16]()
        if len(input) >= 4:
            let end = len(input) - 4
            let quarter = (len(input) >> 3) << 2

        #     self.a = (
        #         UInt64(
        #             (
        #                 from_le_bytes[DType.uint32](
        #                     Buffer[sizeof[UInt32](), DType.uint8](input.data)
        #                 )
        #             ).to_int()
        #         )
        #         << 32
        #     ) | UInt64(
        #         from_le_bytes[DType.uint32](
        #             Buffer[sizeof[UInt32](), DType.uint8](input.data.offset(quarter))
        #         ).to_int()
        #     )
        #     self.b = (
        #         UInt64(
        #             (
        #                 from_le_bytes[DType.uint32](
        #                     Buffer[sizeof[UInt32](), DType.uint8](
        #                         input.data.offset(end)
        #                     )
        #                 )
        #             ).to_int()
        #         )
        #         << 32
        #     ) | UInt64(
        #         from_le_bytes[DType.uint32](
        #             Buffer[sizeof[UInt32](), DType.uint8](
        #                 input.data.offset(end - quarter)
        #             )
        #         ).to_int()
        #     )
        # elif len(input) > 0:
        #     self.a = (
        #         (UInt64(input[0].to_int()) << 16)
        #         | (UInt64(input[len(input) >> 1].to_int()) << 8)
        #         | UInt64(input[len(input) - 1].to_int())
        #     )
        #     self.b = 0
        # else:
        #     self.a = 0
        #     self.b = 0

    fn round(inout self, input: Buffer[48, DType.uint8]):
        @unroll
        for i in range(3):
            # let a = from_le_bytes[DType.uint64](
            #     Buffer[sizeof[UInt64](), DType.uint8](input.data.offset(8 * (2 * i)))
            # )
            # let b = from_le_bytes[DType.uint64](
            #     Buffer[sizeof[UInt64](), DType.uint8](
            #         input.data.offset(8 * (2 * i + 1))
            #     )
            # )
            # self.state[i] = mix(a ^ self._secret[i + 1], b ^ self.state[i])
            pass

    @always_inline
    fn final0(inout self):
        self.state[0] ^= self.state[1] ^ self.state[2]

    #  input_lb must be at least 16-bytes long (in shorter key cases the smallKey function will be
    #  used instead). We use an index into a slice to for comptime processing as opposed to if we
    #  used pointers.
    fn final1[D: Dim](inout self, input_lb: Buffer[D, DType.uint8], start_pos: Int):
        # constrained(input_lb.len >= 16);
        # constrained(input_lb.len - start_pos <= 48);
        let input = Buffer[Dim(), DType.uint8](
            input_lb.data.offset(start_pos), len(input_lb) - start_pos
        )

        for i in range(0, len(input), 16):
            pass
            # self.state[0] = mix(
            #     from_le_bytes[DType.uint64](
            #         Buffer[sizeof[UInt64](), DType.uint8](
            #             input.data.offset(i), len(input) - i
            #         )
            #     )
            #     ^ self._secret[1],
            #     from_le_bytes[DType.uint64](
            #         Buffer[sizeof[UInt64](), DType.uint8](
            #             input.data.offset(i + 8), len(input) - i + 8
            #         )
            #     )
            #     ^ self.state[0],
            # )

        # self.a = from_le_bytes[DType.uint64](
        #     Buffer[sizeof[UInt64](), DType.uint8](
        #         input_lb.data.offset(len(input_lb) - 16)
        #     )
        # )
        # self.b = from_le_bytes[DType.uint64](
        #     Buffer[sizeof[UInt64](), DType.uint8](
        #         input_lb.data.offset(len(input_lb) - 8)
        #     )
        # )

    @always_inline
    fn final2(inout self) -> UInt64:
        self.a ^= self._secret[1]
        print(self._secret[1])
        self.b ^= self.state[0]
        mum(self.a, self.b)
        return mix(self.a ^ self._secret[0] ^ self.total_len, self.b ^ self._secret[1])
