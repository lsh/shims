"""
This is a port of Zig's SipHash
See: https://github.com/ziglang/zig/blob/master/lib/std/crypto/siphash.zig
"""

from memory.buffer import Buffer
from utils.list import Dim
from memory import memcpy, memset_zero
from memory.unsafe import Pointer, DTypePointer
from sys.info import sizeof
from math import rotate_bits_left
from utils.static_tuple import StaticTuple
from math import min
import testing

from shims.bitcast import from_be_bytes, from_le_bytes, to_le_bytes


@always_inline
fn slice_buf[T: DType, D: Dim](b: Buffer[D, T], slc: slice) -> Buffer[Dim(), T]:
    return Buffer[Dim(), T](b.data.offset(slc.start), slc.__len__())


@value
struct SipHashStateless[T: DType, C_ROUNDS: Int, D_ROUNDS: Int]:
    alias block_length = 64
    alias key_length = 16

    var v0: UInt64
    var v1: UInt64
    var v2: UInt64
    var v3: UInt64
    var msg_len: UInt8

    @always_inline
    fn __init__(inout self, key: Buffer[Self.key_length, DType.uint8]) raises:
        # constrained[T == DType.uint64 or T == DType.uint128]()
        constrained[T == DType.uint64]()
        constrained[C_ROUNDS > 0 and D_ROUNDS > 0]()

        let k0: UInt64 = from_le_bytes[DType.uint64](key.simd_load[sizeof[UInt64]()](0))
        let k1: UInt64 = from_le_bytes[DType.uint64](key.simd_load[sizeof[UInt64]()](8))

        self.v0 = k0 ^ UInt64(0x736F6D6570736575)
        self.v1 = k1 ^ UInt64(0x646F72616E646F6D)
        self.v2 = k0 ^ UInt64(0x6C7967656E657261)
        self.v3 = k1 ^ UInt64(0x7465646279746573)
        self.msg_len = UInt8(0)

        #   @parameter if T == DType.128:
        #       self.v1 ^= 0xee;

    @always_inline
    fn update[D: Dim](inout self, b: Buffer[D, DType.uint8]):
        # std.debug.assert(b.len % 8 == 0);

        for off in range(0, len(b), 8):
            let blob = b.simd_load[8](off)
            self.round(blob)

        self.msg_len += UInt8(len(b))

    fn final[D: Dim](inout self, b: Buffer[D, DType.uint8]) -> SIMD[T, 1]:
        #       constrained[len(b) < 8](b.len < 8);
        self.msg_len += UInt8(len(b))

        let buf = Buffer[8, DType.uint8]().stack_allocation()
        memset_zero(buf.data, 8)

        memcpy(buf.data, b.data, len(b))
        buf[7] = self.msg_len
        self.round(buf.simd_load[8](0))

        @parameter
        if T == DType.uint64:
            self.v2 ^= 0xFF
        else:
            self.v2 ^= 0xEE

        @unroll
        for _ in range(D_ROUNDS):
            self.sip_round()

        let b1 = (self.v0 ^ self.v1 ^ self.v2 ^ self.v3).to_int()
        return SIMD[T, 1](b1)

        ## TODO: remove above return when UInt128 is available

        # @parameter if T == dtype.uint64:
        #     return b1

        # self.v1 ^= 0xdd;

        # @unroll
        # for _ in range(D_ROUNDS):
        #     self.sip_round()

        # let b2 = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;
        # return (UInt128(b2) << 64) | b1

    @always_inline
    fn round(inout self, owned b: SIMD[DType.uint8, 8]):
        var m_buf = SIMD[DType.uint8, sizeof[UInt64]()]()

        @unroll
        for i in range(8):
            m_buf[i] = b[i]
        let m = from_le_bytes[DType.uint64](m_buf)
        self.v3 ^= m

        @unroll
        for i in range(C_ROUNDS):
            self.sip_round()
        self.v0 ^= m

    @always_inline
    fn sip_round(inout self):
        self.v0 += self.v1
        self.v1 = rotate_bits_left[13](self.v1)
        self.v1 ^= self.v0
        self.v0 = rotate_bits_left[32](self.v0)
        self.v2 += self.v3
        self.v3 = rotate_bits_left[16](self.v3)
        self.v3 ^= self.v2
        self.v0 += self.v3
        self.v3 = rotate_bits_left[21](self.v3)
        self.v3 ^= self.v0
        self.v2 += self.v1
        self.v1 = rotate_bits_left[17](self.v1)
        self.v1 ^= self.v2
        self.v2 = rotate_bits_left[32](self.v2)

    @staticmethod
    fn hash[
        MsgD: Dim
    ](
        msg: Buffer[MsgD, DType.uint8], key: Buffer[Self.key_length, DType.uint8]
    ) raises -> SIMD[T, 1]:
        let aligned_len = len(msg) - (len(msg) % 8)
        var c = Self(key)
        c.update(slice_buf(msg, slice(0, aligned_len)))
        return c.final(slice_buf(msg, slice(aligned_len, len(msg))))


# TOOD: remove once fix for aliasing static tuples is released
fn make_test_data() -> StaticTuple[63, SIMD[DType.uint8, 8]]:
    return StaticTuple[63, SIMD[DType.uint8, 8]](
        SIMD[DType.uint8, 8](49, 14, 14, 221, 71, 219, 111, 114),
        SIMD[DType.uint8, 8](253, 103, 220, 147, 197, 57, 248, 116),
        SIMD[DType.uint8, 8](90, 79, 169, 217, 9, 128, 108, 13),
        SIMD[DType.uint8, 8](45, 126, 251, 215, 150, 102, 103, 133),
        SIMD[DType.uint8, 8](183, 135, 113, 39, 224, 148, 39, 207),
        SIMD[DType.uint8, 8](141, 166, 153, 205, 100, 85, 118, 24),
        SIMD[DType.uint8, 8](206, 227, 254, 88, 110, 70, 201, 203),
        SIMD[DType.uint8, 8](55, 209, 1, 139, 245, 0, 2, 171),
        SIMD[DType.uint8, 8](98, 36, 147, 154, 121, 245, 245, 147),
        SIMD[DType.uint8, 8](176, 228, 169, 11, 223, 130, 0, 158),
        SIMD[DType.uint8, 8](243, 185, 221, 148, 197, 187, 93, 122),
        SIMD[DType.uint8, 8](167, 173, 107, 34, 70, 47, 179, 244),
        SIMD[DType.uint8, 8](251, 229, 14, 134, 188, 143, 30, 117),
        SIMD[DType.uint8, 8](144, 61, 132, 192, 39, 86, 234, 20),
        SIMD[DType.uint8, 8](238, 242, 122, 142, 144, 202, 35, 247),
        SIMD[DType.uint8, 8](229, 69, 190, 73, 97, 202, 41, 161),
        SIMD[DType.uint8, 8](219, 155, 194, 87, 127, 204, 42, 63),
        SIMD[DType.uint8, 8](148, 71, 190, 44, 245, 233, 154, 105),
        SIMD[DType.uint8, 8](156, 211, 141, 150, 240, 179, 193, 75),
        SIMD[DType.uint8, 8](189, 97, 121, 167, 29, 201, 109, 187),
        SIMD[DType.uint8, 8](152, 238, 162, 26, 242, 92, 214, 190),
        SIMD[DType.uint8, 8](199, 103, 59, 46, 176, 203, 242, 208),
        SIMD[DType.uint8, 8](136, 62, 163, 227, 149, 103, 83, 147),
        SIMD[DType.uint8, 8](200, 206, 92, 205, 140, 3, 12, 168),
        SIMD[DType.uint8, 8](148, 175, 73, 246, 198, 80, 173, 184),
        SIMD[DType.uint8, 8](234, 184, 133, 138, 222, 146, 225, 188),
        SIMD[DType.uint8, 8](243, 21, 187, 91, 184, 53, 216, 23),
        SIMD[DType.uint8, 8](173, 207, 107, 7, 99, 97, 46, 47),
        SIMD[DType.uint8, 8](165, 201, 29, 167, 172, 170, 77, 222),
        SIMD[DType.uint8, 8](113, 101, 149, 135, 102, 80, 162, 166),
        SIMD[DType.uint8, 8](40, 239, 73, 92, 83, 163, 135, 173),
        SIMD[DType.uint8, 8](66, 195, 65, 216, 250, 146, 216, 50),
        SIMD[DType.uint8, 8](206, 124, 242, 114, 47, 81, 39, 113),
        SIMD[DType.uint8, 8](227, 120, 89, 249, 70, 35, 243, 167),
        SIMD[DType.uint8, 8](56, 18, 5, 187, 26, 176, 224, 18),
        SIMD[DType.uint8, 8](174, 151, 161, 15, 212, 52, 224, 21),
        SIMD[DType.uint8, 8](180, 163, 21, 8, 190, 255, 77, 49),
        SIMD[DType.uint8, 8](129, 57, 98, 41, 240, 144, 121, 2),
        SIMD[DType.uint8, 8](77, 12, 244, 158, 229, 212, 220, 202),
        SIMD[DType.uint8, 8](92, 115, 51, 106, 118, 216, 191, 154),
        SIMD[DType.uint8, 8](208, 167, 4, 83, 107, 169, 62, 14),
        SIMD[DType.uint8, 8](146, 89, 88, 252, 214, 66, 12, 173),
        SIMD[DType.uint8, 8](169, 21, 194, 155, 200, 6, 115, 24),
        SIMD[DType.uint8, 8](149, 43, 121, 243, 188, 10, 166, 212),
        SIMD[DType.uint8, 8](242, 29, 242, 228, 29, 69, 53, 249),
        SIMD[DType.uint8, 8](135, 87, 117, 25, 4, 143, 83, 169),
        SIMD[DType.uint8, 8](16, 165, 108, 245, 223, 205, 154, 219),
        SIMD[DType.uint8, 8](235, 117, 9, 92, 205, 152, 108, 208),
        SIMD[DType.uint8, 8](81, 169, 203, 158, 203, 163, 18, 230),
        SIMD[DType.uint8, 8](150, 175, 173, 252, 44, 230, 102, 199),
        SIMD[DType.uint8, 8](114, 254, 82, 151, 90, 67, 100, 238),
        SIMD[DType.uint8, 8](90, 22, 69, 178, 118, 213, 146, 161),
        SIMD[DType.uint8, 8](178, 116, 203, 142, 191, 135, 135, 10),
        SIMD[DType.uint8, 8](111, 155, 180, 32, 61, 231, 179, 129),
        SIMD[DType.uint8, 8](234, 236, 178, 163, 11, 34, 168, 127),
        SIMD[DType.uint8, 8](153, 36, 164, 60, 193, 49, 87, 36),
        SIMD[DType.uint8, 8](189, 131, 141, 58, 175, 191, 141, 183),
        SIMD[DType.uint8, 8](11, 26, 42, 50, 101, 213, 26, 234),
        SIMD[DType.uint8, 8](19, 80, 121, 163, 35, 28, 230, 96),
        SIMD[DType.uint8, 8](147, 43, 40, 70, 228, 215, 6, 102),
        SIMD[DType.uint8, 8](225, 145, 95, 92, 177, 236, 164, 108),
        SIMD[DType.uint8, 8](243, 37, 150, 92, 161, 109, 98, 159),
        SIMD[DType.uint8, 8](87, 95, 242, 142, 96, 56, 27, 229),
        SIMD[DType.uint8, 8](114, 69, 6, 235, 76, 50, 138, 149),
    )


@value
struct SipHash[T: DType, C_ROUNDS: Int, D_ROUNDS: Int]:
    alias key_length = 16
    alias mac_length = sizeof[SIMD[T, 1]]()
    alias block_length = 8

    alias State = SipHashStateless[T, C_ROUNDS, D_ROUNDS]
    var state: Self.State
    var ptr: DTypePointer[DType.uint8]
    var buf: Buffer[8, DType.uint8]
    var buf_len: Int

    fn __init__(inout self, key: Buffer[Self.key_length, DType.uint8]) raises:
        # constrained[T == DType.uint64 or T== DType.uint128]()
        constrained[T == DType.uint64]()
        constrained[C_ROUNDS > 0 and D_ROUNDS > 0]()
        self.state = SipHashStateless[T, C_ROUNDS, D_ROUNDS](key)
        self.ptr = DTypePointer[DType.uint8]().alloc(8)
        self.buf = Buffer[8, DType.uint8](self.ptr)
        self.buf_len = 0

    fn update(inout self, b: Buffer[Dim(), DType.uint8]):
        """
        Add data to the state.
        """

        var off = 0

        if self.buf_len != 0 and self.buf_len + len(b) >= 8:
            off += 8 - self.buf_len
            memcpy(self.buf.data.offset(self.buf_len), b.data, off)
            self.state.update(self.buf)
            self.buf_len = 0

        let remain_len = len(b) - off
        let aligned_len = remain_len - (remain_len % 8)
        self.state.update(slice_buf(b, slice(off, off + aligned_len)))

        let b_slice = slice_buf(b, slice(off + aligned_len, len(b)))
        memcpy(self.buf.data.offset(self.buf_len), b_slice.data, len(b_slice))
        self.buf_len += len(b_slice)

    fn peek(self) -> Buffer[Self.mac_length, DType.uint8]:
        var copy = self
        return copy.final_result()

    fn final(inout self, out: Buffer[Self.mac_length, DType.uint8]):
        """
        Return an authentication tag for the current state
        Assumes `out` is less than or equal to `mac_length`.
        """
        let s = self.state.final(slice_buf(self.buf, slice(0, self.buf_len)))
        let bytes = to_le_bytes(s)
        out.simd_store[Self.mac_length](0, bytes)

    fn final_result(inout self) -> Buffer[Self.mac_length, DType.uint8]:
        let result = Buffer[Self.mac_length, DType.uint8]().stack_allocation()
        self.final(result)
        return result

    @staticmethod
    fn create(
        out: Buffer[Self.mac_length, DType.uint8],
        msg: Buffer[Dim(), DType.uint8],
        key: Buffer[Self.key_length, DType.uint8],
    ) raises:
        """
        Return an authentication tag for a message and a key.
        """

        var ctx = Self(key)
        ctx.update(msg)
        ctx.final(out)

    fn final_int(inout self) -> SIMD[T, 1]:
        """
        Return an authentication tag for the current state, as an integer.
        """

        return self.state.final(slice_buf(self.buf, slice(0, self.buf_len)))

    @staticmethod
    fn to_int(
        msg: Buffer[Dim(), DType.uint8],
        key: Buffer[Self.key_length, DType.uint8],
    ) raises -> SIMD[T, 1]:
        """
        Return an authentication tag for a message and a key, as an integer.
        """

        return Self.State.hash(msg, key)

    fn __del__(owned self):
        self.ptr.free()


alias UInt8x8 = SIMD[DType.uint8, 8]


alias SipHash24 = SipHash[DType.uint64, 2, 4]


fn test_siphash64_2_4(test_key: Buffer[16, DType.uint8]) raises:
    let msg = Buffer[64, DType.uint8]().stack_allocation()
    let test_data = make_test_data()
    for i in range(test_data.__len__()):
        msg[i] = i
        let out = Buffer[SipHash24.mac_length, DType.uint8]().stack_allocation()
        SipHash24.create(out, slice_buf(msg, slice(0, i)), test_key)
        let out_str = String(
            StringRef(out.data.bitcast[DType.int8]().address, SipHash24.mac_length)
        )
        var vector = test_data[i]
        let vector_str = String(
            StringRef(
                Pointer.address_of[SIMD[DType.uint8, 8]](vector)
                .bitcast[__mlir_type.`!pop.scalar<si8>`]()
                .address,
                SipHash24.mac_length,
            )
        )
        if not testing.assert_equal(vector_str, out_str):
            raise Error("failed")


fn test_iterative_non_divisible_update() raises:
    alias BUF_LEN = 1024
    let buf = Buffer[BUF_LEN, DType.uint8]().stack_allocation()

    @unroll
    for i in range(BUF_LEN):
        buf[i] = i

    let key_str = String("0x128dad08f12307")
    let key = Buffer[SipHash24.key_length, DType.uint8]().stack_allocation()

    for i in range(SipHash24.key_length):
        key[i] = ord(key_str[i])

    let end = 9
    for _ in range(end, len(buf), 9):
        let non_iterative_hash = SipHash24.to_int(slice_buf(buf, slice(0, end)), key)
        var siphash = SipHash24(key)
        for i in range(0, end, 7):
            siphash.update(slice_buf(buf, slice(i, min(i + 7, end))))
        let iterative_hash = siphash.final_int()
        if not testing.assert_equal(iterative_hash, non_iterative_hash):
            raise Error("failed")


fn run_tests() raises:
    # Test vectors from reference implementation.
    # https://github.com/veorq/SipHash/blob/master/vectors.h
    let bufptr = DTypePointer[DType.uint8]().alloc(16)
    let test_key = Buffer[
        16,
        DType.uint8,
    ](bufptr)
    test_key.simd_store[16](
        0,
        SIMD[DType.uint8, 16](
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0xA,
            0xB,
            0xC,
            0x0D,
            0x0E,
            0x0F,
        ),
    )

    test_siphash64_2_4(test_key)
    test_iterative_non_divisible_update()
