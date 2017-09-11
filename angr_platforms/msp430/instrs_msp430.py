import abc
from arch_msp430 import ArchMSP430
from pyvex.lift.util import *
import bitstring
from bitstring import Bits

REGISTER_TYPE = Type.int_16
BYTE_TYPE = Type.int_8
INDEX_TYPE = Type.int_16
STATUS_REG_IND = 2
CARRY_BIT_IND = 0
NEGATIVE_BIT_IND = 2
ZERO_BIT_IND = 1
OVERFLOW_BIT_IND = 8

##
## NOTE: The bitstream legend for this arch is:
# s: source
# d: destination
# A: source addressing mode
# a: destination addressing mode
# S: Extension word source immediate
# D: extension word destination immediate
# b: byte/word flag
# o: opcode
# O: Offset immediate

# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return Bits(bin=s).int

class MSP430Instruction(Instruction):

    @property
    def bin_format(self):
        return self.bin_format.replace('o' * len(self.opcode), self.opcode)

    def to_asm(self):
        return self.asm_format.format(self.__dict__) # TODO this is probably bad Python...also these need to encode to asm and currently they encode to strings

    def to_binary(self):
        output_data = {}
        for key, (ty, deps) in self.datamap.iteritems():
            binary_rep = getattr(self, key).to_binary()
            for dep, binrep in zip(deps, binary_rep):
                output_data[dep] = binrep
        binary = ''
        for c in self.bin_format:
            if c in '01':
                binary += c
            elif c in output_data:
                binary += output_data[c][0]
                output_data[c] = output_data[c][1:]
        return binary

# # TODO figure out how to deal with variable length encodings
# #      could it be done the same way that multiple ASM representations is done?
#  #
#      def parse(self, bitstrm):
#          """
#          MSP430 instructions can have one or two extension words for 16 bit immediates
#          We therefore extend the normal parsing so that we make sure we can
#          get another word if we have to.
#          """
#          data = Instruction.parse(self, bitstrm)
#          data['S'] = None
#          data['D'] = None
#          # We don't always have a source or destination.
#          # Theoretically I could put these in the TypeXInstruction classes, but
#          # I'm lazy. Note that we resolve these here, as opposed to later, due to
#          # needing to fiddle with the bitstream.
#          if 's' in data:
#              src_mode = int(data['A'], 2)
#              if (src_mode == ArchMSP430.Mode.INDEXED_MODE and data['s'] != '0011') \
#                      or (data['s'] == '0000' and src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE):
#                  data['S'] = bitstring.Bits(uint=bitstrm.read('uintle:16'), length=16).bin
#          if 'd' in data:
#              dst_mode = int(data['a'], 2)
#              if dst_mode == ArchMSP430.Mode.INDEXED_MODE:
#                  data['D'] = bitstring.Bits(uint=bitstrm.read('uintle:16'), length=16).bin
#          return data


    # Default flag handling
    def zero(self, *args):
        retval = args[-1]
        return retval == self.constant(0, retval.ty)

    def negative(self, *args):
        retval = args[-1]
        return retval[15] if self.data['b'] == '0' else retval[7]

    def carry(self, *args):
        return None

    def overflow(self, *args):
        return None

    # Some common stuff we use around

    def get_sr(self):
        return self.get(2, REGISTER_TYPE)

    def get_pc(self):
        return self.get(0, REGISTER_TYPE)

    def put_pc(self, val):
        return self.put(val, 0)

    def put_sr(self, val):
        return self.put(val, 2)

    def get_carry(self):
        return self.get_sr()[CARRY_BIT_IND]

    def get_zero(self):
        return self.get_sr()[ZERO_BIT_IND]

    def get_negative(self):
        return self.get_sr()[NEGATIVE_BIT_IND]

    def get_overflow(self):
        return self.get_sr()[OVERFLOW_BIT_IND]

    def match_instruction(self, data, bitstrm):
        # NOTE: The matching behavior for instructions is a "try-them-all-until-it-fits" approach.
        # Static bits are already checked, so we just look for the opcode.
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" % (self.opcode, data['o']))
        return True

    def assemble(self, ins, *ops):
        self.data = {}
        self.data['o'] = ins.opcode

    def lift(self):
        # The basic flow of an MSP430 instruction:
        # 0. Always do this:
        self.mark_instruction_start()
        # 1. Figure out what our operands are.
        inputs = self.fetch_operands()
        # 2. Do the actual instruction's "meat", and commit the result
        retval = self.compute_result(*inputs)
        args = inputs + (retval, )
        # 3. Update the flags:
        self.compute_flags(*args)
        # 4. Commit
        if retval is not None and self.commit_func is not None:
            self.commit_func(retval)

    def compute_flags(self, *args):
        """
        Compute the flags touched by each instruction
        and store them in the status register
        """
        z = self.zero(*args)
        n = self.negative(*args)
        c = self.carry(*args)
        o = self.overflow(*args)
        self.set_flags(z, n, c, o)

    def set_flags(self, z, n, c, o):
        # TODO: FIXME: This isn't actually efficient.
        if not self.zero and not self.overflow and not self.carry and not self.negative:
            return
        flags = [(z, ZERO_BIT_IND, 'Z'),
                 (n, NEGATIVE_BIT_IND, 'N'),
                 (o, OVERFLOW_BIT_IND, 'V'),
                 (c, CARRY_BIT_IND, 'C')]
        sreg = self.get_sr()
        for flag, offset, name in flags:
            if flag:
                sreg = sreg & ~(1 << offset) | (flag.cast_to(Type.int_16) << offset).cast_to(sreg.ty)
        self.put_sr(sreg)

    ##
    ## Functions for dealing with MSP430's complex addressing modes
    ##

    # The TypeXInstruction classes will do this.
    @abc.abstractmethod
    def fetch_operands(self):
        pass

##
## MSP430 has three instruction "types" (which type is which varies depending on which docs you read)
## These define the formats, and number of arguments.
## Here are the classes for those:
##

class Type1Instruction(MSP430Instruction):
    # A single argument
    datamap = { 'src'     : (SrcOperand, ('s', 'A', 'S')),
                'bitmode' : (BitMode, ('b')), }
    bin_format = "000100ooobAAssss"
    asm_format = '{name}{bitmode} {src}'

    @abc.abstractmethod
    def compute_result(self, src):
        pass

class Type2Instruction(MSP430Instruction):
    # No argument; jumps and branches
    self.datamap = { 'offset' : (Offset, ('O')), }
    bin_format = "001oooOOOOOOOOOO"
    asm_format = '{name} {offset}' # TODO figure out how to align these (maybe returning as a list is a good idea?)


    # No flags for all of type2
    def compute_flags(self, *args):
        pass

    @abc.abstractmethod
    def compute_result(self, offset):
        pass

class Type3Instruction(MSP430Instruction):
    # Two arguments
    self.datamap = { 'src'     : (SrcOperand, ['s', 'A', 'S']),
                     'dst'     : (DstOperand, ['d', 'a', 'D']),
                     'bitmode' : (BitMode, ['b']), }
    bin_format = 'oooossssabAAdddd'
    asm_format = '{name}{bitmode} {src} {dst}'

    @abc.abstractmethod
    def compute_result(self, src, dst):
        pass

##
## Single Operand Instructions (type 1)
##

class Instruction_RRC(Type1Instruction):
    # Rotate Right logical with carry-in.
    opcode = "000" # TODO I still dislike using this instead of bin_format unless they are automatically placed into bin_format
    name = 'rrc'

    def compute_result(self, src):
        # Get carry-in
        carryin = self.get_carry()
        # Do it
        src >>= 1
        # Put the carry-in in the right place
        if self.data['b'] == '1':
            src[7] = carryin
        else:
            src[15] = carryin
        # Write it out
        return src

    def carry(self, src, retval):
        return src[0]


class Instruction_SWPB(Type1Instruction):
    # Swap byte halves.  No B/W forms.
    opcode = '001'
    name = 'swpb'

    def compute_result(self, src):
        low_half = src[:8]
        high_half = src[8:]
        return high_half + (low_half << 8)


class Instruction_RRA(Type1Instruction):
    # Rotate Right Arithmetic.  Right shift with sign-extend.
    opcode = "010"
    name = 'rra'

    def compute_result(self, src, writeout):
        # Do it
        src >>= 1
        # A shitty sign-extend
        if self.data['b'] == '1':
            src[7] = src[6]
        else:
            src[15] = src[14]
        return src

    def carry(self, src, ret):
        return src[0]


class Instruction_SXT(Type1Instruction):
    # Sign extend 8 to 16 bits.
    # No b/w form.
    opcode = '011'
    name = 'sxt'

    def compute_result(self, src, writeout):
        return src.cast_to(Type.int_16, signed=True)


class Instruction_PUSH(Type1Instruction):
    # Push src onto the stack.
    opcode = '100'
    name = 'push'

    def compute_result(self, src):
        # Decrement SP
        sp = self.get(1, REGISTER_TYPE)
        sp -= 2
        # Store src at SP
        self.store(src, sp)
        # Store SP.  No write-out.
        self.put(sp, 1)

    # No flags.
    def negative(self, src, ret):
        pass

    def zero(self, src, ret):
        pass


class Instruction_CALL(Type1Instruction):
    opcode = '101'
    name = 'call'
    # Call src.  Pushes PC. No flags.

    def compute_result(self, src):
        # Push PC
        pc = self.get_pc()
        sp = self.get(1, Type.int_16)
        sp -= 2
        self.store(pc, sp)
        self.put_pc(src)
        # This ends the BB, update the IRSB
        self.jump(None, src, jumpkind=JumpKind.Call)

    def negative(self, src, ret):
        pass

    def zero(self, src, ret):
        pass


class Instruction_RETI(Type1Instruction):
    # Return *from interrupt*
    # Pop SR AND PC.
    opcode = '110'
    name = 'reti'

    def disassemble(self):
        return self, self.name, []

    def compute_result(self, src):
        # Pop the saved SR
        sp = self.get(1, REGISTER_TYPE)
        sr = self.get_sr()
        sp += 2
        # Pop the saved PC
        newpc = self.load(sp, Type.int_16)
        sp += 2
        # Store the popped values
        self.put_sr(sr)
        self.put_pc(newpc)
        # Jump to PC (setting the jumpkind)
        self.jump(None, newpc, jumpkind=JumpKind.Ret)

    def negative(self, ret):
        pass

    def zero(self, ret):
        pass

##
## Two operand instructions.
##


class Instruction_MOV(Type3Instruction):
    # Boring move.  No flags.
    opcode = '0100'
    name = 'mov'

    aliases = {'RET' : 'MOV @SP+,PC',
               'BR {dst}'  : 'MOV {dst},PC'}

    def disassemble(self):
        # support useful pseudo-ops for disassembly
        addr, name, args = Type3Instruction.disassemble(self)
        if self.data['d'] == '0000':
            if self.data['s'] == '0001':
                return addr, 'ret', []
            else:
                # If we're setting PC, but not from SP+, it's a BR instead
                return addr, 'br', [args[0]]
        else:
            return addr, name, args

    def compute_result(self, src, dst):
        # HACK: In MSP430, a MOV to R0 from SP is a RET.
        # VEX would like it very much if you set the jumpkind.
        if self.data['d'] == '0000':
            if self.data['s'] == '0001':
                self.jump(None, src, jumpkind=JumpKind.Ret)
            else:
                # If we're setting PC, but not from SP+, it's a BR instead
                self.jump(None, self.const(self.addr, REGISTER_TYPE))
        return src

    def negative(self, src, dst, ret):
        pass

    def zero(self, src, dst, ret):
        pass


class Instruction_ADD(Type3Instruction):
    # Add src + dst, set carry
    opcode = '0101'
    opcode = 'add'

    def compute_result(self, src, dst):
        return src + dst

    def compute_flags(self, src, dst, ret):
        # The flags for this are super ugly.
        if self.data['b'] == '0':
            src17 = src.cast_to(Type.int_17)
            dst17 = dst.cast_to(Type.int_17)
            ret17 = src17 + dst17
            c = ret17[16]
            o = (ret17[15] ^ src17[15]) & (ret17[15] ^ dst17[15])
        else:
            src9 = src.cast_to(Type.int_9)
            dst9 = dst.cast_to(Type.int_9)
            ret9 = src9 + dst9
            c = ret9[8]
            o = ((ret9[7] ^ src9[7]) & (ret9[7] ^ dst9[7])).cast_to(Type.int_1)
        z = self.zero(src, dst, writeout, retval)
        n = self.negative(src, dst, writeout, retval)
        self.set_flags(z, n, c, o)


class Instruction_ADDC(Type3Instruction):
    # dst = src + dst + C
    opcode = '0110'
    name = 'addc'

    def compute_result(self, src, dst, writeout):
        return src + dst + self.get_carry()

    def compute_flags(self, src, dst, writeout, retval):
        carryin = self.get_carry()
        if self.data['b'] == '0':
            src17 = src.cast_to(Type.int_17)
            dst17 = dst.cast_to(Type.int_17)
            ci17 = carryin.cast_to(Type.int_17)
            ret17 = src17 + dst17 + ci17
            c = ret17[16]
            o = ((ret17[15] ^ src17[15]) & (ret17[15] ^ dst17[15])).cast_to(Type.int_16)
        else:  # self.data['b'] == '1':
            src9 = src.cast_to(Type.int_9)
            dst9 = dst.cast_to(Type.int_9)
            ret9 = src9 + dst9
            c = ret9[8]
            o = ((ret9[7] ^ src9[7]) & (ret9[7] ^ dst9[7])).cast_to(Type.int_16)
        z = self.zero(src, dst, writeout, retval)
        n = self.negative(src, dst, writeout, retval)
        self.set_flags(z, n, c, o)


class Instruction_SUBC(Type3Instruction):
    opcode = '0111'
    name = 'subc'

    def compute_result(self, src, dst):
        return src - dst + self.get_carry()

    def overflow(self, src, dst, ret):
        # TODO: This is probably wrong
        if self.data['b'] == '0':
            return (ret[15] ^ src[15]) & (ret[15] ^ dst[15])
        else:
            return (ret[7] ^ src[7]) & (ret[7] ^ dst[7])

    def carry(self, src, dst, ret):
        return dst > (src + self.get_carry())


class Instruction_SUB(Type3Instruction):
    opcode = '1000'
    name = "sub"

    def compute_result(self, src, dst):
        return src - dst

    def overflow(self, src, dst, ret):
        # TODO: This is probably wrong
        if self.data['b'] == '0':
            return (ret[15] ^ src[15]) & (ret[15] ^ dst[15])
        else:
            return (ret[7] ^ src[7]) & (ret[7] ^ dst[7])

    def carry(self, src, dst, ret):
        return dst > src


class Instruction_CMP(Type3Instruction):
    opcode = '1001'
    name = 'cmp'

    def compute_result(self, src, dst):
        # Compute once, save for flags, don't commit
        self.ret = src - dst

    def zero(self, src, dst, ret):
        return self.ret == self.constant(0, self.ret.ty)

    def negative(self, src, dst, ret):
        return self.ret[15] if self.data['b'] == '0' else self.ret[7]

    def carry(self, src, dst, ret):
        return dst > src

    def overflow(self, src, dst, ret):
        if self.data['b'] == '0':
            # FIXME: this is probably wrong
            return (self.ret[15] ^ src[15]) & (self.ret[15] ^ dst[15])
        else:  # self.data['b'] == '1':
            # add.b
            return (self.ret[7] ^ src[7]) & (self.ret[7] ^ dst[7])


class Instruction_DADD(Type3Instruction):
    opcode = '1010'
    name = 'dadd'

    def compute_result(self, src, dst, writeout):
        # Ya know... fuck this...
        srcs = []
        dsts = []
        bits = 8 if self.data['b'] == '1' else 16
        ret = self.constant(0, BYTE_TYPE if self.data['b'] == '1' else REGISTER_TYPE)
        for x in range(0, bits, 4):
            srcs += src[x:x+3]
            dsts += dst[x:x+3]
        carry = self.get_carry()
        rets = []
        for s, d in zip(srcs, dsts):
            r = s + d + carry
            carry = r / 10
            r %= 10
            rets += r
        self.carry = carry #Carry computed in-line. save it.
        # Smash the digits back together
        for r, x in zip(rets, range(0, bits, 4)):
                ret | (r << x).cast_to(Type.int_16)
        return ret

    def carry(self, src, dst, ret):
        return self.carry

    def overflow(self, src, dst, ret):
        return None # WTF: Docs say this is actually undefined!?


class Instruction_BIC(Type3Instruction):
    # Bit Clear.  dst = ~src & dst
    opcode = '1100'
    name = 'bic'

    def compute_result(self, src, dst):
        return ~src & dst

    def negative(self, src, dst, ret):
        pass

    def zero(self, src, dst, ret):
        pass


class Instruction_BIS(Type3Instruction):
    # Bit Set.  Normal people call this "or"
    opcode = '1101'
    name = 'bis'

    def compute_result(self, src, dst):
        return src | dst


class Instruction_BIT(Type3Instruction):
    # Bit Test. Just update flags.  No write-out
    opcode = "1011"
    name = "bit"

    def compute_result(self, src, dst):
        return src & dst

    def zero(self, src, dst, ret):
        return self.constant(0, ret.ty)

    def carry(self, src, dst, ret):
        return ret != self.constant(0, ret.ty)


class Instruction_XOR(Type3Instruction):
    # Exclusive Or
    opcode = "1110"
    name = 'xor'

    def compute_result(self, src, dst):
        return src ^ dst

    def carry(self, src, dst, ret):
        return ret != self.constant(0, ret.ty)

    def overflow(self, src, dst, ret):
        if self.data['b'] == '1':
            return src[7] & dst[7]
        else:
            return src[15] & dst[15]


class Instruction_AND(Type3Instruction):
    # Logical and.
    opcode = "1111"
    name = 'and'

    def compute_result(self, src, dst):
        return src & dst

    def overflow(self, src, dst, ret):
        return self.constant(0, ret.ty)

    def carry(self, src, dst, ret):
        return ret != self.constant(0, ret.ty)

##
## Zero-operand Jumps
##


class Instruction_JNE(Type2Instruction):
    opcode = '000'
    name = 'jne'

    def compute_result(self, dst):
        self.jump(self.get_zero() != 0, dst)


class Instruction_JEQ(Type2Instruction):
    opcode = '001'
    name = 'jeq'

    def compute_result(self, dst):
        self.jump(self.get_zero() == 0, dst)


class Instruction_JNC(Type2Instruction):
    opcode = '010'
    name = 'jnc'

    def compute_result(self, dst):
        self.jump(self.get_carry() == 0, dst)


class Instruction_JC(Type2Instruction):
    opcode = '011'
    name = 'jc'

    def compute_result(self, dst):
        self.jump(self.get_carry() != 0, dst)


class Instruction_JN(Type2Instruction):
    opcode = '100'
    name = 'jn'

    def compute_result(self, dst):
        self.jump(self.get_negative() != 0, dst)


class Instruction_JGE(Type2Instruction):
    opcode = '101'
    name = 'jge'

    def compute_result(self, dst):
        self.jump(self.get_negative() == self.get_overflow(), dst)


class Instruction_JL(Type2Instruction):
    opcode = '110'
    name = 'jl'

    def compute_result(self, dst):
        self.jump(self.get_negative() == self.get_overflow(), dst)


class Instruction_JMP(Type2Instruction):
    opcode = '111'
    name = 'jl'

    def compute_result(self, dst):
        self.jump(None, dst)
