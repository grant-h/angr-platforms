import archinfo
import pyvex
from pyvex.lift.util import *
from pyvex.lift import register
from arch_bf import ArchBF
import bitstring
import sys
import os
import claripy
from angr import SimValueError
import logging

log = logging.getLogger("LifterBF")

# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017
# Rewrote by edg for gymrat on 9/4/2017
# The goal of this, and any other lifter, is to convert one basic block of raw bytes into
# a set of VEX instructions representing what the code does.
# A basic block, in this case is defined a set of instructions terminated by:
# !) a conditional branch
# 2) A function call
# 3) A system call
# 4) the end of the program
#
# We need to build an IRSB, a grouping of VEX code, and associated metadata representing one block.
# This is then used by angr itself to perform static analysis and symbolic execution.

##
# These helper functions are how we resolve jumps in BF.
# Because they require scanning the actual code to resolve, they require a global view of the program's memory.
# Lifters in pyvex only get block-at-a-time access to memory, so we solve this by using a "CCall", which tells VEX
# /angr to execute a side-effect-less function and put the result in a variable.
# We therefore let angr resolve all jumps at "run"-time.
# TODO: FIXME: We need to refactor CCall to be more friendly to adding CCalls.  I will document the process
# here as best I can.


def _build_jump_table(state):
    """
    This is the standard stack algorithm for bracket-matching, which is also how we resolve jumps in BF
    :param state:
    :return:
    """
    jump_table = {}
    jstack = []
    addr = 0
    while True:
        try:
            inst = chr(state.mem_concrete(addr, 1))
        except SimValueError:
            break
        except KeyError:
            break
        if inst == '[':
            jstack.append(addr)
        elif inst == ']':
            try:
                src = jstack.pop()
                dest = addr
                jump_table.update({src: dest + 1})
                jump_table.update({dest: src + 1})
            except IndexError:
                raise ValueError("Extra ] at offset %d" % inst)
        addr += 1
    if jstack:
        raise ValueError("Unmatched [s at: " + ",".join(jstack))
    return jump_table


def bf_resolve_jump(state):
    """
    Resolve the jump at the current IP of the state.
    :param state:
    :return:
    """
    # CCall won't give us the addr of the current instruction, so we have to figure that out.  Ugh.
    real_ip = state.se.eval(state.ip)
    offset = 0
    while True:
        inst = chr(state.mem_concrete(real_ip + offset, 1))
        if inst == "]" or inst == '[':
            addr = real_ip + offset
            break
        offset += 1
    # We don't have a persistent place to compute the jump table, and because brackets can be nested, we must construct
    # the full table each time instead of doing a scan back/forward.
    # Some day, if we ever get a nice place to put this, this should only be computed once.
    jtable = _build_jump_table(state)
    real_ip = state.se.eval(addr)
    try:
        return (claripy.BVV(jtable[real_ip], 64), [])
    except KeyError:
        raise ValueError("There is no entry in the jump table at " + repr(real_ip))

# For the sake of my sanity, the ptr is 64 bits wide.
# By the spec, cells are 8 bits, and do all the usual wrapping stuff.
PTR_TYPE = Type.int_64
CELL_TYPE = Type.int_8
PTR_REG = ArchBF().registers['ptr'][0]
INOUT_REG = ArchBF().registers['inout'][0]


class Instruction_NOP(Instruction):
    # Convert everything that's not an instruction into a No-op to meet the BF spec
    bin_format = 'xxxxxxxx' # We don't care, match it all

    def parse(self, bitstrm):
        self.last_instruction = False
        data = Instruction.parse(self, bitstrm)
        try:
            bitstrm.peek(8)
        except bitstring.ReadError:
            # We ran off the end!
            self.last_instruction = True
        return data

    def compute_result(self):
        if self.last_instruction:
            self.jump(None, self.constant(self.addr, PTR_TYPE), jumpkind=JumpKind.Exit)


# These are the standard BrainFuck instructions.


class Instruction_INCPTR(Instruction):
    bin_format = bin(ord(">"))[2:].zfill(8)
    name = 'incptr'

    def compute_result(self, *args):
        """
        '>': move the ptr register to the right one cell, or
        ptr += 1
        :param irsb_c:
        :type irsb_c: vex_helpers.IRSBCustomizer
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr += 1
        self.put(ptr, PTR_REG)


class Instruction_DECPTR(Instruction):
    #bin_format = bin(ord("<"))[2:].zfill(8)
    bin_format = '00111100'

    def compute_result(self, *args):
        """
        '<': Move the ptr register to the left one cell, or
        ptr -= 1
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr -= 1
        self.put(ptr, PTR_REG)

class Instruction_INC(Instruction):
    bin_format = bin(ord("+"))[2:].zfill(8)
    name = 'inc'

    def compute_result(self, *args):
        """
        '+': Increment the value of the data memory pointed at by the ptr register, or:
        ptr* += 1

        :type irsb_c: vex_helper.IRSBCustomizer
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        val += 1
        self.store(val, ptr)


class Instruction_DEC(Instruction):
    bin_format = bin(ord("-"))[2:].zfill(8)
    name = 'dec'

    def compute_result(self, *args):
        """
        '-': Increment the data memory value pointed at by the ptr register, or:
        ptr* -= 1
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        val -= 1
        self.store(val, ptr)


class Instruction_SKZ(Instruction):
    bin_format = bin(ord("["))[2:].zfill(8)
    name = 'skz'

    def compute_result(self, *args):
        """
        '[': Skip to the matching ], IF the value pointed at by the ptr register is zero.
        The matching ] is defined by pairs of matched braces, not necessarily the next ].

        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        # NOTE: VEX doesn't support non-constant values for conditional exits.
        # What we do to avoid this is to make the default exit of this block the conditional one,
        # and make the other take us to the next instruction.  Therefore, we invert the comparison.
        # We use a "CCall" to let VEX resolve these at "run"-time, since we may not be able to see the ]
        # This uses the above helper functions to find the matching ]
        dst = self.ccall(PTR_TYPE, bf_resolve_jump, [])
        # Go to the next instruction if *ptr != 0
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(val != 0, next_instr)
        # And go to the next ] if *ptr == 0
        self.jump(None, dst)


class Instruction_SKNZ(Instruction):
    bin_format = bin(ord("]"))[2:].zfill(8)
    name = 'sknz'

    def compute_result(self, *args):
        """
        ']': Skip to the matching [ backward if the value pointed at by the ptr register is not zero.
        Similar to the above, see that for important notes.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        dst = self.ccall(PTR_TYPE, bf_resolve_jump, [])
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(val == 0, next_instr)
        self.jump(None, dst)


class Instruction_IN(Instruction):
    bin_format = bin(ord(","))[2:].zfill(8)
    name = 'in'

    def compute_result(self, *args):
        """
        ',': Get one byte from standard input.
        We use a "syscall" here, see simos_bf.py for the SimProcedures that get called.
        :return:
        """
        # Having a 0 in the "inout" register tells VEX to kick off simos_bf.WriteByteToPtr()
        self.put(self.constant(0, PTR_TYPE), INOUT_REG)
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)

class Instruction_OUT(Instruction):
    bin_format = bin(ord("."))[2:].zfill(8)
    name = 'out'

    def compute_result(self, *args):
        """
        '.': Get the current value pointed at by the ptr register and print it to stdout
        As above, we use a Syscall / simprocedure to do this
        """
        # Putting a 1 in "inout", executes simos_bf.ReadValueAtPtr()
        self.put(self.constant(1, PTR_TYPE), INOUT_REG)
        # Go to the next instruction after, but set the Syscall jumpkind
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)


# The instrs are in this order so we try NOP last.
all_instrs = [
    Instruction_INCPTR,
    Instruction_DECPTR,
    Instruction_INC,
    Instruction_DEC,
    Instruction_SKZ,
    Instruction_SKNZ,
    Instruction_IN,
    Instruction_OUT,
    Instruction_NOP
]


class LifterBF(GymratLifter):
    instrs = all_instrs

# Tell PyVEX that this lifter exists.
register(LifterBF)

if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import logging
    logging.getLogger('pyvex').setLevel(logging.DEBUG)
    logging.basicConfig()

    irsb_ = pyvex.IRSB(None, 0, arch=archinfo.arch_from_id('bf'))
    test1 = '<>+-[].,'
    test2 = '<>+-[].,'
    lifter = LifterBF(irsb_, test1,len(test1) , len(test1), 0, None,  decode_only=True)
    lifter.lift()
    irsb_ = pyvex.IRSB(None, 0, arch=ArchBF())
    lifter = LifterBF(irsb_, test2, len(test2),len(test2),0,  None)
    lifter.lift()
    lifter.irsb.pp()

    i = pyvex.IRSB(test1, 0x0, arch=ArchBF())
