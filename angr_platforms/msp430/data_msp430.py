class BitMode(DataComponent):
    def __init__(self, is_bitmode):
        self.is_bitmode = is_bitmode

    def to_asm(self):
        return '.b' if self.is_bitmode else ''

    def from_asm(cls, bitmode_annotation):
        return BitMode(True if bitmode_annotation == '.b' else False)

    def to_binary(self):
        return '1' if self.is_bitmode else '0'

    def from_binary(cls, bitmode_bit):
        return BitMode(True if bitmode_bit == '1' else False)

class Offset(DataComponent): # TODO figure out how offset encoding works
    def __init__(self, offset):
        self.offset = offset

    def to_asm(self):
        pass

    def from_asm(cls, offset_annotation):
        pass

    def to_binary(self):
        pass

    def from_binary(self):
        pass

class MSP430Operand(DataComponent):
    def to_asm(self): # TODO copy paste
        """
        Decorate the register argument used for disassembly
        """

        # Boring register mode.  A write is just a Put.
        if reg_mode == ArchMSP430.Mode.REGISTER_MODE:
            reg_str = reg_name
        # Indexed mode, add the immediate to the register
        elif reg_mode == ArchMSP430.Mode.INDEXED_MODE:
            reg_str = "%d(%s)" % (imm, reg_name)
        # Indirect mode; fetch address in register; store is a write there.
        elif reg_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
            reg_str = "@%s" % reg_str
        # Indirect Autoincrement mode. Increment the register by the type size, then access it
        elif reg_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
            reg_str = "@%s+" % reg_name
        elif reg_mode == ArchMSP430.Mode.ABSOLUTE_MODE:
            reg_str = imm
        else:
            raise Exception('Unknown mode found')
        return reg_str

    def from_asm(self):
        pass

    def to_binary(self):
        pass

    def from_binary(cls, reg_num, reg_mode, imm_vv, ty): # TODO copy paste
        """
        Resolve the operand for register-based modes.
        :param reg_num: The Register Number
        :param reg_mode: The Register Mode
        :param imm_vv: The immediate word, if any
        :param ty: The Type (byte or word)
        :return: The VexValue of the operand, and the writeout function, if any.
        """
        # Fetch the register
        reg_vv = self.get(reg_num, ty)
        # Boring register mode.  A write is just a Put.
        if reg_mode == ArchMSP430.Mode.REGISTER_MODE:
            val = reg_vv
            writeout = lambda v: self.put(v, reg_num)
        # Indexed mode, add the immediate to the register
        # A write here is a store to reg + imm
        elif reg_mode == ArchMSP430.Mode.INDEXED_MODE:
            val = reg_vv + imm_vv
            writeout = lambda v: self.store(v, val)
        # Indirect mode; fetch address in register; store is a write there.
        elif reg_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
            val = self.load(reg_num, ty)
            writeout = lambda v: self.store(v, regvv)
        # Indirect Autoincrement mode. Increment the register by the type size, then access it
        elif reg_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
            if ty == Type.int_16:
                incconst = self.constant(16, ty)
            else:
                incconst = self.constant(8, ty)
            # Do the increment, now
            self.put(reg_vv + incconst, reg_num)
            # Now load it.
            val = self.load(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_num)
        elif reg_mode == ArchMSP430.Mode.ABSOLUTE_MODE:
            val = self.load(imm_vv, ty)
            writeout = lambda v: self.store(v, imm_vv)
        else:
            raise Exception('Unknown mode found')
        return val, writeout

class SrcOperand(MSP430Operand):

    def to_asm(self):
        """
        Computes the decorated source operand for disassembly
        """
        src = ArchMSP430.register_index[int(src_bits, 2)]
        src_mode = int(mode_bits, 2)
        writeout = None
        # Load the immediate word
        src_imm = None
        if imm_bits:
            src_imm = bits_to_signed_int(imm_bits)
        # Symbolic and Immediate modes use the PC as the source.
        if src == 'pc':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src == 'cg':
            if src_mode == ArchMSP430.Mode.REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src == 'sr':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE8
        # Fetch constants
        if src_mode == ArchMSP430.Mode.CONSTANT_MODE0:
            src_str = "#0"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE1:
            src_str = "#1"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE2:
            src_str = "#2"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE4:
            src_str = "#4"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE8:
            src_str = "#8"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE_NEG1:
            src_str = "#-1"
        # Fetch immediate.
        elif src_mode == ArchMSP430.Mode.IMMEDIATE_MODE:
            src_str = str(bits_to_signed_int(imm_bits))
        # Symbolic mode: Add the immediate to the PC
        elif src_mode == ArchMSP430.Mode.SYMBOLIC_MODE:
            src_str = "%s+%d" % (src, bits_to_signed_int(imm_bits))
        else:
            # Register mode can write-out to the source for one-operand, so set the writeout
            src_str = self.decorate_reg(src, src_mode, src_imm)
        return src_str


    def from_asm(self):
        pass

    def to_binary(self):
        pass

    def from_binary(self, src_bits, mode_bits, imm_bits, ty): # TODO just copied and pasted
        """
        Fetch the ``source'' operand of an instruction.
        Returns the source as a VexValue, and, if it exists, a function for how it can be written
        to if needed (e.g., one-operand instructions)
        :param src_bits: bit-string of the src
        :param mode_bits: bit-string of the mode
        :param imm_bits: bit-string of the immediate
        :param ty: The type to use (the byte type or word type)
        :return: The src as a VexValue, and a lambda describing how to write to it if necessary
        """
        src_num = int(src_bits, 2)
        src_name = ArchMSP430.register_index[src_num]
        src_mode = int(mode_bits, 2)
        writeout = None
        # Load the immediate word
        src_imm = None
        if imm_bits:
            src_imm = self.constant(bits_to_signed_int(imm_bits), ty)
        # Symbolic and Immediate modes use the PC as the source.
        if src_name == 'pc':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src_name == 'cg':
            if src_mode == ArchMSP430.Mode.REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src_name == 'sr':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE8
        # Fetch constants
        if src_mode == ArchMSP430.Mode.CONSTANT_MODE0:
            src_vv = self.constant(0, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE1:
            src_vv = self.constant(1, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE2:
            src_vv = self.constant(2, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE4:
            src_vv = self.constant(4, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE8:
            src_vv = self.constant(8, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE_NEG1:
            src_vv = self.constant(-1, ty)
        # Fetch immediate.
        elif src_mode == ArchMSP430.Mode.IMMEDIATE_MODE:
            src_vv = self.constant(bits_to_signed_int(imm_bits), ty)
        # Symbolic mode: Add the immediate to the PC
        elif src_mode == ArchMSP430.Mode.SYMBOLIC_MODE:
            src_vv = self.get(src_num, Type.int_16) + bits_to_signed_int(imm_bits)
        else:
            # Register mode can write-out to the source for one-operand, so set the writeout
            src_vv, writeout = self.fetch_reg(src_num, src_mode, src_imm, ty)
        return src_vv, writeout
        pass

def DstOperand(MSP430Operand):
    def to_asm(self): # TODO copy paste
        """
        Computes the decorated destination operand for disassembly
        """
        dst = ArchMSP430.register_index[int(dst_bits, 2)]
        dst_mode = int(mode_bits, 2)
        dst_imm = None
        # Using sr as the dst enables "absolute addressing"
        if dst == 'sr' and dst_mode == ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = ArchMSP430.Mode.ABSOLUTE_MODE
        if imm_bits:
            dst_imm = bits_to_signed_int(imm_bits)

        # two-op instructions always have a dst
        dst_str = self.decorate_reg(dst, dst_mode, dst_imm)
        # val = val.cast_to(ty)
        return dst_str

    def from_asm(self):
        pass

    def to_binary(self):
        pass

    def from_binary(self, dst_bits, mode_bits, imm_bits, ty): # TODO copy paste
        """
        Fetch the destination argument.
        :param dst_bits:
        :param mode_bits:
        :param imm_bits:
        :param ty:
        :return: The VexValue representing the destination, and the writeout function for it
        """
        dst_num = int(dst_bits, 2)
        dst_name = ArchMSP430.register_index[dst_num]
        dst_mode = int(mode_bits, 2)
        dst_imm = None
        # Using sr as the dst enables "absolute addressing"
        if dst_name == 'sr' and dst_mode == ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = ArchMSP430.Mode.ABSOLUTE_MODE
        if imm_bits:
            dst_imm = self.constant(int(imm_bits, 2), ty)
        pass
        # two-op instructions always have a dst and a writeout
        val, writeout = self.fetch_reg(dst_num, dst_mode, dst_imm, ty)
        # val = val.cast_to(ty)
        return val, writeout
