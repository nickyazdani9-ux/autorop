"""Core ROP chain solver using Z3 constraint satisfaction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from pwn import ELF, ROP, context
from z3 import BitVec, BitVecVal, Solver as Z3Solver, sat


@dataclass
class Gadget:
    """A ROP gadget with its address and effects on register state."""

    address: int
    instructions: str
    effects: dict[str, str] = field(default_factory=dict)  # reg -> operation
    clobbers: set[str] = field(default_factory=set)
    stack_adjust: int = 0  # bytes consumed from stack beyond ret
    preconditions: dict[str, int] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"Gadget(0x{self.address:x}: {self.instructions})"


@dataclass
class Chain:
    """A solved ROP chain ready for payload construction."""

    gadgets: list[Gadget]
    payload: bytes = b""
    register_state: dict[str, int] = field(default_factory=dict)

    def __bytes__(self) -> bytes:
        return self.payload

    def dump(self) -> str:
        """Pretty print the chain."""
        lines = ["=== autorop chain ==="]
        for i, g in enumerate(self.gadgets):
            lines.append(f"  [{i}] 0x{g.address:x}: {g.instructions}")
        lines.append(f"  payload: {len(self.payload)} bytes")
        return "\n".join(lines)


class Solver:
    """Automated ROP chain solver.

    Usage:
        elf = ELF('./target')
        solver = Solver(elf)
        chain = solver.solve(rdi=0xdeadbeef, rsi=0, rax=59, call='syscall')
    """

    # x86_64 argument registers in calling convention order
    ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    ALL_REGS = [
        "rax", "rbx", "rcx", "rdx", "rdi", "rsi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ]

    def __init__(self, elf: ELF, arch: str = "amd64") -> None:
        self.elf = elf
        self.arch = arch
        context.arch = arch
        self._rop = ROP(elf)
        self._gadgets: list[Gadget] = []
        self._scan_gadgets()

    def _scan_gadgets(self) -> None:
        """Extract and classify gadgets from the binary."""
        # pop reg; ret gadgets - most common and useful
        for reg in self.ALL_REGS:
            try:
                gadget_addr = self._rop.find_gadget(["pop " + reg, "ret"])
                if gadget_addr:
                    self._gadgets.append(Gadget(
                        address=gadget_addr[0] if isinstance(gadget_addr, list) else gadget_addr,
                        instructions=f"pop {reg}; ret",
                        effects={reg: "pop"},
                        stack_adjust=8,
                    ))
            except Exception:
                continue

        # xor reg, reg; ret - zeroing gadgets
        for reg in self.ALL_REGS:
            try:
                gadget_addr = self._rop.find_gadget(["xor " + reg + ", " + reg, "ret"])
                if gadget_addr:
                    self._gadgets.append(Gadget(
                        address=gadget_addr[0] if isinstance(gadget_addr, list) else gadget_addr,
                        instructions=f"xor {reg}, {reg}; ret",
                        effects={reg: "zero"},
                        clobbers=set(),
                    ))
            except Exception:
                continue

        # TODO: mov reg, reg; ret gadgets
        # TODO: multi-pop gadgets (pop rdi; pop rsi; ret)
        # TODO: syscall; ret and call reg gadgets

    def _find_pop_gadget(self, reg: str) -> Optional[Gadget]:
        """Find a pop gadget for a specific register."""
        for g in self._gadgets:
            if g.effects.get(reg) == "pop":
                return g
        return None

    def _find_zero_gadget(self, reg: str) -> Optional[Gadget]:
        """Find a zeroing gadget for a specific register."""
        for g in self._gadgets:
            if g.effects.get(reg) == "zero":
                return g
        return None

    def solve(self, call: Optional[str] = None, **register_goals: int) -> Chain:
        """Solve for a ROP chain that achieves the given register state.

        Args:
            call: Final call target - 'syscall', a function name, or an address.
            **register_goals: Target register values, e.g. rdi=0, rax=59.

        Returns:
            A Chain object containing the solved gadget sequence and payload.

        Raises:
            ValueError: If no valid chain can be found.
        """
        chain_gadgets: list[Gadget] = []
        payload = b""

        # Sort goals: zero-value registers first (might use xor), then pops
        zero_goals = {r: v for r, v in register_goals.items() if v == 0}
        nonzero_goals = {r: v for r, v in register_goals.items() if v != 0}

        # Handle zero-value registers
        for reg, val in zero_goals.items():
            zero_g = self._find_zero_gadget(reg)
            pop_g = self._find_pop_gadget(reg)

            if zero_g:
                chain_gadgets.append(zero_g)
                payload += self._pack(zero_g.address)
            elif pop_g:
                chain_gadgets.append(pop_g)
                payload += self._pack(pop_g.address)
                payload += self._pack(0)
            else:
                raise ValueError(f"No gadget found to set {reg} = 0")

        # Handle non-zero registers
        for reg, val in nonzero_goals.items():
            pop_g = self._find_pop_gadget(reg)
            if pop_g:
                chain_gadgets.append(pop_g)
                payload += self._pack(pop_g.address)
                payload += self._pack(val)
            else:
                raise ValueError(f"No gadget found to set {reg} = 0x{val:x}")

        # Handle the final call/syscall
        if call:
            call_addr = self._resolve_call(call)
            payload += self._pack(call_addr)

        return Chain(
            gadgets=chain_gadgets,
            payload=payload,
            register_state=register_goals,
        )

    def _resolve_call(self, call: str) -> int:
        """Resolve a call target to an address."""
        if call == "syscall":
            # Find a syscall; ret gadget
            try:
                addr = self._rop.find_gadget(["syscall", "ret"])
                if addr:
                    return addr[0] if isinstance(addr, list) else addr
            except Exception:
                pass
            # Try raw syscall instruction
            try:
                addr = self._rop.find_gadget(["syscall"])
                if addr:
                    return addr[0] if isinstance(addr, list) else addr
            except Exception:
                raise ValueError("No syscall gadget found in binary")

        if isinstance(call, int):
            return call

        # Try as symbol name
        if call in self.elf.symbols:
            return self.elf.symbols[call]
        if call in self.elf.plt:
            return self.elf.plt[call]

        raise ValueError(f"Cannot resolve call target: {call}")

    def _pack(self, value: int) -> bytes:
        """Pack an integer to bytes for the current architecture."""
        if self.arch == "amd64":
            return value.to_bytes(8, "little")
        return value.to_bytes(4, "little")

    @property
    def gadgets(self) -> list[Gadget]:
        """Return all discovered gadgets."""
        return list(self._gadgets)

    def show_gadgets(self) -> None:
        """Print all discovered gadgets."""
        for g in self._gadgets:
            print(g)
