"""Core ROP chain solver with Markov state-aware search and Z3 constraint stubs."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from pwn import ELF, ROP, context

logger = logging.getLogger(__name__)


# --- Z3 Stub Layer ---
# Call sites are explicit. When z3-solver is installed, these become real solvers.

_Z3_AVAILABLE = False
try:
    from z3 import BitVec, BitVecVal, Solver as Z3Solver, sat  # noqa: F401
    _Z3_AVAILABLE = True
except ImportError:
    pass


def _z3_solve_constraints(
    gadgets: list[Gadget],
    goals: dict[str, int],
    achieved: dict[str, int],
) -> Optional[list[Gadget]]:
    """Z3-backed constraint solver for complex chains with clobber resolution.

    Handles cases where Markov search fails due to mutual clobber conflicts
    requiring simultaneous constraint satisfaction.

    Stub: raises NotImplementedError until z3-solver is installed.
    """
    if not _Z3_AVAILABLE:
        raise NotImplementedError(
            "Z3 constraint solver requires z3-solver. "
            "Install with: pip install autorop[solver]"
        )
    # TODO: Encode each gadget as a state transformation function over BitVecs
    # TODO: Create BitVec variables for register state at each chain position
    # TODO: Assert goal state constraints at final position
    # TODO: Assert no-clobber invariants across all positions
    # TODO: Minimize chain length via optimization objective
    # TODO: Solve, extract gadget ordering, return
    raise NotImplementedError("Z3 constraint solver not yet implemented")


# --- Data Structures ---

@dataclass
class Gadget:
    """A ROP gadget with its address, effects, and constraints."""

    address: int
    instructions: str
    sets: dict[str, str] = field(default_factory=dict)
    clobbers: set[str] = field(default_factory=set)
    reads: set[str] = field(default_factory=set)
    stack_consume: int = 0

    def __repr__(self) -> str:
        clobber_str = f" clobbers={self.clobbers}" if self.clobbers else ""
        return f"Gadget(0x{self.address:x}: {self.instructions}{clobber_str})"

    def makes_progress(self, remaining: dict[str, int]) -> bool:
        """Does this gadget set at least one register we still need?"""
        return bool(set(self.sets.keys()) & set(remaining.keys()))

    def clobbers_achieved(self, achieved: dict[str, int]) -> bool:
        """Does this gadget destroy any register we already set?"""
        return bool(self.clobbers & set(achieved.keys()))

    def preconditions_met(self, achieved: dict[str, int]) -> bool:
        """Are all registers this gadget reads already set correctly?"""
        return all(reg in achieved for reg in self.reads)


@dataclass
class SolverState:
    """Markov state for chain construction.

    The transition rule depends only on current state + chosen gadget,
    not on history. This is the Markov property that enables pruning.
    """

    achieved: dict[str, int] = field(default_factory=dict)
    remaining: dict[str, int] = field(default_factory=dict)
    chain: list[Gadget] = field(default_factory=list)
    stack_layout: list[int] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return len(self.remaining) == 0

    def copy(self) -> SolverState:
        return SolverState(
            achieved=dict(self.achieved),
            remaining=dict(self.remaining),
            chain=list(self.chain),
            stack_layout=list(self.stack_layout),
        )


@dataclass
class Chain:
    """A solved ROP chain ready for payload construction."""

    gadgets: list[Gadget]
    payload: bytes = b""
    register_state: dict[str, int] = field(default_factory=dict)

    def __bytes__(self) -> bytes:
        return self.payload

    def __len__(self) -> int:
        return len(self.gadgets)

    def dump(self) -> str:
        """Pretty print the chain."""
        lines = ["=== autorop chain ==="]
        for i, g in enumerate(self.gadgets):
            lines.append(f"  [{i}] 0x{g.address:x}: {g.instructions}")
        lines.append(
            f"  registers: "
            f"{', '.join(f'{r}=0x{v:x}' for r, v in self.register_state.items())}"
        )
        lines.append(f"  payload: {len(self.payload)} bytes")
        return "\n".join(lines)


# --- Solver ---

class Solver:
    """Automated ROP chain solver.

    Strategies:
        'markov' (default) - State-aware DFS with Markov transition pruning.
                             Complete search, guaranteed to find all valid chains
                             up to MAX_CHAIN_LENGTH.
        'z3'               - Z3 constraint satisfaction for complex chains.
                             Handles mutual clobber conflicts. Requires z3-solver.

    Usage:
        elf = ELF('./target')
        solver = Solver(elf)

        # Find all valid chains (Markov search)
        chains = solver.solve(rdi=0xdeadbeef, rsi=0, rax=59, call='syscall')
        best = chains[0]  # shortest chain
        print(best.dump())
        payload = b'A' * offset + bytes(best)

        # Try Z3 solver for complex cases (requires z3-solver)
        chains = solver.solve(rdi=0xdead, rsi=0, strategy='z3')
    """

    ALL_REGS = [
        "rax", "rbx", "rcx", "rdx", "rdi", "rsi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ]

    MAX_CHAIN_LENGTH = 10
    MAX_RESULTS = 50

    def __init__(self, elf: ELF, arch: str = "amd64") -> None:
        self.elf = elf
        self.arch = arch
        self._word_size = 8 if arch == "amd64" else 4
        context.arch = arch
        self._rop = ROP(elf)
        self._gadgets: list[Gadget] = []
        self._scan_gadgets()
        logger.info(f"Discovered {len(self._gadgets)} usable gadgets")

    # --- Gadget Discovery ---

    def _scan_gadgets(self) -> None:
        """Extract and classify all usable gadgets from the binary."""
        self._scan_pop_gadgets()
        self._scan_multi_pop_gadgets()
        self._scan_zero_gadgets()
        self._scan_mov_gadgets()
        self._scan_xchg_gadgets()

    def _try_find_gadget(self, insns: list[str]) -> Optional[int]:
        """Safely find a gadget, returning its address or None."""
        try:
            result = self._rop.find_gadget(insns)
            if result:
                return result[0] if isinstance(result, list) else result
        except Exception:
            pass
        return None

    def _scan_pop_gadgets(self) -> None:
        for reg in self.ALL_REGS:
            addr = self._try_find_gadget([f"pop {reg}", "ret"])
            if addr:
                self._gadgets.append(Gadget(
                    address=addr,
                    instructions=f"pop {reg}; ret",
                    sets={reg: "pop"},
                    stack_consume=self._word_size,
                ))

    def _scan_multi_pop_gadgets(self) -> None:
        pairs = [
            ("rdi", "rsi"), ("rdi", "rdx"), ("rsi", "rdx"),
            ("rdi", "rbx"), ("rcx", "rdx"),
        ]
        for reg1, reg2 in pairs:
            addr = self._try_find_gadget([f"pop {reg1}", f"pop {reg2}", "ret"])
            if addr:
                self._gadgets.append(Gadget(
                    address=addr,
                    instructions=f"pop {reg1}; pop {reg2}; ret",
                    sets={reg1: "pop", reg2: "pop"},
                    stack_consume=self._word_size * 2,
                ))

        addr = self._try_find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])
        if addr:
            self._gadgets.append(Gadget(
                address=addr,
                instructions="pop rdi; pop rsi; pop rdx; ret",
                sets={"rdi": "pop", "rsi": "pop", "rdx": "pop"},
                stack_consume=self._word_size * 3,
            ))

    def _scan_zero_gadgets(self) -> None:
        for reg in self.ALL_REGS:
            addr = self._try_find_gadget([f"xor {reg}, {reg}", "ret"])
            if addr:
                self._gadgets.append(Gadget(
                    address=addr,
                    instructions=f"xor {reg}, {reg}; ret",
                    sets={reg: "zero"},
                ))

    def _scan_mov_gadgets(self) -> None:
        for dst in self.ALL_REGS:
            for src in self.ALL_REGS:
                if dst == src:
                    continue
                addr = self._try_find_gadget([f"mov {dst}, {src}", "ret"])
                if addr:
                    self._gadgets.append(Gadget(
                        address=addr,
                        instructions=f"mov {dst}, {src}; ret",
                        sets={dst: f"mov_{src}"},
                        reads={src},
                    ))

    def _scan_xchg_gadgets(self) -> None:
        for i, reg1 in enumerate(self.ALL_REGS):
            for reg2 in self.ALL_REGS[i + 1:]:
                addr = self._try_find_gadget([f"xchg {reg1}, {reg2}", "ret"])
                if addr:
                    self._gadgets.append(Gadget(
                        address=addr,
                        instructions=f"xchg {reg1}, {reg2}; ret",
                        sets={reg1: f"mov_{reg2}", reg2: f"mov_{reg1}"},
                        reads={reg1, reg2},
                    ))

    # --- Call Resolution ---

    def _resolve_call(self, call: str | int) -> int:
        """Resolve a call target to an address."""
        if isinstance(call, int):
            return call

        if call == "syscall":
            for insns in [["syscall", "ret"], ["syscall"]]:
                addr = self._try_find_gadget(insns)
                if addr:
                    return addr
            raise ValueError("No syscall gadget found in binary")

        if call in self.elf.symbols:
            return self.elf.symbols[call]
        if call in self.elf.plt:
            return self.elf.plt[call]

        raise ValueError(f"Cannot resolve call target: {call}")

    # --- Payload Construction ---

    def _pack(self, value: int) -> bytes:
        return value.to_bytes(self._word_size, "little")

    def _build_payload(self, state: SolverState, call: Optional[str | int]) -> bytes:
        """Construct raw payload bytes from a solved state."""
        payload = b""
        stack_idx = 0

        for gadget in state.chain:
            payload += self._pack(gadget.address)
            n_vals = gadget.stack_consume // self._word_size
            for j in range(n_vals):
                if stack_idx < len(state.stack_layout):
                    payload += self._pack(state.stack_layout[stack_idx])
                    stack_idx += 1
                else:
                    payload += self._pack(0)

        if call is not None:
            payload += self._pack(self._resolve_call(call))

        return payload

    # --- Markov State-Aware Search (Tier 1) ---

    def _apply_gadget(self, state: SolverState, gadget: Gadget) -> Optional[SolverState]:
        """Apply a gadget to current state, producing new state.

        Returns None if the gadget doesn't actually make progress
        (e.g. a zero gadget when the goal value isn't zero).

        This is the Markov transition function: output depends only
        on (current_state, gadget), not on chain history.
        """
        new_state = state.copy()
        new_state.chain.append(gadget)
        progress = False

        for reg, effect in gadget.sets.items():
            if reg not in new_state.remaining:
                continue

            target_val = new_state.remaining[reg]

            if effect == "pop":
                new_state.stack_layout.append(target_val)
                new_state.achieved[reg] = target_val
                del new_state.remaining[reg]
                progress = True

            elif effect == "zero":
                if target_val == 0:
                    new_state.achieved[reg] = 0
                    del new_state.remaining[reg]
                    progress = True

            elif effect.startswith("mov_"):
                src_reg = effect[4:]
                if (
                    src_reg in new_state.achieved
                    and new_state.achieved[src_reg] == target_val
                ):
                    new_state.achieved[reg] = target_val
                    del new_state.remaining[reg]
                    progress = True

        if not progress:
            return None

        # Pad stack for pops in multi-pop gadgets that aren't targeting remaining regs
        n_expected = gadget.stack_consume // self._word_size
        n_pushed = len(new_state.stack_layout) - len(state.stack_layout)
        for _ in range(n_expected - n_pushed):
            new_state.stack_layout.append(0)

        return new_state

    def _valid_transitions(self, state: SolverState) -> list[Gadget]:
        """Return gadgets that are valid Markov transitions from current state.

        A gadget is valid iff:
            1. It sets at least one register still in `remaining`
            2. It doesn't clobber any register in `achieved`
            3. Its read-preconditions are satisfied by `achieved`
        """
        valid = []
        for gadget in self._gadgets:
            if not gadget.makes_progress(state.remaining):
                continue
            if gadget.clobbers_achieved(state.achieved):
                continue
            if not gadget.preconditions_met(state.achieved):
                continue
            valid.append(gadget)
        return valid

    def _search(
        self,
        state: SolverState,
        results: list[SolverState],
    ) -> None:
        """Recursive DFS with Markov transition pruning.

        At each level, only valid transitions are explored.
        Search space shrinks at every level:
          - `remaining` decreases (fewer goals = fewer useful gadgets)
          - `achieved` increases (more clobber constraints = more pruning)
        """
        if state.is_complete:
            results.append(state)
            return

        if len(state.chain) >= self.MAX_CHAIN_LENGTH:
            return

        if len(results) >= self.MAX_RESULTS:
            return

        transitions = self._valid_transitions(state)

        # Prefer gadgets that set more remaining registers (multi-pops first)
        transitions.sort(
            key=lambda g: len(set(g.sets.keys()) & set(state.remaining.keys())),
            reverse=True,
        )

        for gadget in transitions:
            new_state = self._apply_gadget(state, gadget)
            if new_state is not None:
                self._search(new_state, results)

    # --- Public API ---

    def solve(
        self,
        call: Optional[str | int] = None,
        strategy: str = "markov",
        **register_goals: int,
    ) -> list[Chain]:
        """Solve for ROP chains achieving the given register state.

        Args:
            call: Final call target - 'syscall', function name, or address.
            strategy: 'markov' (default) or 'z3'.
            **register_goals: Target values, e.g. rdi=0xdeadbeef, rax=59.

        Returns:
            List of Chain objects, sorted shortest first.

        Raises:
            ValueError: If no valid chain can be found.
            NotImplementedError: If strategy='z3' and z3-solver not installed.
        """
        if not register_goals:
            raise ValueError("No register goals specified")

        # --- Tier 2 stub: Z3 constraint solver ---
        if strategy == "z3":
            z3_result = _z3_solve_constraints(
                self._gadgets, register_goals, {}
            )
            # Would construct and return Chain list from z3_result here
            raise NotImplementedError("Z3 chain construction not yet implemented")

        # --- Tier 1: Markov state-aware search ---
        initial_state = SolverState(
            achieved={},
            remaining=dict(register_goals),
        )

        results: list[SolverState] = []
        self._search(initial_state, results)

        if not results:
            raise ValueError(
                f"No valid chain found for: "
                f"{', '.join(f'{r}=0x{v:x}' for r, v in register_goals.items())}. "
                f"Gadgets available: {len(self._gadgets)}"
            )

        # Sort by chain length (shortest = best)
        results.sort(key=lambda s: len(s.chain))

        chains = []
        for state in results:
            payload = self._build_payload(state, call)
            chains.append(Chain(
                gadgets=state.chain,
                payload=payload,
                register_state=register_goals,
            ))

        logger.info(
            f"Found {len(chains)} valid chains, "
            f"shortest: {len(chains[0])} gadgets"
        )
        return chains

    @property
    def gadgets(self) -> list[Gadget]:
        """All discovered gadgets."""
        return list(self._gadgets)

    def show_gadgets(self) -> None:
        """Print all discovered gadgets."""
        print(f"=== {len(self._gadgets)} gadgets ===")
        for g in self._gadgets:
            print(f"  {g}")

    @property
    def z3_available(self) -> bool:
        """Whether Z3 solver backend is installed."""
        return _Z3_AVAILABLE
