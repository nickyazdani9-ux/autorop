"""Tests for autorop solver."""

import pytest
from autorop.solver import Chain, Gadget, SolverState, _z3_solve_constraints


# --- Gadget Tests ---

class TestGadget:
    def test_repr(self):
        g = Gadget(address=0x401234, instructions="pop rdi; ret")
        assert "0x401234" in repr(g)
        assert "pop rdi; ret" in repr(g)

    def test_repr_with_clobbers(self):
        g = Gadget(
            address=0x401234,
            instructions="add rax, rdi; pop rdi; ret",
            clobbers={"rax"},
        )
        assert "clobbers" in repr(g)
        assert "rax" in repr(g)

    def test_makes_progress_true(self):
        g = Gadget(address=0x0, instructions="", sets={"rdi": "pop"})
        assert g.makes_progress({"rdi": 0xdead, "rsi": 0}) is True

    def test_makes_progress_false(self):
        g = Gadget(address=0x0, instructions="", sets={"rdi": "pop"})
        assert g.makes_progress({"rsi": 0, "rdx": 0}) is False

    def test_clobbers_achieved_true(self):
        g = Gadget(address=0x0, instructions="", clobbers={"rax"})
        assert g.clobbers_achieved({"rax": 59}) is True

    def test_clobbers_achieved_false(self):
        g = Gadget(address=0x0, instructions="", clobbers={"rax"})
        assert g.clobbers_achieved({"rdi": 0xdead}) is False

    def test_clobbers_achieved_empty(self):
        g = Gadget(address=0x0, instructions="", clobbers=set())
        assert g.clobbers_achieved({"rdi": 0xdead}) is False

    def test_preconditions_met_true(self):
        g = Gadget(address=0x0, instructions="", reads={"rsi"})
        assert g.preconditions_met({"rsi": 0, "rdi": 0xdead}) is True

    def test_preconditions_met_false(self):
        g = Gadget(address=0x0, instructions="", reads={"rsi"})
        assert g.preconditions_met({"rdi": 0xdead}) is False

    def test_preconditions_met_no_reads(self):
        g = Gadget(address=0x0, instructions="", reads=set())
        assert g.preconditions_met({}) is True


# --- SolverState Tests ---

class TestSolverState:
    def test_is_complete_true(self):
        state = SolverState(achieved={"rdi": 0xdead}, remaining={})
        assert state.is_complete is True

    def test_is_complete_false(self):
        state = SolverState(remaining={"rdi": 0xdead})
        assert state.is_complete is False

    def test_copy_is_independent(self):
        state = SolverState(
            achieved={"rdi": 0xdead},
            remaining={"rsi": 0},
            chain=[Gadget(address=0x0, instructions="nop")],
            stack_layout=[0xdead],
        )
        copied = state.copy()

        # Modify copy, original unchanged
        copied.achieved["rax"] = 59
        copied.remaining["rdx"] = 0
        copied.chain.append(Gadget(address=0x1, instructions="nop"))
        copied.stack_layout.append(0)

        assert "rax" not in state.achieved
        assert "rdx" not in state.remaining
        assert len(state.chain) == 1
        assert len(state.stack_layout) == 1


# --- Chain Tests ---

class TestChain:
    def test_bytes(self):
        chain = Chain(gadgets=[], payload=b"\x41\x42\x43")
        assert bytes(chain) == b"\x41\x42\x43"

    def test_len(self):
        gadgets = [
            Gadget(address=0x0, instructions="pop rdi; ret"),
            Gadget(address=0x1, instructions="pop rsi; ret"),
        ]
        chain = Chain(gadgets=gadgets)
        assert len(chain) == 2

    def test_dump_contains_addresses(self):
        g = Gadget(address=0x401234, instructions="pop rdi; ret")
        chain = Chain(
            gadgets=[g],
            payload=b"\x00" * 16,
            register_state={"rdi": 0xdead},
        )
        dump = chain.dump()
        assert "0x401234" in dump
        assert "16 bytes" in dump
        assert "rdi=0xdead" in dump

    def test_dump_empty_chain(self):
        chain = Chain(gadgets=[], payload=b"", register_state={})
        dump = chain.dump()
        assert "0 bytes" in dump


# --- Z3 Stub Tests ---

class TestZ3Stub:
    def test_z3_stub_raises(self):
        """Z3 stub should raise NotImplementedError."""
        with pytest.raises(NotImplementedError):
            _z3_solve_constraints([], {"rdi": 0}, {})


# --- Markov Transition Logic Tests (unit level, no binary needed) ---

class TestMarkovTransitions:
    """Test the transition logic in isolation using hand-built gadgets."""

    def _make_pop(self, reg: str, addr: int = 0x1000) -> Gadget:
        return Gadget(
            address=addr,
            instructions=f"pop {reg}; ret",
            sets={reg: "pop"},
            stack_consume=8,
        )

    def _make_zero(self, reg: str, addr: int = 0x2000) -> Gadget:
        return Gadget(
            address=addr,
            instructions=f"xor {reg}, {reg}; ret",
            sets={reg: "zero"},
        )

    def _make_multi_pop(self, reg1: str, reg2: str, addr: int = 0x3000) -> Gadget:
        return Gadget(
            address=addr,
            instructions=f"pop {reg1}; pop {reg2}; ret",
            sets={reg1: "pop", reg2: "pop"},
            stack_consume=16,
        )

    def _make_clobbering(self, sets_reg: str, clobbers_reg: str, addr: int = 0x4000) -> Gadget:
        return Gadget(
            address=addr,
            instructions=f"pop {sets_reg}; (clobbers {clobbers_reg}); ret",
            sets={sets_reg: "pop"},
            clobbers={clobbers_reg},
            stack_consume=8,
        )

    def test_pop_makes_progress(self):
        g = self._make_pop("rdi")
        remaining = {"rdi": 0xdead}
        assert g.makes_progress(remaining) is True

    def test_pop_no_progress_on_irrelevant(self):
        g = self._make_pop("rdi")
        remaining = {"rsi": 0}
        assert g.makes_progress(remaining) is False

    def test_clobber_blocks_transition(self):
        g = self._make_clobbering("rsi", "rdi")
        achieved = {"rdi": 0xdead}
        assert g.clobbers_achieved(achieved) is True

    def test_no_clobber_allows_transition(self):
        g = self._make_clobbering("rsi", "rax")
        achieved = {"rdi": 0xdead}
        assert g.clobbers_achieved(achieved) is False

    def test_multi_pop_progress_on_both(self):
        g = self._make_multi_pop("rdi", "rsi")
        remaining = {"rdi": 0xdead, "rsi": 0}
        assert g.makes_progress(remaining) is True

    def test_multi_pop_progress_on_one(self):
        g = self._make_multi_pop("rdi", "rsi")
        remaining = {"rdi": 0xdead}
        assert g.makes_progress(remaining) is True

    def test_zero_progress_only_when_goal_is_zero(self):
        g = self._make_zero("rax")
        assert g.makes_progress({"rax": 0}) is True
        assert g.makes_progress({"rax": 59}) is True  # makes_progress just checks key overlap
        # The actual zero-vs-nonzero filtering happens in _apply_gadget


# --- Integration Tests (require actual ELF binaries) ---

class TestSolverIntegration:
    @pytest.mark.skip(reason="Requires test binary fixture")
    def test_solve_execve_chain(self):
        """End-to-end: solve for execve('/bin/sh', NULL, NULL)."""
        pass

    @pytest.mark.skip(reason="Requires test binary fixture")
    def test_solve_returns_shortest_first(self):
        """Chains should be sorted by length, shortest first."""
        pass

    @pytest.mark.skip(reason="Requires test binary fixture")
    def test_solve_no_solution_raises(self):
        """ValueError when no chain exists for the given goals."""
        pass

    @pytest.mark.skip(reason="Requires test binary fixture")
    def test_z3_strategy_raises_not_implemented(self):
        """Z3 strategy should raise until implemented."""
        pass

    @pytest.mark.skip(reason="Requires test binary fixture")
    def test_multi_pop_preferred_over_singles(self):
        """A pop rdi; pop rsi; ret should produce a shorter chain than two single pops."""
        pass
