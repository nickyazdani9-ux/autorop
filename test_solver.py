"""Basic tests for autorop solver."""

import pytest
from autorop import Solver
from autorop.solver import Gadget, Chain


class TestGadget:
    def test_repr(self):
        g = Gadget(address=0x401234, instructions="pop rdi; ret")
        assert "0x401234" in repr(g)
        assert "pop rdi; ret" in repr(g)


class TestChain:
    def test_dump(self):
        g = Gadget(address=0x401234, instructions="pop rdi; ret")
        chain = Chain(gadgets=[g], payload=b"\x00" * 16)
        dump = chain.dump()
        assert "0x401234" in dump
        assert "16 bytes" in dump

    def test_bytes(self):
        chain = Chain(gadgets=[], payload=b"\x41\x42\x43")
        assert bytes(chain) == b"\x41\x42\x43"


# Integration tests require actual ELF binaries
# These will be added with test fixtures
class TestSolverIntegration:
    @pytest.mark.skip(reason="Requires test binary fixture")
    def test_solve_simple_chain(self):
        pass
