# autorop

Automated ROP chain solver using constraint satisfaction. Stop chaining gadgets by hand.

`autorop` wraps [pwntools](https://github.com/Gallopsled/pwntools) for gadget enumeration and uses [Z3](https://github.com/Z3Prover/z3) for constraint solving to automatically build ROP chains from a target binary and a goal register state.

## Install

```bash
pip install autorop
```

## Quick Start

```python
from pwn import *
from autorop import Solver

elf = ELF('./vulnerable_binary')
solver = Solver(elf)

# execve("/bin/sh", NULL, NULL)
chain = solver.solve(
    rdi=next(elf.search(b'/bin/sh')),
    rsi=0,
    rdx=0,
    rax=59,
    call='syscall'
)

print(chain.dump())

# Use in an exploit
payload = b'A' * offset + bytes(chain)
```

## How It Works

1. **Scan** — Extracts gadgets from the binary via pwntools
2. **Classify** — Categorises each gadget by its effects on register state
3. **Solve** — Takes your goal state and finds a valid gadget chain using constraint satisfaction
4. **Pack** — Outputs the chain as a ready-to-use payload

## API

### `Solver(elf, arch='amd64')`

Create a solver for a given binary.

- `elf` — A pwntools `ELF` object
- `arch` — Target architecture (default: `amd64`)

### `solver.solve(call=None, **register_goals) -> Chain`

Solve for a chain that achieves the given register state.

- `call` — Final call target: `'syscall'`, a function name, or an address
- `**register_goals` — Target values, e.g. `rdi=0xdeadbeef, rax=59`

Returns a `Chain` object with:
- `chain.payload` — Raw bytes for the ROP chain
- `chain.gadgets` — List of gadgets used
- `chain.dump()` — Pretty-printed chain summary
- `bytes(chain)` — Same as `.payload`

### `solver.gadgets`

List all discovered gadgets.

### `solver.show_gadgets()`

Print all discovered gadgets.

## Roadmap

- [ ] Multi-pop gadgets (`pop rdi; pop rsi; ret`)
- [ ] `mov` gadgets for register-to-register transfers
- [ ] Z3-backed constraint solver for complex chains with clobber avoidance
- [ ] Stack pivot support
- [ ] ASLR-aware solving with partial overwrites
- [ ] ret2libc / ret2plt helpers
- [ ] i386 support
- [ ] Integration with angr for CFG-aware gadget discovery

## Requirements

- Python >= 3.9
- pwntools >= 4.11.0
- z3-solver >= 4.12.0

## License

MIT
