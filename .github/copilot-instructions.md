This is the OpenDCDiag project. OpenDCDiag is a tool to test CPUs and other
parts of the system on a live running system for manufacturing and other
defects.


The central header file for this project is `framework/sandstone.h`. When reviewing
code, use the following order of preference:

1. **If you can read files directly** (agentic/chat mode): load `framework/sandstone.h`
   from the repository root as the authoritative API and architectural reference.
2. **Otherwise** (web review / no file access): refer to the
   `.github/instructions/sandstone-api*.instructions.md` files, which contain the
   full API reference extracted from that header.


# Code review general rules

Use the Markdown files from the table below as rules for any code review:

| File | Purpose |
| ---- | ------- |
| `.github/instructions/style.instructions.md` | Coding style guide |
| `.github/instructions/general-c++.instructions.md` | C++ coding rules |
| `.github/instructions/test.instructions.md` | Test specific coding guidelines |

