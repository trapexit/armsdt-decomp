# armcpp Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C99 reconstruction in `armcpp/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcpp-step1
  step: 1
  applies_to: armcpp
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armcpp/armcpp
    - armcpp/armcpp_decomp_ghidra.c
    - armcpp/armcpp_decomp_retdec.c
    - armcpp/armcpp_objdump.txt
    - armcpp/armcpp_readelf.txt
    - armcpp/armcpp_usage.txt
  must_outputs:
    - armcpp/recompiled/Makefile
    - armcpp/recompiled/src/
    - armcpp/recompiled/tests/
    - armcpp/recompiled/build/armcpp
  status_values:
    - confirmed
    - open
    - blocked
  closeout_requirements:
    - no externally visible mismatch
    - tests pass with parity evidence
    - unresolved items remain only as blocked with closure experiments
```

## Tool profile

- Directory: `armcpp/`
- Tool: ARM C++ Compiler
- Description: Compiles C++ source into AOF objects.
- Original binary size: 902 KB
- Recompiled priority: 6

## Shared step 1 guidance

Use [generic_step1.md](generic_step1.md) for shared step 1 requirements:
- Required references and inputs
- Required outputs
- Bootstrap-from-Ghidra baseline and initial commit order
- Build and test workflow, including two-way testing
- Analysis workflow, portability rules, source recovery rules, and verification strategy
- Commit and artifact rules

## Tool documentation references

- [ARM SDT 2.50 Reference Guide](../docs/ARM_DUI0041C_Reference_Guide.md)
- [ARM SDT 2.50 User Guide](../docs/ARM Software Development Toolkit Version 2.50 User Guide - ARM DUI 0040D.pdf)
- [ARM SDT 2.50 Errata](../docs/ARM SDT 2.50 User and Reference Guides Errata 01 - ARM DEI 0002A.pdf)
- [ARM SDT Suite Overview](../docs/norcroft_c/02_arm_sdt_suite_overview.md)
- [ARM SDT Command-Line Reference](../docs/norcroft_c/03_command_line_reference.md)
- [ARM SDT File Formats Reference](../docs/norcroft_c/04_file_formats_reference.md)
- [ARM SDT Platform and Target Support](../docs/norcroft_c/05_platform_and_target_support.md)
- [Norcroft C History and Overview](../docs/norcroft_c/01_norcroft_c_history_and_overview.md)
- [Norcroft Additional Resources and Archives](../docs/norcroft_c/07_additional_resources_and_archives.md)
- [Reverse Engineering Guide](../docs/norcroft_c/06_reverse_engineering_guide.md)
- [3DO SDK - ARM Object Format](../docs/3DO SDK - ARM Object Format.md)
- [3DO SDK - ARM Procedure Call Standard](../docs/3DO SDK - ARM Procedure Call Standard.md)
- [3DO SDK - ARM Cookbook](../docs/3DO SDK - ARM Cookbook.md)
- [ARM DUI0041C Reference Guide - ARM Object Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md)
- [AOF Specification](../docs/AOF_Specification.md)
- [AOF-1989](../docs/AOF-1989.md)
- [AOF-2002](../docs/AOF-2002.md)
- [APCS](../docs/APCS.md)
- [ASDTF](../docs/ASDTF.md)
- [RISC OS PRMs Appendix D - Code file formats](../docs/RISC OS Programmers Reference Manual - Appendix D - Code file formats.md)
- [RISC OS PRMs Code file formats](../docs/RISC_OS_PRMs_Code_file_formats.md)

## armcpp-specific focus

Prioritize driver compatibility and shared backend interactions first; recover C++ semantic behavior carefully for name resolution, overload behavior, and diagnostics; preserve compatibility-critical output and error behavior for supported workflows.

## Tool-specific constraints and priorities

- Prioritize driver compatibility and backend coupling before advanced C++ edge features.
- Recover C++ semantic behavior with emphasis on name resolution and overload handling.
- Treat diagnostics and deterministic output text as compatibility-critical.

## Tool-specific examples

- Overload-resolution cases with ambiguous-call diagnostics.
- Language-mode switches that alter parsing or code generation.
- Class and namespace semantics exercised by the required corpus.

## C++ language feature support (per ARM DUI 0041C)

Reference for which ISO/IEC December 1996 Draft Standard C++ features this compiler supports. Use this to scope test fixtures and avoid testing unsupported features as if they should work.

### Fully supported

- Core language (Draft Standard sections 1-13)
- Templates (except `export`)
- Array new/delete
- `bool` type
- Full linkage specification (`extern "C"`, etc.)
- `for` loop variable scope change (C++ rules, not C rules)
- Default template arguments
- Template instantiation directive
- Template specialization directive
- `typename` keyword
- Member templates
- Partial specialization for class templates
- Partial ordering of function templates

### Partially supported

- **RTTI** — `typeid` works for static types and non-polymorphic expressions only. Dynamic `typeid` on polymorphic types and `dynamic_cast` are not supported.
- **New style casts** — `static_cast`, `const_cast`, `reinterpret_cast`, `dynamic_cast` syntax is accepted but no restrictions are enforced; they behave identically to old-style C casts.
- **extern inline** — Supported except for functions that contain static data.

### Not supported

- **Exceptions** — No `try`/`catch`/`throw`. However, `new` does not throw on failure (returns null instead).
- **Namespaces** — No `namespace` keyword support.
- **nothrow new** — `new(std::nothrow)` syntax not supported (but `new` never throws anyway).
- **wchar_t type** — Not available as a distinct type.
- **explicit keyword** — Not recognized; implicit conversions from single-argument constructors are always allowed.
- **Static member constants** — In-class initialization of static const members not supported.
- **Covariant return types** — Overriding virtual functions cannot change return type to a derived class pointer/reference.
- **Universal character names** — `\uXXXX` and `\UXXXXXXXX` in identifiers not supported.

### Test fixture implications

- **Do not test**: exception handling, `namespace` blocks, `dynamic_cast`, `explicit` constructors, `wchar_t`, covariant returns, `new(std::nothrow)`, universal character names. The original compiler rejects or ignores these.
- **Test with caveats**: RTTI only on static/non-polymorphic types; new-style casts should behave identically to C-style casts; `extern inline` with static data is a known gap.
- **Test freely**: all core language features, templates (minus `export`), `bool`, array new/delete, full linkage spec, for-loop scoping, default template args, specialization, `typename`, member templates, partial specialization.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Suggested tests to generate

Create tests under `armcpp/recompiled/tests/` using the armlib `test_basic.c` CLI parity pattern as the harness template. Each test runs inputs through both `../../armcpp` (original) and `../build/armcpp` (recompiled), comparing exit codes, stdout/stderr, and output file bytes.

### Fixture strategy

- **Copy from 3do-devkit**: Representative `.cpp` sources from `3do-devkit/src/` (e.g., `main.cpp`, `display.cpp`, `cel_rotation.cpp`) and `3do-devkit/examples/community/`. These provide real-world C++ compilation inputs with class hierarchies and platform-specific patterns.
- **Generate minimal fixtures**: Small hand-written `.cpp` files (deterministic, self-contained) targeting specific C++ semantic areas. Compile each with the original binary to produce reference `.o` files for comparison.

### Suggested test types

- **CLI parity** — `-help`, no-args error, unrecognised options. Verify exit codes and error message text match original.
- **Basic compilation** — Compile `.cpp` fixtures (both generated minimal and 3do-devkit sources) through both binaries, compare output AOF objects with `cmp`.
- **Name lookup** — Scope resolution operator, friend function lookup, using declarations. Compare diagnostic output for ambiguous resolution cases.
- **Overload resolution** — Normal overload selection, ambiguous call errors, implicit conversion ranking, const-correctness in overload selection.
- **Language modes** — ARM vs standard C++ mode flags. Verify each mode produces identical output to original.
- **Diagnostic parity** — Ambiguous call errors, access violation messages, undefined reference diagnostics, template instantiation errors. Error text must match original exactly.
- **Class semantics** — Constructor/destructor ordering, virtual function dispatch, multiple inheritance layout, operator overloading.
- **Adversarial inputs** — Empty files, files with only `#include`, syntax errors in class bodies, ambiguous overload sets, circular dependencies.

### Suggested algorithmic pre-C++98 fixtures

Generate pure C++ source files using only pre-C++98 features (no `bool` keyword reliance, no `static_cast`/`reinterpret_cast`, no templates beyond basics available in ARM C++). Each fixture must be self-contained with no external dependencies. Compile with the original binary to produce reference `.o` files, then verify the recompiled binary produces identical output.

- **CRC32** — CRC32 as a class with static table member, operator() for processing. Tests: class code generation, static member handling, constructor initialization of lookup table.
- **MD5** — MD5 as a class with private round constants, public update/finalize methods. Tests: class layout, method inlining decisions, const member functions, private data access patterns.
- **Fibonacci** — Iterative free function + recursive version with memoization using a simple cache class. Tests: function overloading, default arguments, static local variable handling.
- **Prime sieve** — Sieve encapsulated in a class with iterator-style next() method. Tests: class state management, operator overloading (e.g., operator++ for prime iteration).
- **Sort algorithms** — Template-free sort implementations using function overloading for different types, comparator as function pointer or functor class. Tests: overload resolution, function pointer generation, functor object layout, vtable generation for polymorphic comparators.
- **String class** — Minimal String class with manual memory management, operator+, operator==, c_str(). Tests: constructor/destructor ordering, copy semantics, operator overloading code generation, memory management patterns.
- **Bit vector** — Fixed-size bit vector class with operator[], bitwise operators, popcount method. Tests: operator overloading for subscript, friend functions, inline method decisions.
- **Matrix class** — Fixed-size matrix with operator(), operator*, transpose method. Tests: multi-dimensional indexing, arithmetic operator overloading, return-by-value optimization.
- **UB / edge cases** — Virtual destructor omission, slicing through base-class copy, diamond inheritance without virtual base, pure virtual call from constructor, static initialization order fiasco, placement new on misaligned buffer, delete through base pointer without virtual destructor. Tests: diagnostic generation, vtable layout, object construction/destruction ordering. Note: RTTI is only partial (static/non-polymorphic types); do not test dynamic typeid or dynamic_cast.
- **Template basics** — Simple class templates (pair, optional-like), function templates (swap, min, max). Tests: template instantiation, name mangling for template functions, code bloat from multiple instantiations. Note: `export` is not supported.
- **New-style casts** — `static_cast`, `const_cast`, `reinterpret_cast` syntax accepted but behave as C-style casts. Tests: syntax acceptance, identical output to old-style casts.

### Suggested structural pre-C++98 fixtures

Generate `.cpp` files that exercise specific C++ compiler code-generation and semantic analysis features beyond algorithmic correctness. These target how armcpp handles language constructs, ABI decisions, and diagnostic behavior.

- **Virtual inheritance diamond** — `class A {}; class B : virtual A {}; class C : virtual A {}; class D : B, C {};`. Tests virtual base table layout, constructor delegation, `this` pointer adjustment. Note: RTTI for virtual bases is partial (static types only).
- **Multiple inheritance** — Classes with 3+ base classes, mixed virtual/non-virtual bases. Tests vtable layout, thunk generation, pointer adjustment during casts.
- **Operator overloading suite** — Arithmetic (`operator+`, `operator*`), comparison (`operator<`, `operator==`), stream (`operator<<`, `operator>>`), subscript (`operator[]`), function call (`operator()`). Tests name mangling for operators, implicit conversion triggering, temporary object generation.
- **RAII resource wrappers** — File handle wrapper, mutex lock guard, memory pool guard. Tests constructor/destructor pairing, stack unwinding with multiple guards. Note: no exceptions; cleanup is purely scope-based.
- **Copy semantics** — Deep copy vs shallow copy, copy-on-write string, self-assignment guard in `operator=`. Tests copy constructor generation, assignment operator generation, temporary object lifecycle.
- **Pure virtual interfaces** — Abstract base classes with pure virtual methods, concrete implementations. Tests vtable entries for pure virtuals, abstract class instantiation prevention. Note: no `dynamic_cast` to interface.
- **Static initialization** — Global objects with interdependent constructors, static local variable initialization. Tests static initialization order, guard variable generation for function-local statics, construction before main.
- **Explicit template specialization** — Full and partial specializations of class templates. Tests specialization selection, separate compilation of specialized methods.
- **Friend patterns** — Friend functions accessing private members, friend classes, friend templates. Tests access control enforcement, name lookup for friend declarations, symbol visibility.

## Step 1 completion criteria

Step 1 for `armcpp` is complete when:

1. Recompiled `armcpp` builds repeatably and processes all original C++ inputs.
2. Shared tests match original behavior for language-mode handling, name lookup, and diagnostics.
3. Parity checks cover emitted objects and compatibility-sensitive text output.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original features are excluded.
