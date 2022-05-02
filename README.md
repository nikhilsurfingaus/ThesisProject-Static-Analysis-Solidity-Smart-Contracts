# ThesisProject
## Intro
TODO
## Dependicies
TODO
## Usage
### Standard Contract
TODO
### Withdraw Function
TODO
## Bugs Detected
### Overflow/Underflow Vulnerabiltiies
Num | Detector | Detection Details | Solutuion | Risk | Confidence
--- | --- | --- | --- | --- | --- |
1 | `Check Safe Math` | This check catches if a smart contract is defined using the
^ operator for compiler version. | Best practice to use static rather than dynamic compiler version
as future versions could have unintended effects | Medium | High
2 | `Check Integer Operations` | This check catches if a smart contract is defined without
the Safe Math Library present when using uint variable type | Best practice to use Safe Math Library which can minimise attack
exploiting overflow/underflow vulnerabilities with arthimetic operations | High | High
3 | `Check Loop Condition` | This check catches if a smart contract uses arithemtic operations such as 
'+, -, *, /, %' when Safe Math functions could be used.  | Best practice to use Safe Math Library functions of add, sub, div, mod or mul 
which can minimise attack exploiting overflow/underflow vulnerabilities | Medium | High
4 | `Check Div Multiply` | This check catches if a smart contract has mathematical operations with
multiplication or division, that division occurs first  | Best practice to use have multiplication first, as division first can
cause loss of pecision in operations  | Medium | Medium
5 | `Check Unary` | This check catches if a smart contract contains =+, =- or =* 
which could be intended as =+, -= or *= | To minimise misconception be sure to use += or -= or *= | Low | High
6 | `Check Type Inference` | This check catches if a smart contract defined variable using var
instead of using numerical data type of uint | Should explicitly declare uint data types to 
avoid unexpected behaviors | Medium | High

### Syntax Vulnerabiltiies
Num | Detector | Detection Details | Solutuion | Risk | Impact
--- | --- | --- | --- | --- | --- |
1 | `Compiler Issue` | TODO | TODO | High | High
2 | `Check Boolean Constant` | TODO | TODO | High | High
3 | `Check Array Length` | TODO | TODO | High | High
4 | `Check Address Zero` | TODO | TODO | High | High
5 | `Check Map Struct Deletion` | TODO | TODO | High | High
6 | `Check Initial Storage Variable` | TODO | TODO | High | High
7 | `Check Assemble Shift` | TODO | TODO | High | High
8 | `Check Self Destruct` | TODO | TODO | High | High
9 | `Check Transfer` | TODO | TODO | High | High
10 | `Check Bytes` | TODO | TODO | High | High
11 | `Check Tx Origin` | TODO | TODO | High | High
12 | `Check Fuction Visibility` | TODO | TODO | High | High
12 | `Check Balance Equality` | TODO | TODO | High | High
13 | `Check Block Timestamp` | TODO | TODO | High | High
14 | `Check Block Variable` | TODO | TODO | High | High
15 | `Check Block Number` | TODO | TODO | High | High
16 | `Check Block Gas` | TODO | TODO | High | High
17 | `Check Delegate Call` | TODO | TODO | High | High
18 | `Check Loop Function` | TODO | TODO | High | High
19 | `Check Owner Power` | TODO | TODO | High | High
20 | `Check Constructor Initialise` | TODO | TODO | High | High
21 | `Check Local Variable Shadowing` | TODO | TODO | High | High
22 | `Check State Variable Shadowing` | TODO | TODO | High | High
23 | `Check Fallback` | TODO | TODO | High | High

### DAO Vulnerabiltiies
Num | Detector | Detection Details | Solutuion | Risk | Impact
--- | --- | --- | --- | --- | --- |
1 | `Check Contract Lock` | TODO | TODO | High | High
2 | `Check Require` | TODO | TODO | High | High
3 | `Check State Variable Update` | TODO | TODO | High | High
4 | `Check External Call` | TODO | TODO | High | High
5 | `Check Effect Interacts Pattern` | TODO | TODO | High | High

## Contributions
TODO
## References
TODO
