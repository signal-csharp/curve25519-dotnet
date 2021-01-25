# Contributing to curve25519-dotnet

This repo aims to reflect Signal's [curve25519-java](https://github.com/signalapp/curve25519-java). Any commits there should be replicated here.

## Building

### Requirements

1. [.NET Core 3.1 or greater](https://dotnet.microsoft.com/download)
    - Opening in Visual Studio requires Visual Studio 2019 (v16.4.0) or greater

### Steps

#### Visual Studio

1. Open the curve25519-dotnet.sln in Visual Studio
2. Build the solution
3. Run the tests using the Test Explorer window

#### Command Line

1. `dotnet build`
2. `dotnet test`

## Replicating a commit

1. Make changes
    - The code here should largely reflect the code in curve25519-java. The major difference will be how pointers vs arrays are handled as we can't do pointer math in safe C#.
    - It's OK to turn C style if functions that return an int to C# style if functions that return a boolean. (see [C gen_labelset#is_labelset_empty](https://github.com/signalapp/curve25519-java/blob/b71b9f135d3941ca7e8eafd3807f68e688dd5891/android/jni/ed25519/additions/generalized/gen_labelset.c#L114-L118) vs [C# gen_labelset.is_labelset_empty](https://github.com/signal-csharp/curve25519-dotnet/blob/30d2a462c40030d44a568c42c48138ce53bc1d1f/curve25519-dotnet/csharp/gen_labelset.cs#L126-L131))
2. Test changes
    - Tests here should match tests in the curve25519-java. Tests should pass before creating a PR. When testing C changes it's best practice to run just `InternalFastTests.cs`. Once all tests there pass run `InternalSlowTests.cs`. If you want to be really sure unignore `generalized_xveddsa_slow_test` and make sure that passes as well.
3. Commit changes with your commit message matching the commit message from curve25519-java. For example [this](https://github.com/signal-csharp/curve25519-dotnet/commit/a1d500d505d2edefc1646f1142d290b890bd2d7a). It's also include a link back to the curve25519-java commit in your commit description.

## Debugging curve25519-java in Android Studio

TODO because I haven't figured it out yet.

## Debugging curve25519-java C tests

If your tests fail after you've made your changes it can be helpful to debug the C code to see what the delta is.

### Debugging on Windows using Visual Studio Code

1. Follow the prerequisite steps from the [VSCode documentation](https://code.visualstudio.com/docs/cpp/config-msvc#_prerequisites)
2. Launch a Developer Powershell for Visual Studio
3. Copy the `.vscode` folder from `docs/curve25519-java C debugging` to where you cloned curve25519-java
4. Navigate to where you cloned curve25519-java
5. Checkout the commit you're replicating then the repo in VSCode (`code .`)
6. Create a `main.c` and reference the test file you want to run. Example below.
```c
#include "internal_fast_tests.h"

int main(int argc, char* argv[])
{
    all_fast_tests(0);
    return 0;
}
```
7. You may need to edit some C files to fix errors. For example you can't use MSG_LEN to define array lengths in internal_fast_tests.c so replace that with the value of MSG_LEN.
8. Set any needed breakpoints
9. Start the debugger

Note that this will create a bunch of .obj, .ilk, .pdb, and .exe files in the root directory.
