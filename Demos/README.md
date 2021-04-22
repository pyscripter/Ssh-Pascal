### Instructions for running the demos

- Open the dpr file in Delphi
- In Project, Options under "Compiler Options" specify specify "..\\..\\Bin\\$(Platform)" as the output directory.  This will avoid the need to copy the deployment libraries to the executable directory.
- Use Run, Parameters to provide suitable command-line parameters
- Run or debug the demos from the Delphi IDE.