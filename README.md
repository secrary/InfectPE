# InfectPE

Using this tool you can inject x-code/shellcode into PE file.
InjectPE works only with 32-bit executable files.

## Why you need InjectPE?
* You can test your security products.
* Use in a phishing campaign.
* Learn how PE injection works.
* ...and so on.

In the project, there is hardcoded x-code of MessageBoxA, you can change it.

## Download
[Windows x86 binary](https://github.com/secrary/InfectPE/releases) - Hardcoded MessageBoxA x-code, only for demos.
## Dependencies: 
[vc_redist.x86](https://www.microsoft.com/en-us/download/details.aspx?id=53840) - Microsoft Visual C++ Redistributable

## Usage
```
.\InfectPE.exe .\input.exe .\out.exe code
```
x-code is injected into code section, this method is more stealthy, but sometimes there is no enough space in the code section.

```
.\InfectPE.exe .\input.exe .\out.exe largest
```

x-code is injected into a section with the largest number of zeros, using this method you can inject bigger x-code. This method modifies characteristics of the section and is a bit more suspicious.

In the patched file, ASLR and NX are disabled, for the more technical information you can analyze VS project.

Please, don't use with packed or malformed executables.

## TODO: 
Add more techniques to inject x-code into PE file.
