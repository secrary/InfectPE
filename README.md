![InfectPE](https://cloud.githubusercontent.com/assets/16405698/25353873/cf8d1058-2941-11e7-806a-b8f41f4f906e.png)

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
X-code is injected into code section, this method is more stealthy, but sometimes there is no enough space in the code section.

```
.\InfectPE.exe .\input.exe .\out.exe largest
```

X-code is injected into a section with the largest number of zeros, using this method you can inject bigger x-code. This method modifies characteristics of the section and is a bit more suspicious.

```
.\InfectPE.exe .\input.exe .\out.exe resize
```
Expand the size of code section and inject x-code. This technique, like "code" one, is less suspicious, also you can inject much bigger x-code.

```
.\InfectPE.exe .\input.exe .\out.exe new
```
Create a new section and inject x-code into it, hardcoded name of the section is ".infect"

In the patched file, ASLR and NX are disabled, for the more technical information you can analyze VS project.

Please, don't use with packed or malformed executables.

## Demo
[Vimeo](https://vimeo.com/214230957) - "code" and "largest" techniques.

[Vimeo](https://vimeo.com/214506728) - "resize" technique.

## TODO: 
Add more techniques to inject x-code into PE file.

## !!!
I create this project for me to learn a little bit more about PE file format. 

There are no advanced techniques. 

Just only for educational purposes.
