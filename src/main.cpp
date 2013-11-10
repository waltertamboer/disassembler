/**
 * A basic disassembler written by Walter Tamboer
 *
 * http://waltertamboer.nl
 * https://github.com/WalterTamboer/disassembler
 */

#include "PrecompiledHeader.hpp"
#include "Disassembler.hpp"

int _tmain(int argc, _TCHAR* argv[])
{
	Disassembler::Disassembler disassembler;

	if (argc < 2)
	{
		std::cout << "Usage: disassembler fileToDisassemble" << std::endl;
		return 1;
	}
	
	return disassembler.run(argv[1]) ? 0 : 1;
}
