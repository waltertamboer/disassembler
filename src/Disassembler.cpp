/**
 * A basic disassembler written by Walter Tamboer
 *
 * http://waltertamboer.nl
 * https://github.com/WalterTamboer/disassembler
 */

#include "PrecompiledHeader.hpp"
#include "Disassembler.hpp"

namespace Disassembler
{
	Disassembler::Disassembler()
		: m_FileHandle(nullptr), m_DosHeader(nullptr), m_NtHeader(nullptr)
	{
	}

	Disassembler::~Disassembler()
	{
		if (m_FileHandle != nullptr)
		{
			CloseHandle(m_FileHandle);
			m_FileHandle = nullptr;
		}
	}

	bool Disassembler::run(const std::wstring& path)
	{
		m_FileHandle = CreateFile(
			path.c_str(), 
			GENERIC_READ, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);
		
		m_FileHandle = CreateFile(
			path.c_str(), 
			GENERIC_READ, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);

		if (m_FileHandle == INVALID_HANDLE_VALUE)
		{
			std::wcout << "Failed to open the file '" << path << "'." << std::endl;
			return 1;
		}

		return disassembleFile();
	}

	bool Disassembler::disassembleFile()
	{
		HANDLE fileMapping = CreateFileMapping(m_FileHandle, NULL, PAGE_READONLY, 0, 0, NULL);

		bool result = disassembleFileMapping(fileMapping);

		CloseHandle(fileMapping);

		return result;
	}

	bool Disassembler::disassembleFileMapping(HANDLE fileMapping)
	{
		LPVOID view = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

		bool result = disassembleFileMappingView(view);

		UnmapViewOfFile(view);

		return result;
	}

	bool Disassembler::disassembleFileMappingView(LPVOID base)
	{
		m_DosHeader = (PIMAGE_DOS_HEADER)base;
		if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			std::cout << "No valid DOS magic number found." << std::endl;
			return false;
		}

		m_NtHeader = (PIMAGE_NT_HEADERS)((DWORD)base + m_DosHeader->e_lfanew);
		if (m_NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			std::cout << "This file is not a valid PE file." << std::endl;
			return false;
		}

		DWORD preferredBase = m_NtHeader->OptionalHeader.AddressOfEntryPoint + m_NtHeader->OptionalHeader.ImageBase;
		DWORD sectionHeaderBase = (DWORD)base + m_DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);

		for( int i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i++ )
		{
			if (!disassembleSection((PIMAGE_SECTION_HEADER)sectionHeaderBase, preferredBase))
			{
				return false;
			}

			sectionHeaderBase += sizeof(IMAGE_SECTION_HEADER);
		}

		return true;
	}

	bool Disassembler::disassembleSection(PIMAGE_SECTION_HEADER section, DWORD preferredBase)
	{
		std::cout << section->Name
			<< " "
			<< std::hex
			<< section->Misc.VirtualSize
			<< " "
			<< section->VirtualAddress
			<< " "
			<< section->SizeOfRawData
			<< " "
			<< section->PointerToRawData
			<< " "
			<< section->Characteristics
			<< std::endl;

		SetFilePointer(m_FileHandle, section->PointerToRawData, NULL, FILE_BEGIN);

		DWORD dwBytesRead = 0;
		BYTE *buffer = new BYTE[section->SizeOfRawData];
		ReadFile(m_FileHandle, buffer, section->SizeOfRawData, &dwBytesRead, NULL );

		bool result = disassembleSectionBuffer(section->SizeOfRawData, buffer, preferredBase);

		delete[] buffer;

		return result;
	}

	bool Disassembler::disassembleSectionBuffer(DWORD rawDataSize, BYTE* buffer, DWORD preferredBase)
	{
		for (DWORD index = 0; index < rawDataSize; index++)
		{
			DWORD address = preferredBase + index;

			std::cout << std::hex << address << ":\t";

			index += disassembleSectionData(buffer, preferredBase, index);
		}

		return true;
	}

	DWORD Disassembler::disassembleSectionData(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		DWORD result = 0;

		switch (buffer[index])
		{
		case 0x33:
			result += disassembleInstructionXor(buffer, preferredBase, index);
			break;

		case 0x50:
			result += disassembleInstructionPushEax(buffer, preferredBase, index);
			break;

		case 0x53:
			result += disassembleInstructionPushEbx(buffer, preferredBase, index);
			break;

		case 0x58:
			result += disassembleInstructionPopEax(buffer, preferredBase, index);
			break;

		case 0x5B:
			result += disassembleInstructionPopEbx(buffer, preferredBase, index);
			break;

		case 0x6A:
			result += disassembleInstructionPush(buffer, preferredBase, index);
			break;

		case 0x74:
			result += disassembleInstructionJeShort(buffer, preferredBase, index);
			break;

		case 0x83:
			result += disassembleInstructionCmp(buffer, preferredBase, index);
			break;

		case 0x85:
			result += disassembleInstructionTest(buffer, preferredBase, index);
			break;

		case 0xB8:
			result += disassembleInstructionMovEax(buffer, preferredBase, index);
			break;

		case 0xBB:
			result += disassembleInstructionMovEbx(buffer, preferredBase, index);
			break;

		case 0xE8:
			result += disassembleInstructionCall(buffer, preferredBase, index);
			break;

		case 0xFF:
			result += disassembleInstructionJmp(buffer, preferredBase, index);
			break;

		default:
			result += disassembleInstructionUnknown(buffer, preferredBase, index);
			break;
		}

		return result;
	}

	DWORD Disassembler::disassembleInstructionCall(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "call " 
			<< std::hex 
			<< (DWORD)buffer[index + 1] 
			<< (DWORD)buffer[index + 2] 
			<< (DWORD)buffer[index + 3] 
			<< (DWORD)buffer[index + 4] 
			<< std::endl;

		return 4;
	}

	DWORD Disassembler::disassembleInstructionCmp(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "cmp";

		switch (buffer[index + 1])
		{
		case 0xFB:
			std::cout << " ebx, " << std::hex << (DWORD)buffer[index + 2];
			break;
			
		case 0xF8:
			std::cout << " eax, " << std::hex << (DWORD)buffer[index + 2];
			break;

		default:
			break;
		}

		std::cout << std::endl;

		return 2;
	}

	DWORD Disassembler::disassembleInstructionJmp(BYTE* buffer, DWORD preferredBase, DWORD index)
	{	
		DWORD result = 0;

		if (buffer[index + 1] == 0x25)
		{
			std::cout << "jmp dword ptr ds:["
				<< std::hex
				<< (DWORD)buffer[index + 2]
				<< (DWORD)buffer[index + 3]
				<< (DWORD)buffer[index + 4]
				<< (DWORD)buffer[index + 5]
				<< "]"
				<< std::endl;

			result = 5;
		}

		return result;
	}

	DWORD Disassembler::disassembleInstructionJeShort(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		DWORD offset = preferredBase + index + 2 + buffer[index + 1];

		std::cout << "je short " << std::hex << offset << std::endl;

		return 1;
	}

	DWORD Disassembler::disassembleInstructionMovEax(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "mov eax," << std::hex << (DWORD)buffer[index + 1] << std::endl;
		return 4;
	}

	DWORD Disassembler::disassembleInstructionMovEbx(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "mov ebx " << std::hex << (DWORD)buffer[index + 1] << std::endl;
		return 4;
	}

	DWORD Disassembler::disassembleInstructionPopEax(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "pop eax" << std::endl;
		return 0;
	}

	DWORD Disassembler::disassembleInstructionPopEbx(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "pop ebx" << std::endl;
		return 0;
	}

	DWORD Disassembler::disassembleInstructionPush(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "push " << std::dec << (DWORD)buffer[index + 1] << std::endl;
		return 1;
	}

	DWORD Disassembler::disassembleInstructionPushEax(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "push eax" << std::endl;
		return 0;
	}

	DWORD Disassembler::disassembleInstructionPushEbx(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "push ebx" << std::endl;
		return 0;
	}

	DWORD Disassembler::disassembleInstructionTest(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "test";

		switch (buffer[index + 1])
		{
		case 0xDB:
			std::cout << " ebx,ebx";
			break;

		case 0xC0:
			std::cout << " eax,eax";
			break;

		default:
			break;
		}

		std::cout << std::endl;

		return 1;
	}

	DWORD Disassembler::disassembleInstructionXor(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "xor";

		if (buffer[index + 1] == 0xC0)
		{
			std::cout << " eax,eax";
		}
		else if (buffer[index + 1] == 0xDB)
		{
			std::cout << " ebx,ebx";
		}

		std::cout << std::endl;

		return 1;
	}

	DWORD Disassembler::disassembleInstructionUnknown(BYTE* buffer, DWORD preferredBase, DWORD index)
	{
		std::cout << "db " << std::hex << (DWORD)buffer[index] << std::endl;
		return 0;
	}
}
