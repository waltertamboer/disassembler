/**
 * A basic disassembler written by Walter Tamboer
 *
 * http://waltertamboer.nl
 * https://github.com/WalterTamboer/disassembler
 */

#pragma once

namespace Disassembler
{
	class Disassembler
	{
	public:
		Disassembler();
		~Disassembler();
		bool run(const std::wstring& path);

	private:
		bool disassembleFile();
		bool disassembleFileMapping(HANDLE fileMapping);
		bool disassembleFileMappingView(HANDLE view);
		bool disassembleSection(PIMAGE_SECTION_HEADER section, DWORD preferredBase);
		bool disassembleSectionBuffer(DWORD rawDataSize, BYTE* buffer, DWORD preferredBase);
		DWORD disassembleSectionData(BYTE* buffer, DWORD preferredBase, DWORD index);

		DWORD disassembleInstructionCall(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionCmp(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionJmp(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionJeShort(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionMovEax(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionMovEbx(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionPopEax(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionPopEbx(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionPush(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionPushEax(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionPushEbx(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionTest(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionXor(BYTE* buffer, DWORD preferredBase, DWORD index);
		DWORD disassembleInstructionUnknown(BYTE* buffer, DWORD preferredBase, DWORD index);

		HANDLE m_FileHandle;
		PIMAGE_DOS_HEADER m_DosHeader;
		PIMAGE_NT_HEADERS m_NtHeader;
	};
}
