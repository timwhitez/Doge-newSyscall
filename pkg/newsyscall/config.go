package newsyscall

type (
	DWORD     uint32
	ULONGLONG uint64
	WORD      uint16
	BYTE      uint8
	LONG      uint32
)

const (
	MEM_COMMIT  = 0x001000
	MEM_RESERVE = 0x002000
	IDX         = 32
)

type unNtd struct {
	pModule uintptr
	size    uintptr
}

// Library - describes a loaded library
type Library struct {
	Name        string
	BaseAddress uintptr
	Exports     map[string]uint64
}

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
)

type _IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_FILE_HEADER _IMAGE_FILE_HEADER

type IMAGE_OPTIONAL_HEADER64 _IMAGE_OPTIONAL_HEADER64
type IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}
type _IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}
type IMAGE_DATA_DIRECTORY _IMAGE_DATA_DIRECTORY

type _IMAGE_NT_HEADERS64 struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}
type IMAGE_NT_HEADERS64 _IMAGE_NT_HEADERS64
type IMAGE_NT_HEADERS IMAGE_NT_HEADERS64
type _IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DOS_HEADER _IMAGE_DOS_HEADER

var hookedapi = []string{"15b9463b6ebb4c271a615df3a0e94b034bd539f4", "f5f80bb355dfeac91ae8d3ac3837fa1a859a9182", "98c0e7aeaa7cfe44e841a1e8d7ca0c3fe031d5c2", "04262a7943514ab931287729e862ca663d81f515", "e8d02c5ad8677d34be44742e93beff65a4b0096d", "0a602922644e8bbcfc3339d53bec5a62ba70916c", "df5a9d992d87f1ffd8a0e264efee12d0bb6588dc", "6ee6e75a7ec33ef750d48225b1efcb71c91499a3", "9ff6fa2b8fb83ea0432045d6766ca0e3ae7038aa", "f1ec0b2e52b8a40ef01b3512f007a79df6e94eb0", "3ac851354afeaa4429ccc36ba79f034c7dc2d521", "2e597b557e9e74ee80a809768b0e69b3ced08ca6", "df1a83db80c83f59a3b2c0337d704fe579401473", "06e877128ef82c17d7e772d3b266425217026272", "8c2beefa1c516d318252c9b1b45253e0549bb1c4", "91958a615f982790029f18c9cdb6d7f7e02d396f", "38ddf35aac26fbc18787e2d5409d396cf9a033f5", "84804f99e2c7ab8aee611d256a085cf4879c4be8", "32be5bbc7d877b871818a53cab08ef40e7a42c3b", "e29d137622fea28f1601e9c4db12ee8815836168", "a1d05025332c91a8c5618aebbb67ec0eed8423da", "7b4de15f2536a9fba49672485b8f598880345622", "00b66f89be96d7fa40e584d7eb9728f9b43e29d2", "00a703c63c1b4c30c68e94e216fca2475e8b433c", "fa2fc5b74e9a9da9bd3ad4322568f2e2a77d3bda", "4bf8c7b359e848d956eeaf0f34a634de68381aaf", "e44543e6033227c0ccf74065d7c129fd44ad6d72", "1e369e672361dd9bf33903ac273188b55f718ae9", "e4f8711db3bdcf171ef2a587eef11a88769f8436", "6020cf768d1b404612fdb1981e3e025e3704764a", "52355143c8beb1a98a7bb50f862cf0493ca67ee2", "15508eac8f0d22a830cbfae323b46d314029eca5", "ee60ccc9cd3f5d32c7013918694a833febe7aa4b", "7cb7fb48f3e9cfc2e2c692b93e2b10519ab161cb", "d328cda61cc036ae11b0c961aad82553d5a97ff8", "4004985833ffe74ded36f4470263427b6205cde9", "aabf1b0a27c6a6f878207c018d00558b06593a57", "3dca0c391dab95ebd1e68d0fb2cd9884b19eec82", "2582169ad1cb19ff1f27f9965e95108767353534", "b2e8d70a1327d535590e11bdd9fbaf17593e00d4", "5fcb80f4860b40a12a9a33a664954beb36271a20", "059637f5757d91ad1bc91215f73ab6037db6fe59", "5484af2fe93ebc7ae1c30af9ad978bb817a9184e", "ae3a279785651a5e5bdb5d43abf9470ead77c5eb", "5dc83c740d32f0d99ca6923830a29cf7b33ea405", "777e1962aa30c83ccb29874bb58c03b76f81e346", "1338830650b98326c8fa67660818f8ad5015cfa8", "ff06d2a62a1b4f33ab91d501ad53158cf899f780", "24ef15280221dcfa1eb15ec79f2570b324d85a06", "7c9afc9fb9345bc8598e2433aa1eb0c10b9f7e74", "24b985d5cb2367342a409057dcbf764bbf2c1c97", "80f14fbcb28ac3840dfcd5c46e9049380fb21467", "43ada77e56c062029486709b858b089175a42434", "ee680bb3dc4f47d1e3a14538f25a98899974d0dc", "8d1f75361ce3bb9fae20905d6eef038567bbfa5d", "e11f2cdcd205601d9b8551e35e8d3fe414b3350c", "eba66f227cb81a6e33171126785087fef2a23964", "e7f51d980633a074f844b9310a5177da0e09f62c", "b4cd871d9fb455919b7224e2098a63aaf0fa57cd", "e21de3e4e2ce4ba662cb22f6137d0a65a6aeb195", "a447c7c1c9d6025cb52c57b9fbd61619ab6cda1e", "973e29991918a6755efd09628bd4f33eed83e910", "dfe120de1844de0023554aca90a70e79f8dcd023", "0430fa2b2b00aa2a343dd0cf1a37e386de086b8b", "00fc6f0291ecc4743243851f7fb3ddfcf54fcfde", "e7e503e95407d0620f0b9e33b1e9861b32dbd3c6", "e43b5003e940dbf77598c99c6f8814f5432b8af2", "b7582e26d262f02fa593dfc2afac08cdd0475d85", "934ba7320b26692a46b2079327eee4ae75379eff", "c8022d58d347ae20ebad6a19742ad2c1d2ba5d53", "d3d72a1e7dcfe535371b84e0786302feab22d6d1", "bab64ab3009f237d28c9dc1ed3707190336fae77", "630b5bff9a195abb86d44ca2f65467bb0f996d9f", "bbcaba7d62b64f0d64972ac875bebeced87eb5e9", "d59c852c8b0241cf7fc6821a943ee157341dd175", "539f57e5744ca09c2914cd147427736b6860615c", "18ede0448e4ad01e04175beb0c5216977ddf8b74", "6caed95840c323932b680d07df0a1bce28a89d1c", "59b7e129371d567ab9ff9bf9e4463424b7dd4a11", "50454e4fa4c8a139f674836972ac46ec7dd46e56", "d75f63a367c3ac7e27bb0abaef4588dd27709196", "0667405eec3a1ce10ec6e4100da43890be68a6f5", "e2c8e43cb2cabef7c790af5b9ec86eea316d47c3", "27dffd1dd7df9bcfcdcf0513700515a7f6eeb766", "ad41dfc29c61dd50b290626bc505473fee129013", "6e3f4091fa9a78daaa92656965bae738957848d7", "2e715068746392cd28ee70a2c1fe195105f5bdfc", "e7cc12d0a31a64cfb3592e07b2930f552354525e", "512ba0db263aadd932c74711cc6636d652a8fcfd", "42fef932368f5b3294a3515ddf825587e46544d0", "5d00bd6255f0705bcae248c6a260b7c799969796", "28b94a540bdf6ce2960c96f1d3c2704c7db4f0ad", "66ca9bced91a4a1456f40a5a1adade05651e9c4f", "6c77983fd061dc56b34b08d326655d42f87dd192", "3475dd0624c9049d9e28fa2fb083eebcce2162bc", "60e2031ed26f1e6b5d968ee41ab0f4085ac2a9d1", "245656aa1c10628334ae829722f5706bd5641b69", "9e5b671461471fad1fa0bd434f64d6b3fe1c1d64", "94bad7b0a174f135a6f253720fbbfc17cde6a1df", "53a16c12d601b25f4785e62e858e51fc88b27e41", "03a88c31dcedabba5ebf637d0ff7a65666ac8d56", "c8bdf44a167cf70216ab3c97d012c558d5aa23eb", "53cd2292c0d76f4166598ca89979d57c8fbeeca3", "70f8af25efd4d4783e4a92d1e3bc88dc0ea8ac0f", "b2ad246aa6732e4f0defbb51c22bb4fa905baa19", "4cd47a1316933e750a8e113d2619931ea5495f78", "4722e0577c85ecb9c134ffbb2ce080fee0ba5d64", "650d7a3cc9421a5552d33e69ec9533f2a5034e2e", "b84e0c4945bda8ff2f5e4b5ea35c2b19c998a46c", "b1533c8a4627af97134439271073274184caa7ff", "521321c0c24ab6cbe71cd18dbd0cbd6c7b6f8ccd", "35093dea97c5a998974cdde5f884ae89baa3e7cc", "041978235606f21d126fb6c8dd7c03d5b2cf7813", "4ef41467627dbdb704a4e29cd3c7264e828b1f30", "cea29ef21a928876271307bd63b8e0f16064e041", "510e3ca97226a67602eac6ef945877c75e6c9e54", "1c12e2cb7ba4a7f67408c91888076ef23bef9291", "e6439fb2a49fd2581d22baf12da13c5cba577ab0", "4f10b73e83ecb438380cc8c248bc75ec57c80c19", "5d4a1a9da970a75f362c0c529622b35b764c9025", "ed55b35dafa796b39073abc1537e8f8251230e3f", "66a36894d9f588ef736d9d960c41c39b01ce00e8", "ac38e0975073d359388476d57e04eb4760df5572", "5e821365365709ad73ad7aa62851be1ae66a707b", "f3f0b849d7fe4470b3321e5df813478e658d4709", "752568e97474e926ba9511039047a343e48c89c0", "58a75ba3086b82ca71bc29b276a4144f93905df8", "bddf60e57d4db0132b31f36980501268e71c92bf", "cf6f633bf591b6044d9c2fce05d1a9cce06bba64", "3910d3a78490d1944f9799f1177dfa332edda1be", "8ec384e0b9287086f1283a050753ba20fd90307d", "e443ed560b708d022b1aac71f0f637a58436e3d0"}
