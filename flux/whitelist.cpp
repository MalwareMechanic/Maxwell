#include <Windows.h>
#include "log.h"

const char *ignoredProc[] = {
	"C:\\Python27\\python.exe",
	"\\\\?\\C:\\Windows\\system32\\wbem\\WMIADAP.EXE",
    "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\mscorsvw.exe",
};

bool ProcessWhitelist()
{
	char ProcPath[MAX_PATH];
	GetModuleFileNameA(NULL, ProcPath, MAX_PATH);
	for (int i = 0; i < ARRAYSIZE(ignoredProc); i++)
	{
		if (strcmp(ProcPath, ignoredProc[i]) == 0)
			return true;
	}
	return false;

}

#define S(s, f) {L##s, sizeof(s)-1, f}

#define FLAG_NONE           0
#define FLAG_BEGINS_WITH    1

static struct _ignored_file_t {
	const wchar_t   *unicode;
	unsigned int    length;
	unsigned int    flags;
} g_ignored_files[] = {
	S("\\lsass", FLAG_NONE),
	S("\\wkssvc", FLAG_NONE),
	S("\\MsFteWds", FLAG_NONE),
	S("\\srvsvc", FLAG_NONE),
    S("\\Maxwell", FLAG_NONE),
    S("\\traffic.pcap", FLAG_NONE),

    S("\\Users\\max\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Local\\Microsoft\\Internet Explorer\\DOMStore\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Local\\Microsoft\\Internet Explorer\\Recovery", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\LocalLow\\Microsoft\\Internet Explorer\\Services\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Roaming\\Macromedia\\Flash Player\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Roaming\\Adobe\\Flash Player\\AssetCache\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Roaming\\Microsoft\\Internet Explorer\\UserData\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive\\NonCritical", FLAG_BEGINS_WITH),

	S("\\Windows\\System32\\wbem\\Performance\\", FLAG_BEGINS_WITH),
	S("\\Windows\\Microsoft.NET\\Framework\v2.0.50727\\", FLAG_BEGINS_WITH),
    S("\\Users\\max\\AppData\\Local\\Microsoft\\Internet Explorer\\VersionManager\\ver", FLAG_BEGINS_WITH),
	S("\\logs\\", FLAG_BEGINS_WITH),
	S("\\drop\\", FLAG_BEGINS_WITH),
};

bool is_ignored_file_unicode(const wchar_t *fname, int length)
{
	struct _ignored_file_t *f = g_ignored_files;
	for (unsigned int i = 0; i < ARRAYSIZE(g_ignored_files); i++, f++) {
		if (f->flags == FLAG_NONE && length == f->length &&
			!_wcsnicmp(fname, f->unicode, length)) {
			return true;
		}
		else if (f->flags == FLAG_BEGINS_WITH && length >= f->length &&
			!_wcsnicmp(fname, f->unicode, f->length)) {
			return true;
		}
	}
	return false;
}

#define M(s, m, f) {##s, sizeof(s)-1, ##m, f }
#define FLAG_BEGIN	0
#define FLAG_ANY	1
#define FLAG_END	3

static struct _ignored_mem {
	const char   *buf;
	unsigned int    length;
	const char * mask;
	unsigned int flag;
} ignored_mem[] = {
	M("dtrR\x00\x00", "xxxxxx", FLAG_BEGIN),
	M("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "xxxxxxxxxx", FLAG_BEGIN),
	M("\xb0\x00\xebp\xb0\x01\xebl\xb0\x02", "xxxxxxxxxx", FLAG_BEGIN),
	M("....\x00\x00\x00\x00\xec", "****xxxxx", FLAG_BEGIN),
	M("\x00\x00\x62\x09\x01\x00\x00\x00\x00\x00","xxxxxxxxxx",FLAG_BEGIN),
	M("\x00\x00\x00\x00\x00\x00\x00\x00\x20", "xxxxxxxxx", FLAG_BEGIN),
};

bool MemoryWhitelist(DWORD_PTR Addr, SIZE_T size)
{
	for (unsigned int i = 0; i < ARRAYSIZE(ignored_mem); i++)
	{
		if (ignored_mem[i].flag == FLAG_BEGIN)
		{
			if (size >= ignored_mem[i].length)
			{
				try
				{
					for (unsigned int j = 0; j < ignored_mem[i].length; j++)
					{
						char x = *(BYTE*)(Addr + j);
						char y = ignored_mem[i].buf[j];
						if (x == y || ignored_mem[i].mask[j] == '*')
						{
							if (j + 1 == ignored_mem[i].length)
							{
								return true;
							}
						}
						else
						{
							break;
						}
					}
				}
				catch(...)
				{
				//	LOG("s", "Exception", "FLAG_BEGIN");
				}
			}
		}
		else if (ignored_mem[i].flag == FLAG_ANY)
		{
			try
			{

				for (unsigned int k = 0; k < (size - ignored_mem[i].length); k++)
				{
					DWORD_PTR start = Addr + k;

					if (size >= ignored_mem[i].length + k)
					{
						for (unsigned int j = 0; j < ignored_mem[i].length; j++)
						{
							char x = *(BYTE*)(start + j);
							char y = ignored_mem[i].buf[j];
							if (x == y || ignored_mem[i].mask[j] == '*')
							{
								if (j + 1 == ignored_mem[i].length)
								{
									return true;
								}
							}
							else
							{
								break;
							}
						}
					}
					else
					{
						break;
					}
				}
			}
			catch (...)
			{
				//LOG("s", "Exception", "FLAG_ANY");
			}
		}
		else if (ignored_mem[i].flag == FLAG_END)
		{

			try
			{
				if (size >= ignored_mem[i].length)
				{
					DWORD_PTR endAddr = Addr + size - ignored_mem[i].length;
					for (unsigned int j = 0; j < ignored_mem[i].length; j++)
					{
						char x = *(BYTE*)(endAddr + j);
						char y = ignored_mem[i].buf[j];
						if (x == y || ignored_mem[i].mask[j] == '*')
						{
							if (j + 1 == ignored_mem[i].length)
							{
								return true;
							}
						}
						else
						{
							break;
						}
					}
				}
			}
			catch (...)
			{
				//LOG("s", "Exception", "FLAG_END");
			}
		}
	}

	return false;

}