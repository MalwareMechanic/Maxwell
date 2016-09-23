#ifndef _WHITELIST_H_
#define _WHITELIST_H_
bool ProcessWhitelist();
bool is_ignored_file_unicode(const wchar_t *fname, int length);
bool MemoryWhitelist(DWORD_PTR Addr, SIZE_T size);

#endif