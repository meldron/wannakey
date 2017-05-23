#include <iostream>
#include <sstream>
#include <iomanip>

#include <wkey/process.h>
#include <wkey/tools.h>

static bool doCheck = false;
static bool doCryptDestroy = true;
static bool doCryptReleaseCtx = true;

static constexpr size_t KeyBits = 2048;
static constexpr size_t SubKeyBits = (KeyBits +1)/2;

static constexpr size_t KeyBytes = KeyBits/8;
static constexpr size_t SubKeyBytes = SubKeyBits/8;

#define USER_RSA_KEY_LEN 2048

using namespace wkey;

std::string hex(const uint8_t* Buf, const size_t Len)
{
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < Len; ++i)
  {
    ss << std::setw(2) << (size_t)(Buf[i]);
  }
  return ss.str();
}

std::vector<uint8_t> unhex(const char* Str)
{
  const size_t Len = strlen(Str);
  std::vector<uint8_t> Ret;
  if ((Len & 1) != 0) {
    return Ret;
  }

  Ret.reserve(Len/2);

  for (size_t i = 0; i < Len; i += 2) {
    uint8_t HexC[] = { Str[i], Str[i+1], 0 };
    Ret.push_back(strtoul((const char*) HexC, nullptr, 16));
  }
  return Ret;
}

static int generateKeyAndCheck(const char* ExePath)
{
  HCRYPTPROV prov;
  HCRYPTKEY keyUser;

  if (!CryptAcquireContext(&prov,
        NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT)) {
    if (!CryptAcquireContext(&prov, 0, 0, 24, 0xF0000000)) {
      std::cerr << "error CryptAcquireContext: " << getLastErrorMsg() << std::endl;
      return 2;
    }
  }

  if (!CryptGenKey(prov, AT_KEYEXCHANGE,
        (USER_RSA_KEY_LEN << 16) | CRYPT_EXPORTABLE, &keyUser)) {
    std::cerr << "error CryptGenKey: " << getLastErrorMsg() << std::endl;
    return 2;
  }

  BYTE keyData[4096];
  memset(keyData, 0xFE, sizeof(keyData));

  DWORD len = 4096;
  if (!CryptExportKey(keyUser, 0, PRIVATEKEYBLOB, 0, &keyData[0], &len)) {
    std::cerr << "error CryptExportKey: " << getLastErrorMsg() << std::endl;
    return 2;
  }

  // Get P and Q, and store them in hexadecimal value. This won't be the value we're looking for!
	size_t idx = 8+12+KeyBytes;
  auto PHex = hex(&keyData[idx], SubKeyBytes);
	idx += SubKeyBytes;
  auto QHex = hex(&keyData[idx], SubKeyBytes);

  printf("Key generated, zeroying data...\n");
  SecureZeroMemory(keyData, 4096);

  if (doCryptDestroy) {
	  CryptDestroyKey(keyUser);
	  printf("Key destroyed!\n");
  }

  if (doCryptReleaseCtx) {
	  CryptReleaseContext(prov, 0);
	  printf("Crypto context released!\n");
  }

  std::cout << "Checking whether primes are still in memory..." << std::endl;

  // Prepare the command line

  std::stringstream CmdLine;
  CmdLine << ExePath << " --check " << GetProcessId(GetCurrentProcess()) << " " << PHex << " " << QHex;
  STARTUPINFO StartupInfo;
  PROCESS_INFORMATION ProcInfo;
  memset(&StartupInfo, 0, sizeof(STARTUPINFO));
  memset(&ProcInfo, 0, sizeof(ProcInfo));
  if (!CreateProcess(NULL, (LPSTR) CmdLine.str().c_str(), NULL, NULL, false, 0, NULL, NULL, &StartupInfo, &ProcInfo)) {
    std::cerr << "Unable to create checking process: " << getLastErrorMsg() << std::endl;
    return 2;
  }

  DWORD ExitCode;
  WaitForSingleObject(ProcInfo.hProcess, INFINITE);
  GetExitCodeProcess(ProcInfo.hProcess, &ExitCode);

  CloseHandle(ProcInfo.hProcess);
  CloseHandle(ProcInfo.hThread);

  return ExitCode;
}

static int searchPrimes(uint32_t PID, const char* PHex, const char* QHex)
{
  int Ret = 1;
  auto const P = unhex(PHex);
  auto const Q = unhex(QHex);
  auto Prev = P;
  auto Qrev = Q;
  std::reverse(Prev.begin(), Prev.end());
  std::reverse(Qrev.begin(), Qrev.end());
  auto Err = walkProcessPrivateRWMemory(PID, [&](uint8_t const* Buf, const size_t Size) {
      if ((memmem(Buf, Size, &P[0], P.size()) != NULL) ||
          (memmem(Buf, Size, &Q[0], Q.size()) != NULL) ||
		  (memmem(Buf, Size, &Prev[0], Prev.size()) != NULL) ||
		  (memmem(Buf, Size, &Qrev[0], Qrev.size()) != NULL))
		{
        Ret = 0;
        return false;
      }
      return true;
  });
  if (Err) {
    std::cerr << "Error while walking process " << PID << "'s memory: " << Err.message() << std::endl;
    return 2;
  }
  return Ret;
}

static void usage(const char* Path)
{
	std::cerr << "Usage: " << Path << " [options]" << std::endl;
	std::cerr << "where options are:" << std::endl;
	std::cerr << "  -h, --help: show this help" << std::endl;
	std::cerr << "  --without-destroy-key: do not call CryptDecryptKey. Implies --without-release-ctx." << std::endl;
	std::cerr << "  --without-release-ctx: do not call CryptReleaseContext." << std::endl;
}


int main(int argc, char** argv)
{
	bool showHelp = false;
	uint32_t PID;
	const char* P;
	const char* Q;

	for (int i = 1; i < argc; ++i) {
		if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0)) {
			usage(argv[0]);
			return 1;
		}
		else
	    if (strcmp(argv[i], "--check") == 0) {
			doCheck = true;
			++i;
			if ((argc - i) >= 3) {
				PID = atol(argv[i]);
				P = argv[i+1];
				Q = argv[i+2];
				i += 3;
				break;
			}
			else {
				usage(argv[0]);
				return 1;
			}
		}
		else
		if (strcmp(argv[i], "--without-destroy-key") == 0) {
			doCryptDestroy = false;
			doCryptReleaseCtx = false;
		}
		else
		if (strcmp(argv[i], "--without-release-ctx") == 0) {
			doCryptReleaseCtx = false;
		}
		else {
			std::cerr << "Error: unknown argument '" << argv[i] << "'" << std::endl << std::endl;
			usage(argv[0]);
			return 1;
		}
	}

  if (!doCheck) {
    int ret;
    ret = generateKeyAndCheck(argv[0]);
    if (ret == 2) {
      std::cerr << "An error occured while searching for primes in memory!" << std::endl;
      return 2;
    }
	std::cout << std::endl << "Results:" << std::endl;
    if (ret == 0) {
      std::cout << "Wannakey technique has chances to work on this OS: Windows Cryptograhic API leaks secrets!" << std::endl;
      std::cout << "You can try wannakey now by launching the wannakey.exe binary." << std::endl;
    }
    else {
      std::cout << "The Windows Cryptograhic API does not seem to leak secrets on this Windows version :/" << std::endl;
      std::cout << "Wannakey has close to zero chance to recover the private key. Sorry :/" << std::endl;
    }
    std::cout << std::endl;
    std::cout << "Please report this result indicating the version of Windows (XP SP3, Seven, etc...) and the architecture (x86/x64) to @adriengnt or by making a PR on https://github.com/aguinet/wannakey!" << std::endl;
    return ret;
  }
  else {
    return searchPrimes(PID, P, Q);
  }

  usage(argv[0]);
  return 1;
}
