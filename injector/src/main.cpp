#include "Windows.h"
#include "API/headers/api.h"
#include "utils/headers/antianalysis.h"

import MyModule;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	AntiAnalysis debug;

	auto& resolver = API::APIResolver::GetInstance();
	auto resolved	  = resolver.GetAPIAccess();

	resolver.IATCamo();
	resolver.LoadModules();
	resolver.ResolveFunctions();

	debug.IsBeingDebugged(resolver);

	return 0;
} 