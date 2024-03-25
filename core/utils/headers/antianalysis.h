#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H


#pragma once
#include "API/headers/api.h"


class AntiAnalysis
{
public:
	PROCESS_BASIC_INFORMATION GetPeb(API::APIResolver& resolver);
	bool IsBeingDebugged(API::APIResolver& resolver);
	int  Nuke(API::APIResolver& resolver);

};
#endif // !ANTIANALYSIS_H