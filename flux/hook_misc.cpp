#include <stdio.h>
#include "hook.h"
#include "ntapi.h"
#include "log.h"
#include "whitelist.h"


HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
	__in    BOOLEAN Alertable,
	__in    PLARGE_INTEGER DelayInterval
	)
{
	unsigned long long milli = -DelayInterval->QuadPart / 10000;
	if (milli >= 1000)
	{
		LARGE_INTEGER newDelay;
		newDelay.QuadPart = -10000000;
		return Old_NtDelayExecution(Alertable, &newDelay);
	}

	return Old_NtDelayExecution(Alertable, DelayInterval);


}


