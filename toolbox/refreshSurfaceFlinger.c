/*
 * Send a signal to surfaceflinger, causing it to reconfigure
 * itself based on properties set elsewhere.
 *
 * This program is released under the Apache Software License 2.0.
 *
 * (C) 2012 Bernhard "Bero" Rosenkraenzer <Bernhard.Rosenkranzer@linaro.org>
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>

int refreshSurfaceFlinger_main(int argc, char **argv) {
	struct dirent *de;
	DIR *d=opendir("/proc");
	assert(d);
	while(de=readdir(d)) {
		pid_t p=atoi(de->d_name);
		if(!p) // Not /proc/<PID>
			continue;
		char fn[strlen(de->d_name)+11];
		char executable[NAME_MAX];
		struct stat st;
		fn[sizeof(fn)-1]=0;
		strcpy(fn, "/proc/");
		strcat(fn, de->d_name);
		strcat(fn, "/exe");
		ssize_t s=readlink(fn, executable, sizeof(executable));
		if(s<0) // Not what we're looking for [probably an in-kernel process]
			continue;
		executable[s]=0;
		if(!strcmp(executable, "/system/bin/surfaceflinger")) {
			kill(p, SIGUSR1);
			break;
		}
	}
	closedir(d);
	return 0;
}
