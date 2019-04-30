/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;
__thread u32 __afl_prev_loc;
u8 init_count=0;
u8 step = 0;
u8 fs_init = 0;
u8 wait_for_regress = 0;
/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;


  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if(init_count == 1){
	  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;
  }

  u8 looped = 0;

  while (1) {

    u32 was_killed;
    int status;
	// when fs2 is forked and entered here, step is already read by fs1. error. what we need is to avoid the read in the first while loop

	/* condition for read this shit:
	 
	 1) fs1 first time entered, e.g., fs_init == 0
	 2) proceed: from second time loop, proceed will can this whole function, e.g., looped = 1
	 3) regress: from second time loop, regress will just ask parent to restart from the loop.
	 
	 
	 */
	if ((looped || !fs_init) && !wait_for_regress){
		if (read(FORKSRV_FD, &step,1)!=1) _exit(1); 
		__afl_area_ptr[MAP_SIZE] = step;
		fs_init = 1;
	}

	looped = 1;
	if (init_count == step){ // when regress, step is still 2

		wait_for_regress = 0;
	    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);
	    child_pid = fork();
	    if (child_pid < 0) _exit(1);
	    if (!child_pid) {return;}

	    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);
	    if (waitpid(child_pid, &status, 0) < 0)  _exit(1);
	   	if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);
		
	}
	else if(init_count < step){ // need to proceed, let kid read from pipe
		// the default fs will read from pipe then execute, which means it will be blocked at read, simply remove the read may cause trouble. but waitpid is blocking, so maybe it's fine.
		
		child_pid = fork();
	    if (child_pid < 0) _exit(1);
	    if (!child_pid) {return;}
		wait_for_regress = 1;
		step--;
		if (waitpid(child_pid, &status, 0) < 0) _exit(1);

	    // if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);
	    // if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);
 	  	//if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);
	
	}
	else{ // need to regress, just return , let parent read from pipe
//		if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) _exit(1);
//	    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);
// 	  	if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

		_exit(1);
	}

  }
}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

	if (!init_count)  __afl_map_shm();
  	  
	/*setup fds, close parent fd and create child fd*/
	init_count++;
	__afl_start_forkserver();
}
	
	
	
	



/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
