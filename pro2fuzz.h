/*declare globals for pro2fuzz*/


u8 has_new_packet();
void dump_buf(u8*,u32,u8*);
u8 set_step(u8);
u8 add_to_Q(); 
void proceed_fuzzing(u8);
static u8  prev_c=0;                  /* c value, shared with TP          */
static u8  prev_step=0;               /* step value, shared with TP          */
static u8  ret_common_fuzz=0;         /* return value of common_fuzz_stuff, if 2 proceed fuzzing*/
static u8  Qid;
static u8* Qid_str;







struct Q
{

u8 Qid,
   shuffle_Q;

u64 Q_cycle; // maybe we don't need this, just increase Q cycle everytime it jumps out of original Q

u32 Qd_paths,						/* Total number of queued testcases */
	Qd_variable,                    /* Testcases with variable behavior */
	Qd_at_start,                    /* Total number of initial inputs   */
	Qd_discovered,                  /* Items discovered during this run */
	Qd_imported,                    /* Items imported via -S            */
	Qd_favored,                     /* Paths deemed favorable           */
	Qd_with_cov;                    /* Paths with new coverage bytes    */
	Q_pending_not_fuzzed,           /* Queued but not done yet          */
	Q_pending_favored,              /* Pending favored paths            */
	Q_cur_skipped_paths,            /* Abandoned inputs in cur cycle    */
	Q_cur_depth,                    /* Current path depth               */
	Q_max_depth,                    /* Max path depth                   */
	Q_useless_at_start,             /* Number of useless starting paths */
	Q_var_byte_count,               /* Bitmap bytes with var behavior   */
	Q_current_entry,                /* Current queue entry ID           */
	Q_havoc_div = 1;                /* Cycle count divisor for havoc    */

struct queue_entry *Qhead,
				   *Q_cur,
                   *Q_top,
                   *Q_prev100;
struct queue_entry *Q_top_rated[MAP_SIZE];
	

};


/*original queue*/
struct queue_entry {
  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */
};




struct Q* multiQ[8]; // init 6 Qs for now



/*
switch to Q with Qid, the idea is to use the struct member of Q with Qid to replace the current global queue variables\
This is basically the member of struct Q, note that some of them can be directly replaced, but some of them have a cumulative relationship with the gobal queue variables.
*/


void switch_to_Q(u8 id){

	Q* curQ = multiQ[id];
	shuffle_queue = curQ->shffle_Q;
	queued_paths = curQ->Qd_paths,              /* Total number of queued testcases */
    queued_variable = curQ->Qd_variable,           /* Testcases with variable behavior */
    queued_at_start = curQ->Qd_at_start,           /* Total number of initial inputs   */
    queued_discovered = curQ->Qd_discovered,         /* Items discovered during this run */
    queued_imported = curQ->Qd_imported,           /* Items imported via -S            */
    queued_favored = curQ->Qd_favored,            /* Paths deemed favorable           */
    queued_with_cov = curQ->Qd_with_cov,           /* Paths with new coverage bytes    */
    pending_not_fuzzed = curQ->Q_pending_not_fuzzed,        /* Queued but not done yet          */
    pending_favored = curQ->Q_pending_favored,           /* Pending favored paths            */
    cur_skipped_paths = curQ->cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
    cur_depth = curQ->Q_cur_depth,                 /* Current path depth               */
    max_depth = curQ->Q_max_depth,                 /* Max path depth                   */
    useless_at_start = curQ->Q_useless_at_start,          /* Number of useless starting paths */
    var_byte_count = curQ->Q_var_byte_count,            /* Bitmap bytes with var behavior   */
    current_entry = curQ->Q_current_entry,             /* Current queue entry ID           */
    havoc_div = curQ->Q_havoc_div;             /* Cycle count divisor for havoc    */
	queue = curQ->Qhead;
	q_cur = curQ->Q_cur;
	q_top = curQ->Q_top;
	q_prev100 = curQ->Q_prev100;
	q_top_rated = curQ->Q_top_rated;
}





/*maybe we need a reverse function of switch_to_Q, to put global variables of queue into Q*/


void store_queue(u8 id) {

	// store global vars from queue to Q
	// TODO
	Q* curQ = multiQ[id];
	curQ->shffle_Q = shuffle_queue;
	curQ->Qd_paths = queued_paths,              /* Total number of queued testcases */
    curQ->Qd_variable = queued_variable,           /* Testcases with variable behavior */
    curQ->Qd_at_start = queued_at_start,           /* Total number of initial inputs   */
    curQ->Qd_discovered = queued_discovered,         /* Items discovered during this run */
    curQ->Qd_imported = queued_imported,           /* Items imported via -S            */
    curQ->Qd_favored = queued_favored,            /* Paths deemed favorable           */
    curQ->Qd_with_cov = queued_with_cov,           /* Paths with new coverage bytes    */
    curQ->Q_pending_not_fuzzed = pending_not_fuzzed,        /* Queued but not done yet          */
    curQ->Q_pending_favored = pending_favored,           /* Pending favored paths            */
    curQ->cur_skipped_paths = cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
    curQ->Q_cur_depth = cur_depth,                 /* Current path depth               */
    curQ->Q_max_depth = max_depth,                 /* Max path depth                   */
    curQ->Q_useless_at_start = useless_at_start,          /* Number of useless starting paths */
    curQ->Q_var_byte_count = var_byte_count,            /* Bitmap bytes with var behavior   */
    curQ->Q_current_entry = current_entry,             /* Current queue entry ID           */
    curQ->Q_havoc_div = havoc_div;             /* Cycle count divisor for havoc    */
	curQ->Qhead = queue;
	curQ->Q_cur = q_cur;
	curQ->Q_top = q_top;
	curQ->Q_prev100 = q_prev100;
	curQ->Q_top_rated = q_top_rated;

}










/*extra funcs for pro2fuzz*/


/* say we spotted new packets, we want to read the packet that right after the current fuzzing packet and fuzz it in the next round, for now, the testing program will write it to a fixed position, fuzzer can simply read from that position, but make it an argv anyway for future dev*/
static void read_next_packet(u8* src_path,u8* dest_path,u8 Qid) {


/* say we want to put the new packet into Q2, but Q2 is currently empty, then we have to create Q2 in mem and create a folder queue,*/



  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  ACTF("Scanning '%s'...", src_path);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(src_path, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           " The Q2 file dir does not seem to be valid.\n");

    PFATAL("Unable to open '%s'", src_path);

  }

  if (shuffle_queue && nl_cnt > 1) {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);

  }

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;

    u8* fn = alloc_printf("%s/%s", src_path, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", src_path, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */
 
    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {

      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);

  }

  //PFATAL("read q finished\n");
  free(nl); /* not tracked */

  if (!queued_paths) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", src_path);

  }

  last_path_time = 0;
  queued_at_start = queued_paths;

}






/*has_new_packet will return 0 if there is no new packet, 1 if c increases, 2 if c decreases, and update prev_c if needed*/
u8 has_new_packet(){
// get c:
    u8 cur_c = trace_bits[MAP_SIZE];
// a simple checking
    if(cur_c<1 || cur_c>4) PFATAL("cur_c is out of range!\n");
    if(cur_c==prev_c) return 0;
	else{
        prev_c = cur_c;
        if (cur_c > prev_c) return 1;
        else return 2;
    } 

}

/*set the value of step, so that TP can read it and change fuzzing target*/
u8 set_step(u8 new_step){
	u8* shm_last = trace_bits;
	shm_last[MAP_SIZE] = new_step;
}


//u8 add_to_Q(u8* fname, u32 len, u8 passed_det, u8 qid){
u8 add_to_Q(){
	// prepare the Q with ID qid
	// add_to_queue(fname,len,passed_det);

}



/*  read from file p2 that cause this to happen, put p2 into Q2 and fuzz Q2 next, return 1 if proceed, 0 otherwise*/

/*reset fuzzing state, fuzz the Q specified by qid*/
void proceed_fuzzing(u8 qid_cur, u8 qid_next){

	store_queue(qid_cur);
	switch_to_queue(qid_next);


}









/*the following functions are for debug*/


void printQHead()
{

struct queue_entry* q = queue;

FILE* f;
u8 buf[4096];
f = fopen(q->fname,"rb");
int r = fread(buf,1,4096,f);
dump_buf(buf,r,"QHead");

}


void printQ()
{

struct queue_entry* q = queue;
struct queue_entry* n;

FILE* f;
u8 buf[4096];
char dumpname[1024];
while(q)
{
n = q->next;
f = fopen(q->fname,"rb");
int r = fread(buf,1,4096,f);
snprintf(dumpname,10,"%d",rand());
dump_buf(buf,r,dumpname);
q = n;
}
}

void dump_buf(u8* buf,u32 size,u8* dumptype)
{
  char* dump_path = alloc_printf("/home/yuroc/tmp/fuzz/%s",dumptype);
  FILE* pFile=fopen(dump_path,"wb");
  if(pFile){
    fwrite(buf,1,size,pFile);
      }
  else{
    PFATAL("error when open file for writing!\n");
  }
  fclose(pFile);

}


