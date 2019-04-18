u8 has_new_packet();
void dump_buf(u8*,u32,u8*);
u8 set_step(u8);
u8 add_to_Q(); 
void proceed_fuzzing(u8);
static u8  prev_c=0;                  /* c value, shared with TP          */
static u8  prev_step=0;               /* step value, shared with TP          */
static u8  ret_common_fuzz=0;         /* return value of common_fuzz_stuff, if 2 proceed fuzzing*/


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
void proceed_fuzzing(u8 qid){




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

