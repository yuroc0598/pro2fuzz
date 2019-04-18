Command line used to find this crash:

/home/yuroc/workspace/protocol/tools/profuzz/afl-fuzz -i /home/yuroc/workspace/protocol/tools/profuzz/testcases/openssl/in/p1 -o /home/yuroc/workspace/protocol/tools/profuzz/testcases/openssl/profuzz_out_p1 -M fuzzer0 -m none -t 400 -f /home/yuroc/workspace/protocol/tools/profuzz/testcases/openssl/input /home/yuroc/workspace/protocol/tools/profuzz/testcases/openssl/openssl 1

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
