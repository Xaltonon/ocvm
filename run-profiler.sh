make prof=1 && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/code/gperftools-2.5/.libs CPUPROFILE_FREQUENCY=10000 CPUPROFILE=ocvm.prof ./ocvm-profiled tmp --frame=basic
