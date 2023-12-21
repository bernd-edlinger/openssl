./config enable-asan enable-ubsan enable-crypto-mdebug enable-crypto-mdebug-backtrace enable-rc5 enable-md2
nohup bash -c 'for ((X=1; X<10000; X++)) do UBSAN_OPTIONS=print_stacktrace=1 LSAN_OPTIONS=use_globals=0:use_stacks=0 OPENSSL_MALLOC_FAILURES=0@0.01 OPENSSL_MALLOC_SEED=$X make test V=1 > debug$X.log 2>&1; done' &
