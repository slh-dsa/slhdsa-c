# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

.PHONY: count

CSRC	=	$(wildcard ../*.c)
OBJS	= 	$(CSRC:.c=.o)

XCOUNT	?=	xcount
XCOUNTC	=	xcount.c my_dbg.c

CC 		=	gcc
CFLAGS	:=	-Wall -Wextra -march=native -O3 
#CFLAGS	+=	-fsanitize=address,undefined
CFLAGS	+=	-I.. -DSLH_EXPERIMENTAL
LDLIBS	+=

$(XCOUNT):	$(OBJS) xcount.c my_dbg.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XCOUNTC) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

acvp_cases.sh: ACVP-Server/gen-val/json-files
	python3 test_slhdsa.py > acvp_cases.sh

ACVP-Server/gen-val/json-files:
	git submodule update --init ACVP-Server

clean:
	$(RM) -rf $(XCOUNT) $(OBJS) *.log
	$(RM) -f *.pyc *.cprof */*.pyc *.rsp *.log
	$(RM) -f acvp_cases.sh
	$(RM) -rf __pycache__ */__pycache__

