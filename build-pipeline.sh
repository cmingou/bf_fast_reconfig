#!/bin/bash

MAVERICKS_CPU_PORT=320
MONTARA_CPU_PORT=192
NEWPORT_CPU_PORT=2
MODEL_CPU_PORT=8
FLOOD_GROUP=65535


set -e

function usage() {
    echo "Please use -p for p4 source directory, -n for profile name, -o for output directory,-f for other flags, -h for help"
}

while getopts "p:n:f:o:m:h?r" argv; do
    case $argv in
        p)
            P4_SRC_DIR=$OPTARG
            ;;
        n)
            PROFILE=$OPTARG
            ;;
        f)
            OTHER_PP_FLAGS=$OPTARG
            ;;
        o)
            OUT_DIR=$OPTARG
            ;;
        r)
            REMOVE_BOOL=1
            ;;
        m)
            MODEL=$OPTARG
            ;;
        h)
            usage
            exit
            ;;
        ?)
            usage
            exit
            ;;
    esac
done
#rm -r /root/bf-sde-9.0.0/install/share/tofinopd/tna_router/ && ./tofino-compile.sh -p $PWD -n tna_router -o /root/bf-sde-9.0.0/install/share/tofinopd/ -m 16

function remove() {
    if [ -d "${SDE_INSTALL}/share/tofinopd/${PROFILE}" ]; then
        echo "Removing old directory"
    fi
}

if [ -z "$MODEL" ]; then
    echo "Error: MODEL is not set, please choose 16 for tofino_model, 32 or 64 for Wedge100BF-32X/65X, 2 for AS9516-32D"
    exit 1
fi

if [ -z "$P4_SRC_DIR" ]; then
    echo "Error: P4_SRC_DIR is not set"
    exit 1
fi

if [ ! -d "${P4_SRC_DIR}" ]; then
    echo "Error: unable to locate "$PROFILE" P4 sources at ${P4_SRC_DIR}"
    exit 1
fi

if [ -z "$SDE_INSTALL" ]; then
    echo "Error: Please set SDE and SDE_INSTALL"
    exit 1
fi

if [ -z "$OUT_DIR" ]; then
    echo "Warning: OUT_DIR is not set"
    echo "Will using default path ."
fi

function clear_dir() {
  if [ -d "$1/${PROFILE}" ]; then
  if [ $REMOVE_BOOL == 1 ]; then
      echo "Removing old directory"
  else
    echo "Warning: directory $1/${PROFILE} is exist"
    exit 1
  fi

fi
}

function do_p4c_tf {
    echo "*** Compiling profile in directory '${P4_SRC_DIR}' for '$1' platform... with Tofino... with CPU_PORT: '$2'"
    echo "*** Output in $3"
    pp_flags="-DCPU_PORT=$2 -DFLOOD_GROUP=$FLOOD_GROUP -DOUTPUT_PORT=$OUTPUT_PORT"
    mkdir -p $3/tofino/${PROFILE}
    (set -x; bf-p4c --target tofino --arch tna -g --std p4-16 \
        -o $3/tofino/${PROFILE} -I ${P4_SRC_DIR} \
        ${pp_flags} ${OTHER_PP_FLAGS} \
        --bf-rt-schema $3/tofino/${PROFILE}/bf-rt.json \
        --parser-timing-reports \
        --create-graphs \
        ${P4_SRC_DIR}/${PROFILE}.p4)
    echo $2 > $3/tofino/${PROFILE}/cpu_port.txt
    echo
}

function do_p4c_tf2 {
    echo "*** Compiling profile in directory '${P4_SRC_DIR}' for '$1' platform... with Tofino2... with CPU_PORT: '$2'"
    echo "*** Output in $3"
    pp_flags="-DCPU_PORT=$2 -DFLOOD_GROUP=$FLOOD_GROUP -DOUTPUT_PORT=$OUTPUT_PORT"
    mkdir -p $3/tofino2/${PROFILE}
    (set -x; bf-p4c --target tofino2 --arch t2na -g --std p4-16 \
        -o $3/tofino2/${PROFILE} -I ${P4_SRC_DIR} \
        ${pp_flags} ${OTHER_PP_FLAGS} \
        --bf-rt-schema $3/tofino2/${PROFILE}/bf-rt.json \
        --parser-timing-reports \
        --create-graphs \
        ${P4_SRC_DIR}/${PROFILE}.p4)
    echo $2 > $3/tofino2/${PROFILE}/cpu_port.txt
    echo
}

case $MODEL in
    "32")
        INPUT_PORT=132
        OUTPUT_PORT=140
        OUT_DIR=${PWD}/target/wedge100bf-32x
        clear_dir $OUT_DIR
        do_p4c_tf "montara" ${MONTARA_CPU_PORT} ${OUT_DIR}
        ;;
    "64")
        OUT_DIR=${PWD}/target/wedge100bf-65x
        clear_dir $OUT_DIR
        do_p4c_tf "mavericks" ${MAVERICKS_CPU_PORT} ${OUT_DIR}
        ;;
    "16")
        INPUT_PORT=8
        OUTPUT_PORT=9
        OUT_DIR=${PWD}/target/model
        clear_dir $OUT_DIR
        do_p4c_tf "tofino_model" ${MODEL_CPU_PORT} ${OUT_DIR}
        do_p4c_tf2 "tofino_model" ${MODEL_CPU_PORT} ${OUT_DIR}
        ;;
    "2")
        OUT_DIR=${PWD}/target/as9516-32d
        clear_dir $OUT_DIR
        do_p4c_tf2 "newport" ${NEWPORT_CPU_PORT} ${OUT_DIR}
        ;;
esac
