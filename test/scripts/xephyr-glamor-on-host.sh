# Start a Xephyr server using glamor.  This assumes that you have an
# existing X Server to host the Xephyr -glamor instance.
export PIGLIT_RESULTS_DIR=$XSERVER_BUILDDIR/test/piglit-results/host-xephyr-glamor

export SERVER_COMMAND="$XSERVER_BUILDDIR/hw/kdrive/ephyr/Xephyr \
        -glamor \
        -glamor-skip-present \
        -noreset \
        -schedMax 2000 \
        -screen 1280x1024"

exec $XSERVER_DIR/test/scripts/run-piglit.sh
