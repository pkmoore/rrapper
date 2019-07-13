NAME=$1
TARGET=${NAME}/${NAME}.bin

CONFIG_PATH=${NAME}/${NAME}.ini
C_PATH=${NAME}/${NAME}.c

# build if C path exists
if [ -f "$C_PATH" ]; then
    echo "Building test ${NAME}..."
    gcc -m32 -static $C_PATH -o $TARGET
fi

echo "Replaying test ${NAME}..."


