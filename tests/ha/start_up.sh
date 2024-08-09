set -e
SCALE=2
POOL="${RBD_POOL:-rbd}"
# Check if argument is provided
if [ $# -ge 1 ]; then
    # Check if argument is an integer larger or equal than 1
    if [ "$1" -eq "$1" ] 2>/dev/null && [ "$1" -ge 1 ]; then
        # Set variable to the provided argument
        SCALE="$1"
    else
        echo "Error: Argument must be an integer larger than 1." >&2
        exit 1
    fi
fi
echo ℹ️  Starting $SCALE nvmeof gateways
docker-compose up -d --remove-orphans --scale nvmeof=$SCALE nvmeof


