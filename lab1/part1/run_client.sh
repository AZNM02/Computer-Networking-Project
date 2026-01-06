set -euo pipefail

dname=$(dirname ${BASH_SOURCE[0]})

if [ "$#" -ne 2 ]; then
    echo "Usage: ./run_client.sh <server name> <port>"
    exit 1
fi

python3 "$dname/client.py" "$1" "$2"
