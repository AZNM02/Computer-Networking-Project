dname=$(dirname ${BASH_SOURCE[0]})

if [ "$#" -ne 2 ]; then
    echo "Usage: ./run_server.sh <server name> <port>"
    exit 1
fi

python3 "$dname/server.py" "$1" "$2"