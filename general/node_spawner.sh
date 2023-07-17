#! /bin/bash

cmd=""
DELAY=2
peer_id=""
ports=(30000)
rpc_output=""
ports_ws=(40000)
ports_rpc=(50000)
localhost="127.0.0.1"
# ip_addr_list=("127.0.0.1")
raw_spec_file="./customSpecRaw.json"

init_steps() {
    read -p "Number of nodes (def 3): " num_of_nodes
    read -p "temp dir path (def ~/tmp): " tmp_dir
    read -p "Mode (def d: debug; r: release): " mode

    if [[ $num_of_nodes == "" ]]; then
        num_of_nodes=3
    elif [ $num_of_nodes -eq 0 ]; then
        echo "invalid num of nodes!"
        exit
    fi

    if [[ $tmp_dir = "" ]]; then
        tmp_dir="$HOME/tmp"
    fi

    if [[ $mode = "" ]]; then
        mode="d"
    fi

    if [ ! -f $raw_spec_file ]; then
        echo -e "\npls generate customSepcRaw.json spec file first!!\n"
        exit
    fi
    for (( i=0; i<$num_of_nodes-1; i=i+1)); do
        ports+=( $( bc -q <<< "${ports[$i]} + 1" ) )
        ports_ws+=( $( bc -q <<< "${ports_ws[$i]} + 1" ) )
        ports_rpc+=( $( bc -q <<< "${ports_rpc[$i]} + 1" ) )
    done
    echo -e "\n\nRPC Port List:\n"
    for p in ${ports_ws[@]}; do
        echo -e "$p"
    done
    echo -e "\n\n"
}

get_data() {
    cat <<MyEOF
    {
        "jsonrpc":"2.0",
        "method": "$1",
        "params": $2,
        "id":1
    }
MyEOF
}

call_rpc() {
    ctype="Content-Type: application/json"
    rpc_output=$(curl -H "$ctype" --data "$(get_data $1 $2)" $3:$4)
}

get_local_peer_id() {
    call_rpc "system_localPeerId" "[]" "$1" $2
    peer_id="$(echo $rpc_output | sed 's/.*\"\(12.*\)\",.*/\1/')"
}

prep_cmd() {
    local i=$1
    local port=$2
    local port_ws=$3
    local port_rpc=$4
    local ip_addr_peer=$5
    local port_peer=$6
    local id_peer=$7

    if [ mode != "d" ]; then
        mode="release"
    else
        mode="debug"
    fi
    local exec_path="./target/$mode/dfs"
    if [ ! -f $exec_path -o ! -x $exec_path ]; then
        echo -e "\n" $exec_path " file either doesn't exist or not an executable\n"
        exit
    fi

    if [[ $id_peer = "" || $port_peer = "" ]]; then
        other_node=""
    else
        other_node="--bootnodes /ip4/$ip_addr_peer/tcp/$port_peer/p2p/$id_peer"
    fi
    
    cmd="$exec_path \
    --base-path $tmp_dir/node$i \
    --chain $raw_spec_file \
    --port $port \
    --ws-port $port_ws \
    --rpc-port $port_rpc \
    --rpc-cors all \
    --no-telemetry \
    --validator \
    --rpc-methods Unsafe \
    --name node$i $other_node &"
}

spawn_nodes() {
    prep_cmd 0 ${ports[0]} ${ports_ws[0]} ${ports_rpc[0]} $localhost
    # here log node params
    bash -c "eval $cmd"
    echo -e "\npls wait for $DELAY sec..\n"
    sleep $DELAY
    get_local_peer_id $localhost ${ports_rpc[0]}
    echo -e "\nParsed PeerId: " $peer_id

    for (( i=1; i < $num_of_nodes; i = i+1 )); do
        prep_cmd $i ${ports[$i]} ${ports_ws[$i]} ${ports_rpc[$i]} $localhost ${ports[$( bc -q <<< "$i-1" )]} $peer_id
        # echo -e "\nrun cmd\n" $cmd
        # here log node params
        bash -c "eval $cmd"
        echo -e "\npls wait for $DELAY sec..\n"
        sleep $DELAY
        # get peer id of node, just started, for next iteration
        get_local_peer_id $localhost ${ports_rpc[$i]}
        echo -e "\nParsed PeerId " $peer_id
    done
}

gen_spec() {
    echo -e "\nGenerating spec file\n"
    cmd="./target/$mode/dfs build-spec --disable-default-bootnode --chain staging > customSpec.json"

}

proc_spec() {
    echo -e "\nProcessing the spec file\n"
    # 1.  balances [[]]
    #   [accid, balance with 18 dec]
    # 2. validatorCount -> ip
    # 3. minimumValidatorCount -> ip
    # 4. invulnerables []
    #   accids of those which we want to add as validator who wont be slashed
    # 5. stakers [[]] length = validatorCount
    #   [ controller, stash, stake_amount with 18 dec, "validator"/"nominator"]
    # 6. minNominatorBond -> ip
    # 7. minValidatorBond -> ip
    # 8. session {keys: [[]]} keys.length = validatorCount
    #   keys: [[ validator, validator, { grandpa: ed_key, babe: sr_key, im_online: sr_key, authority: sr_key}]]
    # 9. technicalComitte {members: []} members.length -> ip (anybody from balances array)
    # 10. elections: {members: []} memebers.length = same as above
    #   [member_addr, vote_weight]
    # 11. sudo {key: anyone from balances}
    # 12. society: {pot, member:[]} members.length = same




}

gen_raw() {
    echo -e "\nGenerating raw spec file\n"
    cmd="./target/$mode/dfs \
    build-spec \
    --chain=customSpec.json \
    --raw \
    --disable-default-bootnode > customSpecRaw.json"
}

post_spawn() {
    # block productions and finalisation
    # insert session keys
    # gran, babe, imol, audi
    # generate Ed25519 key for granpa
    cmd1="./target/$mode/subkey generate --scheme Ed25519"
    ed_key_op1=$(eval $cmd1)
    phrase=""
    cmd2="./target/$mode/subkey inspect --scheme Sr25519 $phrase"
    ed_key_op2=$(eval $cmd2)

}

menu() {
    while true; do
        clear
        echo -e "\n0 - generate spec\n1 - process spec\n2 - generate raw\n3 - spawn nodes\n4 - exit\n"
        read -p "Choice: " choice

        if [ $choice -eq 0 ]; then
            gen_spec; break
        elif [ $choice -eq 1 ]; then
            proc_spec; break
        elif [ $choice -eq 2 ]; then
            gen_raw; break
        elif [ $choice -eq 3 ]; then
            init_steps; spawn_nodes; break
        elif [ $choice -eq 4 ]; then
            echo -e "\nthank u for using this script!!\n";break
        else
            read -p "Invalid choice (press return key to continue): " _
        fi
    done
}

menu



