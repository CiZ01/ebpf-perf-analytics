__get_pretty_prompt_name(){
    namespace_config=$1
    JSON_FILENAME=$2
    
    if  [[ ! -f "config.json" ]] && [[ ! -f $JSON_FILENAME ]];
    then
        pretty_prompt=0
        return
    fi

    pretty_prompt=$(echo $namespace_config | jq -r '.pretty_prompt // 0') 
}