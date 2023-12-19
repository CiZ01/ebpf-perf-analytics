#! /bin/bash

# un software che cicla 10 volte, ogni volta va in sleep per 3 secondi e riparte, printa anche il suo pid

echo "il mio pid è $$"
for i in {1..10}
do
    echo "ciclo $i"
    sleep 3
done

exit 0  