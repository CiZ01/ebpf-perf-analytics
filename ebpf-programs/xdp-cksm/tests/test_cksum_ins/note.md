# Tests Briefing

## Parameters

**ripetizioni per ogni run**: 1000
**pacchetti inviati a ogni rep**: 10000

## About the test

Sono stati eseguiti due tipologie differenti di test.
1. Perf vs rdpmc 
2. Solo perf

Questi due test sono utili anche a conoscere l'overhead di rdpmc.

La directory corrente è strutturata nel seguente modo:

`x` = numero di checksum eseguite all'intenro del programma XDP
`y` = numero di test eseguiti per una determinata configurazione (compreso con e senza trace, che saranno sempre in equal numero)

le cartelle `0x_cksum` indicano che il programma XDP esegue `x` checksum.
A parte il numero di checksum gli altri parametri rimangono invariati.

Su `y` test eseguiti, `y/2` sono stati eseguiti con trace abilitato e `y/2` con trace disabilitato, e saranno sempre identificati con `trace` e `no_trace` rispettivamente.o 