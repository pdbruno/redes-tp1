#!/usr/bin/env python3
from scapy.all import *
import math
import csv

S1 = {}

def prob(e, S):
    return S[e]/sum(S.values())

def info(e, S):
    return -math.log2(prob(e, S))

def entropia(S):
    return sum([info(e, S) * prob(e, S) for e in S])

def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("\n".join([ "%s : %.5f" % (d,k/N) for d,k in simbolos ]))
    
def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0
        S1[s_i] += 1


sniff(count = 20000, prn=callback)
mostrar_fuente(S1)



with open('output.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(('Direccion', 'Protocolo', 'Apariciones'))
    for (t, count) in S1.items():
        writer.writerow((t[0], t[1], count))


#Luego,
#extender el código para que calcule la información de cada símbolo y la entropía de la fuente. Finalmente,
#realizar una captura de tráfico utilizando el código extendido anteriormente. La captura deben ser lo más
#extensa posibles (por ejemplo de más de 10.000 tramas). Las capturas deben hacerse en tantas redes como
#miembros tenga el grupo