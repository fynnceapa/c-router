# PCOM-Tema1

## Protocolul IPV4

Am inceput tema cu protocolul IPv4 fiind familiarizat cu el de la laborator, astfel ca am pornit de la implementarea realizata in cadrul laboratorului.
Prima data verific daca pachetul primit este pentru router sau daca este un mesaj de broadcast, in caz contrar pachetul este dumped si se trece la urmatorul.
Urmatorul pas este sa verific daca ce am primit este un pachet de tipul ICMP, caz in care trimit un echo reply si se trece la urmatorul pachet.
Verificarile urmatoare sunt pentru `checksum`, `ttl` si daca exista o `ruta valida`. Daca la ttl sau best_route nu se trece de verificari se trimite un pachet ICMP.
Daca se trece de aceste verificari se cauta in cache-ul tabelei ARP pentru a verifica daca exista o intrare valida pentru urmatorul hop. (daca nu exista se face `ARP request`).
Actualizez checksum (folosind **htons** pentru a fi in network order) si scad ttl-ul.
Pun in adresa sursa a header-ului de ethernet adresa mac a router-ului si in adresa destinatie mac-ul urmatorului hop (luat din tabela de ARP).
Se trimite pachetul mai departe.

## Longest prefix match

Spre deosebire de laborator, a fost nevoie de o implementare mai rapida pentru LPM. Am implementat folosind cautarea binara.
Astfel ca am sortat tabela de routare folosind **qsort** si functia de comprare `compare` (care sorteaza mai intai dupa mask apoi dupa prefix), apoi fac o cautare binara clasica.
In functia de cautare binara totusi nu iau prima varianta gasita, ci continui cautarea pentru a gasi cea mai specifica ruta. Cautatrea si sortarea se fac in host byte order.
Functia `get_best_route` este mai mult un wrapper pentru `binary_search`.

## Protocolul ARP

Daca pachetul primit nu este de tipul IPv4, atunci verific daca este `ARP` (**ETHERTYPE_ARP == 0x0806**).
Daca am primit pachet ARP atunci verific opcode-ul:

- `opcode 1 -> request`
- `opcode 2 -> reply` 

Daca am primit un request creez un reply. Practic schimb opcode-ul din 1 in 2 si mai schimb adresele intre ele (ip-urile si mac-urile) ca sa il trimit unde trebuie. (functia `arp_request`).

Daca am primit un reply trebuie sa raspund la el. In functia `arp_reply` prima data adaug un nou entry in tabela.
Functia `add_arp_entry` adauga o noua intrare in tabela, tinand cont de ordinea lor, pentru ca le voi cauta folosind cautare binara si acestea trebuie sa fie sortate (dupa ip).

In continuare in `arp_reply` parcurg coada pachet cu pachet. Daca nu mai gasesc un match in tabela de arp inseamna ca nu pot trimite pachetul mai departe asa ca ul pun inapoi in coada si ma opresc.

Functia `send_arp_request` este functia cu care creez un pachet arp de request. Adaug pachetul in coada pentru a astepta sa fie trimis mai departe si creez un request pentru a gasi adresa mac a urmatorului hop. Adresa mac pentru destinatie va fi **broadcast** pentru a putea comunica cu toate interfetele. In continuare setez corespunzator toate tipurile din header-ul de arp.
Adresa IP target va fi urmatorul hop, adresa sursa va fi adresa din **best_route**.

## Protocolul ICMP

Dupa cum se cere in enunt, am implementat doar ICMP-urile pentru time limit, pentru host unreachable si echo request.
In protocolul de IPv4 verific daca primesc un echo request (daca type-ul este 8), caz in care trimit un ICMP de reply.
Daca `ttl <= 1` trimit un ICMP de type-ul 11 si daca functia `get_best_route` returneaza **NULL** inseamna ca nu exista o ruta potrivita si trimit un ICMP cu type-ul 3.
De trimiterea de pachete ICMP se ocupa functia `send_icmp` care primeste buf-ul (pachetul), interfata, lungimea si type-ul. Prima data in functie voi copia la finalul header-ului de icmp 64 de biti de la din ip_hdr. Apoi in header-ul IP actualizez protocolul (`IPPROTO_ICMP`).
Acum doar completez campurile relevante din ICMP, actualizez checksum si trimit pachetul.




