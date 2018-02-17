# Opis rozwiązania.

## Dump odpowiednich pakietów.

Czytanie wszystkich pakietów z pliku nie jest zbyt pomocne.
Pomocne zatem okazało się czytanie kodu w którym jest funkcja wysyłająca dane.

Zatem, filtr do Wiresharka:
ip.dst == 35.205.64.152 and udp

Wyeksportujmy dane do JSONa, aby można je było łatwo odczytać w Pythonie.

## Jak przeprowadzić atak?

Po przeczytaniu kodu można stwierdzić, że do odszyfrowania plików potrzebne jest znalezienie kluczów generowanych przez funkcję gen_next_key().
Generuje ona liczby rosnące o 1 (jedyna zmienna która się różni podczas tworzenia kolejnych kluczy, to count).
Zatem, skoro to RSA, mamy klucz publiczny oraz znamy funkcję (f(x) = x + 1) zależności pomiędzy dwoma m, to możemy użyć „Franklin-Reiter related-message attack”.
Przydatny będzie dokument „Low-Exponent RSA with Related Messages” (https://pdfs.semanticscholar.org/899a/4fdc048102471875e24f7fecb3fb8998d754.pdf). Dla n, e takich jak w naszym kluczu publicznym podany jest gotowy wzór na m. Doskonale.

## Atak.

Na początku wczytałem pakiety z dumpa z punktu 1.
Znamy funkcję zależności pomiędzy kluczami do RSA, więc do posiadania wszystkich kluczy potrzebujemy poznać tylko pierwszy. Aby to zrobić użyłem ataku „Franklin-Reiter related-message attack” dla pierwszych dwóch pakietów.

Teraz pozostało przekazać dany klucz do deskryptora.
Z załączonego przykładowego użycia:
python wannacry.py -d 89ae1c813fbfeac8334259dc913e2909d06be552d2abcf0826f7ae83ef67abfb hkMay1CSgiYgbLwrV2JrojIK9ZnbAXFT09cXNjNxOmc=
Możemy przypuszczać, że drugi parametr (i zarazem interesujący nas ciąg znaków) jest zakodowany przez base64. Próba zakodowania otrzymanego klucza przez base64 zwraca znacznie dłuższy ciąg...
Natomiast po uprzednim zahashowaniu klucza przez SHA256 długość ciągu znaków była zgodna.

Następnie uruchomiłem atak na wszystkich wygenerowanych kluczach i udało się odszyfrować pliki.

