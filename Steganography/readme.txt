Kód programu - Josef Zetek

# Popis programu
Kód obsahuje třídu `ImageFile`, která obsahuje základní metody pro zakódování zprávy do obrázku a její následné dekódování.
V konstruktoru se předpočítají hodnoty pro předaný obrázek včetně velikosti, rozměrů, kapacity, apod. Poté se mohou nad třídou zavolat metody encode/decode, které provedou
kontroly, (zašifrují, následně zakódují)/(dekódují, následně dešifrují) (do)/(z) obrázku data soubora, případně vrátí výjimku. V konstruktoru je zároveň funkce počítající hash, kterým se obsah zašifruje pomocí Vernanovy šifry.

# Vhodnost použítého řešení a generování zcela náhodného klíče

Řešení šifrování je výhodnější v tom, že se heslo dá snadněji zapamatovat a sekvence jedniček a nul je tak odvoditelná z hesla. Nevýhodou je, že klíč
je kratší než zpráva, a tak je možné, že se ve zprávě objeví nějaký vzor pomocí kterého by se dala sekvence odvodit - tuto nevýhodu má
ale i náhodně vygenerovaný klíč. Protože je použitá šifra SHA-512, nedává sekvence 1 a 0 smysl jako kdybychom šifrovali rovnou Vernanovou šifrou s klíčem
v plaintextu. Proto je potřeba prolomit celou šifru - nelze prolomit jen část a zbytek doplnit tak, aby vzniklo například nějaké slovo. V tomto smyslu bych řekl, že
náročnost prolomení je u použití SHA-512 algoritmu stejná jako u náhodně vygenerovaného klíče.