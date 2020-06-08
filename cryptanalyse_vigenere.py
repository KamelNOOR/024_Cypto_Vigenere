# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : ROCHE 3677376
# Etudiant.e 2 : NOOR MOHAMED 3533073

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [0.092134, 0.010354, 0.030179, 0.037537, 0.171748, 0.010939, 0.010615, 0.010718, 0.075073, 0.003833, 0.000070, 0.061368, 0.026499, 0.070308, 0.049141, 0.023698, 0.010160, 0.066093, 0.078168, 0.073743, 0.063562, 0.016451, 0.000011, 0.004072, 0.002300, 0.001226]
print(freq_FR)

# Chiffrement César
def chiffre_cesar(txt, key):
	"""
	string*int -> string
	"""
	res = ""
	for c in txt:
		res += chr(65+((ord(c)-65+key)%26))
	return res

# Déchiffrement César
def dechiffre_cesar(txt, key):
	"""
	string*int -> string
	"""
	res = ""
	for c in txt:
		res += chr(65+((ord(c)-65-key)%26))
	return res

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
	"""
	string*list[int] -> string
	"""
	#conversion du message en list[int]
	l_msg = conversionAlphaNum(txt)
	#extension de la clef
	l_clef = extensionClefListe(key, len(l_msg))
	#chiffrement par addition modulo message + clef
	l_chiffre = additionDeuxListesModulo(l_msg, l_clef)
	#conversion de la liste chiffre en message chiffre
	msg_chiffre = conversionNumAlpha(l_chiffre)
	
	return msg_chiffre

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
	"""
	string*list[int] -> string
	"""
	#conversion du message en list[int]
	l_msg = conversionAlphaNum(txt)
	#extension de la clef
	l_clef = extensionClefListe(key, len(l_msg))
	#chiffrement par addition modulo message + clef
	l_chiffre = soustractionDeuxListesModulo(l_msg, l_clef)
	#conversion de la liste chiffre en message dechiffre
	msg_dechiffre = conversionNumAlpha(l_chiffre)
	
	return msg_dechiffre

# LIBRAIRIE VIGENERE 
def conversionAlphaNum(message):
	"""string -> list[int]"""#testok
	l = []
	for c in message:
		if (ord(c)>=65 and ord(c)<= 90):
			l.append(ord(c)-65)
	return l


def conversionNumAlpha(l):
	"""list[int] -> string"""#testok
	message = ""
	for i in range(0,len(l)):
		message = message + chr(65+l[i])
	return message

def extensionClefListe(clef, taille_msg):
	"""list[int]*int -> list[int]"""
	l = []
	taille_clef = len(clef)
	for i in range(taille_msg):
		l.append(clef[i%taille_clef])
	return l

def additionDeuxListesModulo(l1, l2):
	"""list[int]*list[int] -> list[int]"""#testok
	return [(a+b)%26 for a,b in zip(l1,l2)]

def soustractionDeuxListesModulo(l1, l2):
	"""list[int]*list[int] -> list[int]"""
	return [((a-b)%26) for (a,b) in zip(l1,l2)]

# FIN LIBRAIRIE VIGENERE 


# Analyse de fréquences
# return le nb de d'occurence de chaque lettre
def freq(txt):
	"""
	String -> list[int]
	"""
	#init
	hist=[0]*26
	#loop occ
	for c in txt:
		hist[((ord(c))-65)] += 1
	return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
	"""
	String -> int
	"""
	histOcc = freq(txt)
	occMax = -1
	indexMax = -1
	for index in range(len(histOcc)):
		if (histOcc[index] > occMax):
			occMax = histOcc[index]
			indexMax = index
	return indexMax

# indice de coïncidence
def indice_coincidence(hist):
	"""
	list[int]-> float
	"""
	res = 0.0
	n = 0.0
	for val in hist:
		n += val
	for val in hist:
		res += ((val*(val-1.0))/(n*(n-1.0)))
	return res

# Recherche la longueur de la clé
def longueur_clef(cipher):
	"""
	string --> int
	"""
	# Pour chaque longueur k
	for k in range(1,21):
		listHist = []
		# Pour chaque colonne i
		for i in range(0,k):
			textTronq = ""
			for j in range(i,len(cipher),k):
				textTronq += cipher[j]
			listHist.append(freq(textTronq))
		somme = 0.0
		for val in listHist:
			somme += indice_coincidence(val)
		moy = somme/k
		if moy > 0.06:
			return k
	return 0
	
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
	"""
	string * int --> tab[int]
	"""
	decalages=[0]*key_length
	for i in range(key_length):
		s = ""
		for j in range(i,len(cipher),key_length):
			s += cipher[j]
		imax = lettre_freq_max(s)
		decalages[i] = (imax - ord("E") + 65) % 26
	return decalages

# Cryptanalyse V1 avec décalages par frequence max
#	REPONSE QUESTION :
#	18 / 100 des textes ont été correctement décryptés
#	Cette methode de cryptanalyse n'est pas fiable à 100% car la distribution de lettre
#	dans chaque colonne ( taille de la clef ) n'est pas homogène 

def cryptanalyse_v1(cipher):
	"""
	string --> string
	"""
	key_length = longueur_clef(cipher)
	key = clef_par_decalages(cipher, key_length)
	return dechiffre_vigenere(cipher, key)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
	"""
	list[int]*list[int]*int -> float
	"""
	totalH1 = 0.0
	totalH2 = 0.0
	for i in range(len(h1)):
		totalH1 += h1[i]
		totalH2 += h2[i]
	total = totalH1*totalH2*1.0
	
	res = 0.0
	for i in range(len(h1)):
		res += (h1[i]*h2[(i+d)%len(h1)]) / total
	return res

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
	"""
	string * int --> tab[int]
	cipher est découpé en col[String*key_length]
	h[int*key_length] est l'histogramme de frequence de chaque colonne
	puis le max de ICM(h[0],h[i],d) avec d de 0 à 25 pour obtenir le décalage relatif à la colonne 0 de la clef[i].
	"""
	decalages=[0]*key_length
	col = [""]*key_length
	h = [0]*key_length
	for i in range(len(cipher)):
		col[i%key_length] += cipher[i]
	for i in range(key_length):
		h[i] = freq(col[i])
	for i in range(1,key_length):
		bestDecal = 0
		icm = 0
		icmMax = 0
		for d in range(len(h[0])):
			icm = indice_coincidence_mutuelle(h[0],h[i],d)
			if (icm > icmMax):
				bestDecal = d
				icmMax = icm
		decalages[i] = bestDecal	
	return decalages

# Cryptanalyse V2 avec décalages par ICM
#	REPONSE QUESTION :
#	43 / 100 des textes ont été correctement décryptés
#	Cette methode de cryptanalyse n'est pas fiable à 100%  car
#	le problème persiste pour les clés longues avec des textes courtes
def cryptanalyse_v2(cipher):
	"""
	string --> string
	1) déterminer le décalage relatifs entre les colonnes
	2) rechiffrer cipher en cipher_cesar
	3) déterminer le décalage par rapport à E puis déchiffrer par décalage
		On obtient 43%
	"""
	key_length = longueur_clef(cipher)
	key = tableau_decalages_ICM(cipher, key_length)
	cipher_cesar = dechiffre_vigenere(cipher, key)
	lettre_max = lettre_freq_max(cipher_cesar)
	decalage = (lettre_max - ord("E") + 65) % 26

	return dechiffre_cesar(cipher_cesar,decalage)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
	"""
	list[int] * list[int] --> double
	"""

	# Calcul du numérateur
	numerateur = 0;
	moyenne_L1 = sum(L1)*1.0/(len(L1))
	moyenne_L2 = sum(L2)*1.0/(len(L2))
	for i in range(len(L1)):
		numerateur += (L1[i]-moyenne_L1)*(L2[i]-moyenne_L2)

	# Calcul du dénominateur
	denominateur = 0
	deno_droite = 0
	deno_gauche = 0
	for j in range(len(L1)):
		deno_droite += (L2[j]-moyenne_L2)**2
		deno_gauche += (L1[j]-moyenne_L1)**2
	denominateur = (math.sqrt(deno_droite))*(math.sqrt(deno_gauche))
	denominateur = round(denominateur,5)
	
	return numerateur/denominateur

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
	"""
	string * int --> tuple(int, int)
	"""
	key=[0]*key_length
	score = 0.0
	
	# cipher séparé en colonne
	colonne = []
	for i in range(key_length):
		s = ""
		for j in range(i,len(cipher),key_length):
			s += cipher[j]
		colonne.append(s)

	for j in range(key_length):
		cor_max = -1
		for k in range(26):
			cor = correlation(freq_FR, freq(dechiffre_cesar(colonne[j],k)))
			if (cor>cor_max):
				cor_max = cor
				key[j] = k
		score += cor_max
	score = score/key_length
	return (score, key)

# Cryptanalyse V3 avec correlations
#	REPONSE QUESTION :
#	84 / 100 des textes ont été correctement décryptés
#	Chaque colonne est analysée "indépendamment" dans sa globalité
def cryptanalyse_v3(cipher):
	"""
	string --> string
	"""

	key_length = longueur_clef(cipher)
	score, key = clef_correlations(cipher, key_length)
	return dechiffre_vigenere(cipher, key)


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
	f=open(fichier,"r")
	txt=(f.readlines())[0].rstrip('\n')
	f.close()
	return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
	cipher = read(fichier)
	if version == 1:
		return cryptanalyse_v1(cipher)
	elif version == 2:
		return cryptanalyse_v2(cipher)
	elif version == 3:
		return cryptanalyse_v3(cipher)

def usage():
	print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
	sys.exit(1)

def main(argv):
	size = -1
	version = 0
	fichier = ''
	try:
		opts, args = getopt.getopt(argv,"hv:f:")
	except getopt.GetoptError:
		usage()
	for opt, arg in opts:
		if opt == '-h':
			usage()
		elif opt in ("-v"):
			version = int(arg)
		elif opt in ("-f"):
			fichier = arg
	if fichier=='':
		usage()
	if not(version==1 or version==2 or version==3):
		usage()

	print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
	print(cryptanalyse(fichier, version))
	
if __name__ == "__main__":
	main(sys.argv[1:])
