import re

f = open("aes_ccm.txt", "rt")
data = f.read()
f.close()


# Get examples 

#ex = re.findall("Example[\w\s\\n<>#\-:,\(\)=]+", data)
ex = re.split("={62}", data)

for e in ex:
    ex_data = e #re.split("Decrypt-Verify", e)
    
    #if(len(ex_en) == 2):
        #print(ex_en[0][0:12])
        
        #ex_data = ex_en[0]
        
    num = re.search("Example #\d+", ex_data)
    tlen = re.findall("Tlen = (\d+)", ex_data)
    k = re.findall("K is([\w\s\\n<>]+)N", ex_data)
    iv = re.findall("N is([\w\s\\n<>]+)A is", ex_data)
    a = re.findall("A is([\w\s\\n<>]+)P is", ex_data)
    p = re.findall("P is([\w\s\\n<>]+)B\\n", ex_data)
    c = re.findall("C is([\w\s\\n<>]+)Decrypt", ex_data)

    if((len(p) > 0) and (len(c) > 0) and (len(a) > 0) and (len(iv) > 0)):
        print("{")
        print("    \"" + k[0].replace(" ", "").replace("\n","").replace("<empty>","") +  "\",")
        print("    \"" + iv[0].replace(" ", "").replace("\n","").replace("<empty>","") + "\",")
        print("    \"" + a[0].replace(" ", "").replace("\n","").replace("<empty>","") +  "\",")
        print("    \"" + p[0].replace(" ", "").replace("\n","").replace("<empty>","") +  "\",")
        print("    \"" + c[0].replace(" ", "").replace("\n","").replace("<empty>","") +  "\",")
        print("    " + tlen[0] +",")
        #print("    \"" + tag[0].replace(" ", "").replace("\n","").replace("<empty>","")+ "\",")
        print("},")

        #if(num[0] == "Example #4"):
            #print(num[0])
            #print(k[0])
            #print(iv[0])
            #print(a[0])
            #print(p)
            #print(c)
            #print(tag[0])
            
            