
dofile "bit.lua"

-- This is used to conver hex to binary

if((arg[1] == nil) or (arg[2] == nil))then

    print("Usage:")
    print("  conv [filename] [output filename]")
    os.exit(-1)
end

local file
local data
local checksum
local s,e
local tmp

file = io.open(arg[1], "rt")
if(file ~= nil)then
    data = file:read("*all")
    file:close()
end

-- Extract the check sum 
checksum = string.match(data, "Sum = (%d+)")
if(checksum ~= nil)then
    checksum = tonumber(checksum)
end

print("Checksum =", checksum)


data = string.match(data, "[%da-f\n\r]+")
data = string.gsub(data, "[\n\r]", "")

local sum = 0
local num
-- Divide into words
local i,k
local str
local bits
local b
local bin = {}


file = io.open(arg[2], "wb")
if(file == nil)then
    print("Cannot open output file:", arg[2]..".bin")
    os.exit(-1)
end

for str in string.gmatch(data, "[%da-f][%da-f][%da-f][%da-f][%da-f][%da-f][%da-f][%da-f]") do

    num = tonumber(str, 16)
    sum = math.mod(sum + num, 2^32)
    
    b0, b1, b2, b3 = string.match(str, "([%da-f][%da-f])([%da-f][%da-f])([%da-f][%da-f])([%da-f][%da-f])")
    
    file:write(string.char(tonumber(b0,16)),string.char(tonumber(b1,16)),string.char(tonumber(b2,16)),string.char(tonumber(b3,16)))    
end

if(sum ~= checksum)then
    print("Check sum fail! org=", checksum, "  Calculated=", sum)
else
    print("Check sum ok!\n");
end
    
    

file:close()
        
    
os.exit()
    
    
-- Extract the hex number string
s, e = string.find(data, "//%-%- END %-%-//")

data = string.sub(data, 18, s-3)

print(string.sub(data, 1 , 32))

file = io.open(arg[2], "wt")
if(file == nil)then
    print("Cannot open output file:", arg[2])
    os.exit(-1)
end

for i=1, #data, 8 do

io.write(string.format("%3d%% \r", math.floor(i/#data*100)))

str = string.sub(data, i, i+7)
    
print(str)
    num = tonumber(str,16)
    sum = math.mod(sum + num, 2^32)
    bits = bit.tobits(num)
          
    for k=32,1,-1 do
        b = bits[k]
        if(b == nil)then
            b = 0
        end
        file:write(b.." ")
    end
    --print()
end
io.write(string.format("%3d%% \n", 100))


if(file ~= nil)then
    file:close()
end

print("Checksum", sum)
if(sum == checksum)then
    print("Checksum OK!")
else
    print("Checksum ERROR!!!!!. From input is ", checksum)    
end
