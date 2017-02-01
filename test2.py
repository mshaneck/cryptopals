def unionInt(a):
   b=[]
   for begin,end in sorted(a):
    print a
    print b
    print begin
    print end
    if b and b[-1][1] >= begin - 1:
     b[-1][1] = max(b[-1][1], end)
    else:
     b.append([begin,end])
   ret=[]
   for x in b:
    ret.append((x[0],x[1]))
   return ret
